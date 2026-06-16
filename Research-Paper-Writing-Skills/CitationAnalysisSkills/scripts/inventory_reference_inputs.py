#!/usr/bin/env python3
"""Inventory PDFs and likely source/artifact paths before batch CitationAnalysis ingestion."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover - optional dependency
    PdfReader = None  # type: ignore[assignment]


DEFAULT_REFERENCE_ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference")


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_") or "untitled"


def batch_slug(path: Path) -> str:
    return slugify(path.name)[:60]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_title(value: str) -> str:
    value = value.lower()
    value = re.sub(r"\.pdf$", "", value)
    value = re.sub(r"[_:：\-]+", " ", value)
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def title_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalize_title(value))


def infer_pdf_title(path: Path) -> str:
    if PdfReader is None:
        return ""
    try:
        with path.open("rb") as fh:
            reader = PdfReader(fh)
            metadata = reader.metadata
            if metadata and metadata.title:
                title = str(metadata.title).strip()
                if title and not title.lower().endswith(".pdf"):
                    return title
            if reader.pages:
                text = reader.pages[0].extract_text() or ""
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                for line in lines[:12]:
                    if 12 <= len(line) <= 180 and not re.match(r"^\d+$", line):
                        return line
    except Exception:
        return ""
    return ""


def looks_like_bad_title(title: str, filename_stem: str) -> bool:
    norm = normalize_title(title)
    filename_norm = normalize_title(filename_stem)
    if not norm:
        return True
    bad_prefixes = (
        "this paper is included",
        "proceedings of",
        "ieee transactions on",
        "acm reference format",
        "nullobject",
        "sc ",
    )
    if any(norm.startswith(prefix) for prefix in bad_prefixes):
        return True
    if len(norm.split()) < 3:
        return True
    return bool(filename_norm and len(norm) < max(24, len(filename_norm) * 0.45))


def choose_title_source(path: Path) -> str:
    inferred = infer_pdf_title(path)
    if inferred and not looks_like_bad_title(inferred, path.stem):
        return inferred
    return path.stem


def existing_reference_map(reference_root: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not reference_root.exists():
        return mapping
    for paper_dir in sorted(reference_root.iterdir()):
        if not paper_dir.is_dir() or not re.match(r"^p\d+_", paper_dir.name):
            continue
        metadata = paper_dir / "raw_extraction" / "metadata.json"
        if not metadata.exists():
            continue
        try:
            data = json.loads(metadata.read_text(encoding="utf-8"))
        except Exception:
            continue
        pdf_path = data.get("pdf_path")
        if pdf_path:
            mapping[str(Path(pdf_path))] = paper_dir.name
    return mapping


def next_id_start(reference_root: Path) -> int:
    max_id = 0
    if reference_root.exists():
        for path in reference_root.iterdir():
            match = re.match(r"^p(\d+)_", path.name)
            if match:
                max_id = max(max_id, int(match.group(1)))
    return max_id + 1


def find_source_for_pdf(pdf: Path, target: Path) -> str:
    stem_norm = normalize_title(pdf.stem)
    candidates = []
    for child in target.iterdir():
        if not child.is_dir():
            continue
        child_norm = normalize_title(child.name)
        if child_norm and (child_norm in stem_norm or stem_norm in child_norm):
            candidates.append(child)
    if len(candidates) == 1:
        return str(candidates[0])
    sibling = pdf.with_suffix("")
    if sibling.is_dir():
        return str(sibling)
    return ""


def infer_year(name: str) -> str:
    match = re.search(r"\b(19|20)\d{2}\b", name)
    return match.group(0) if match else ""


def make_paper_id(num: int, title_source: str, year: str) -> str:
    slug = slugify(title_source)
    if year and year not in slug:
        slug = f"{slug}_{year}"
    return f"p{num:02d}_{slug[:90].strip('_')}"


def inventory(target: Path, reference_root: Path) -> list[dict[str, Any]]:
    existing = existing_reference_map(reference_root)
    next_num = next_id_start(reference_root)
    pdfs = sorted(target.rglob("*.pdf"), key=lambda p: str(p).lower())

    by_hash: dict[str, list[Path]] = {}
    for pdf in pdfs:
        try:
            by_hash.setdefault(sha256_file(pdf), []).append(pdf)
        except OSError:
            by_hash.setdefault(f"unreadable:{pdf}", []).append(pdf)

    candidates: list[dict[str, Any]] = []
    seen_titles: dict[str, int] = {}
    for digest, paths in by_hash.items():
        canonical = paths[0]
        title_source = choose_title_source(canonical)
        norm_title = normalize_title(title_source)
        compact_title = title_key(title_source)
        duplicate_paths = [str(p) for p in paths[1:]]
        status = "pending"
        notes: list[str] = []

        if str(canonical) in existing:
            paper_id = existing[str(canonical)]
            status = "analyzed"
            notes.append("Existing reference directory points to this PDF.")
        elif norm_title in seen_titles or compact_title in seen_titles:
            duplicate_index = seen_titles.get(norm_title, seen_titles.get(compact_title))
            assert duplicate_index is not None
            paper_id = candidates[duplicate_index]["assigned_paper_id"]
            status = "skipped_duplicate"
            duplicate_paths = [str(canonical)] + duplicate_paths
            notes.append("Duplicate by normalized PDF title or filename.")
        else:
            year = infer_year(title_source)
            paper_id = make_paper_id(next_num, title_source, year)
            next_num += 1

        if norm_title not in seen_titles:
            seen_titles[norm_title] = len(candidates)
        if compact_title and compact_title not in seen_titles:
            seen_titles[compact_title] = len(candidates)

        source_path = find_source_for_pdf(canonical, target)
        nested = canonical.parent != target
        artifact_type = "Type A" if source_path else "Type D"
        if nested:
            notes.append("Nested PDF; verify whether it is an auxiliary artifact or a paper candidate.")

        candidates.append({
            "input_group": target.name,
            "canonical_pdf_path": str(canonical),
            "duplicate_pdf_paths": duplicate_paths,
            "detected_title": title_source,
            "filename_title": canonical.stem,
            "detected_year": infer_year(title_source),
            "detected_source_path": source_path,
            "artifact_type": artifact_type,
            "assigned_paper_id": paper_id,
            "status": status,
            "notes": notes,
            "sha256": digest,
        })
    return candidates


def write_outputs(reference_root: Path, slug: str, candidates: list[dict[str, Any]]) -> tuple[Path, Path]:
    json_path = reference_root / f"00_batch_inventory_{slug}.json"
    md_path = reference_root / f"00_batch_inventory_{slug}.md"
    reference_root.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps({
        "generated_at": date.today().isoformat(),
        "candidates": candidates,
    }, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")

    lines = [
        f"# Batch Inventory: {slug}",
        "",
        "| Status | assigned_paper_id | PDF | Duplicate Count | Source/Artifact | Notes |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for item in candidates:
        pdf_name = Path(item["canonical_pdf_path"]).name.replace("|", "\\|")
        source = item["detected_source_path"].replace("|", "\\|")
        notes = "; ".join(item["notes"]).replace("|", "\\|")
        lines.append(
            f"| {item['status']} | `{item['assigned_paper_id']}` | {pdf_name} | {len(item['duplicate_pdf_paths'])} | {source} | {notes} |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return json_path, md_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory reference-paper inputs before CitationAnalysis batch ingestion.")
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--reference-root", type=Path, default=DEFAULT_REFERENCE_ROOT)
    args = parser.parse_args()

    if not args.target.exists():
        print(f"Target does not exist: {args.target}", file=sys.stderr)
        return 2

    candidates = inventory(args.target, args.reference_root)
    json_path, md_path = write_outputs(args.reference_root, batch_slug(args.target), candidates)
    unique_pending = [c for c in candidates if c["status"] == "pending"]
    skipped = [c for c in candidates if c["status"] == "skipped_duplicate"]
    analyzed = [c for c in candidates if c["status"] == "analyzed"]
    print(f"PDF candidates: {len(candidates)}")
    print(f"Pending unique papers: {len(unique_pending)}")
    print(f"Already analyzed: {len(analyzed)}")
    print(f"Skipped duplicates: {len(skipped)}")
    print(f"Wrote: {json_path}")
    print(f"Wrote: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
