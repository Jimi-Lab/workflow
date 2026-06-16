#!/usr/bin/env python3
"""Build an initial agent_index.json and extraction_profile.txt from existing raw extraction files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_REFERENCE_ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference")


def is_paper_dir(path: Path) -> bool:
    return path.is_dir() and re.match(r"^p\d+_", path.name) is not None


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def read_text(path: Path, limit: int | None = None) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    return text if limit is None else text[:limit]


def clean_anchor(text: str, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def load_metadata(raw_dir: Path) -> dict[str, Any]:
    path = raw_dir / "metadata.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def confidence_for_text(path: Path) -> str:
    text = read_text(path, limit=2000)
    if len(text.strip()) > 500:
        return "medium"
    if text.strip():
        return "partial"
    return "low"


def add_section_units(paper_id: str, paper_dir: Path, raw_dir: Path, units: list[dict[str, Any]]) -> None:
    section_dir = raw_dir / "section_text"
    if section_dir.exists():
        for path in sorted(section_dir.glob("*.txt")):
            section_name = path.stem
            anchor = clean_anchor(read_text(path, limit=1000))
            units.append({
                "id": f"{paper_id}:section:{section_name}",
                "type": "section",
                "page": None,
                "section": section_name,
                "topic": section_name.replace("_", " "),
                "text_anchor": anchor,
                "bbox": None,
                "files": [rel(path, paper_dir)],
                "confidence": confidence_for_text(path),
                "repair_needed": False,
                "usable_for": infer_usable_for_section(section_name),
                "do_not_use_for": ["exact numeric claim"],
                "notes": "Initial agent index generated from section_text.",
            })

    if not units and (raw_dir / "full_text.txt").exists():
        path = raw_dir / "full_text.txt"
        units.append({
            "id": f"{paper_id}:section:full_text",
            "type": "section",
            "page": None,
            "section": "full_text",
            "topic": "full paper text",
            "text_anchor": clean_anchor(read_text(path, limit=1000)),
            "bbox": None,
            "files": [rel(path, paper_dir)],
            "confidence": confidence_for_text(path),
            "repair_needed": True,
            "usable_for": ["retrieval"],
            "do_not_use_for": ["section-specific claim without manual verification", "exact numeric claim"],
            "notes": "Section files were unavailable; full_text used as fallback.",
        })


def infer_usable_for_section(section_name: str) -> list[str]:
    name = section_name.lower()
    mapping = [
        ("abstract", "abstract"),
        ("intro", "introduction"),
        ("background", "background"),
        ("motivation", "motivation"),
        ("problem", "problem_definition"),
        ("method", "method"),
        ("design", "method"),
        ("approach", "method"),
        ("system", "method"),
        ("experiment", "experiments"),
        ("evaluation", "evaluation"),
        ("result", "evaluation"),
        ("limitation", "limitations"),
        ("discussion", "limitations"),
        ("related", "related_work"),
        ("reference", "citation_verification"),
    ]
    usable = [target for marker, target in mapping if marker in name]
    return usable or ["retrieval"]


def group_files_by_prefix(files: list[Path]) -> dict[str, list[Path]]:
    groups: dict[str, list[Path]] = {}
    for path in files:
        stem = path.stem
        stem = re.sub(r"_(raw|cells|caption|context|agent_summary|page)$", "", stem)
        groups.setdefault(stem, []).append(path)
    return groups


def group_has_marker(group: list[Path], markers: list[str]) -> bool:
    joined = "\n".join(read_text(path, limit=3000).lower() for path in group if path.suffix.lower() in {".txt", ".md", ".csv", ".json"})
    return any(marker.lower() in joined for marker in markers)


def add_table_units(paper_id: str, paper_dir: Path, raw_dir: Path, units: list[dict[str, Any]], gaps: list[str]) -> None:
    table_dir = raw_dir / "tables"
    if not table_dir.exists() or not any(table_dir.iterdir()):
        gaps.append("[NEEDS TABLE REPAIR] no table extraction files found")
        return

    files = [p for p in table_dir.iterdir() if p.is_file() and p.name.lower() != "table_index.txt"]
    if not files:
        gaps.append("[NEEDS TABLE REPAIR] table directory exists but has no table files")
        return

    for prefix, group in sorted(group_files_by_prefix(files).items()):
        has_repair_marker = group_has_marker(group, ["needs table repair", "caption-neighbor", "\"repair_needed\": true", "\"cells\": []"])
        has_structured = any(p.suffix.lower() == ".csv" or p.name.endswith("_cells.json") for p in group) and not has_repair_marker
        has_markdown = any(p.suffix.lower() == ".md" for p in group)
        text_files = [p for p in group if p.suffix.lower() in {".txt", ".md", ".csv", ".json"}]
        anchor = clean_anchor(read_text(text_files[0], limit=1000)) if text_files else ""
        confidence = "medium" if has_structured else ("partial" if has_markdown or anchor else "low")
        repair_needed = not has_structured
        if repair_needed:
            gaps.append(f"[NEEDS TABLE REPAIR] {prefix} is not citation-ready")
        units.append({
            "id": f"{paper_id}:table:{prefix}",
            "type": "table",
            "page": None,
            "section": None,
            "topic": prefix.replace("_", " "),
            "text_anchor": anchor,
            "bbox": None,
            "files": [rel(p, paper_dir) for p in sorted(group)],
            "confidence": confidence,
            "repair_needed": repair_needed,
            "usable_for": ["evaluation", "experiments", "method", "retrieval"],
            "do_not_use_for": ["citation-ready numeric claim"] if repair_needed else [],
            "notes": "Initial table unit generated from existing table extraction files." + (" Extraction marks this table as not citation-ready." if repair_needed else ""),
        })


def add_figure_units(paper_id: str, paper_dir: Path, raw_dir: Path, units: list[dict[str, Any]], gaps: list[str]) -> None:
    figure_dir = raw_dir / "figures"
    if not figure_dir.exists() or not any(figure_dir.iterdir()):
        gaps.append("[NEEDS FIGURE EXTRACTION] no figure files found")
        return

    image_exts = {".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff"}
    files = [p for p in figure_dir.iterdir() if p.is_file() and p.name.lower() != "figure_index.txt"]
    if not files:
        gaps.append("[NEEDS FIGURE EXTRACTION] figure directory exists but has no figure files")
        return

    for prefix, group in sorted(group_files_by_prefix(files).items()):
        has_image = any(p.suffix.lower() in image_exts for p in group)
        has_repair_marker = group_has_marker(group, ["needs figure extraction", "page crop", "page-crop", "not precise figure crop", "not verified"])
        caption_files = [p for p in group if "caption" in p.name.lower()]
        context_files = [p for p in group if "context" in p.name.lower() or "page" in p.name.lower()]
        text_source = caption_files[0] if caption_files else (context_files[0] if context_files else None)
        anchor = clean_anchor(read_text(text_source, limit=1000)) if text_source else ""
        confidence = "medium" if has_image and anchor and not has_repair_marker else ("partial" if anchor or has_image else "low")
        repair_needed = (not has_image) or has_repair_marker
        if repair_needed:
            gaps.append(f"[NEEDS FIGURE EXTRACTION] {prefix} is not exact figure-ready")
        units.append({
            "id": f"{paper_id}:figure:{prefix}",
            "type": "figure",
            "page": None,
            "section": None,
            "topic": prefix.replace("_", " "),
            "text_anchor": anchor,
            "bbox": None,
            "files": [rel(p, paper_dir) for p in sorted(group)],
            "confidence": confidence,
            "repair_needed": repair_needed,
            "usable_for": ["method", "evaluation", "case_study", "retrieval"],
            "do_not_use_for": ["visual-detail claim"] if repair_needed else [],
            "notes": "Initial figure unit generated from existing figure extraction files." + (" Extraction marks this figure as not exact figure-ready." if repair_needed else ""),
        })


def add_special_units(kind: str, paper_id: str, paper_dir: Path, raw_dir: Path, units: list[dict[str, Any]]) -> None:
    special_dir = raw_dir / f"{kind}s"
    if not special_dir.exists():
        return
    for path in sorted(special_dir.glob("*.txt")):
        units.append({
            "id": f"{paper_id}:{kind}:{path.stem}",
            "type": kind,
            "page": None,
            "section": None,
            "topic": path.stem.replace("_", " "),
            "text_anchor": clean_anchor(read_text(path, limit=1000)),
            "bbox": None,
            "files": [rel(path, paper_dir)],
            "confidence": confidence_for_text(path),
            "repair_needed": confidence_for_text(path) != "medium",
            "usable_for": ["method", "retrieval"],
            "do_not_use_for": ["exact reproduction without manual verification"],
            "notes": f"Initial {kind} unit generated from existing extraction files.",
        })


def add_reference_unit(paper_id: str, paper_dir: Path, raw_dir: Path, units: list[dict[str, Any]]) -> None:
    path = raw_dir / "references.txt"
    if not path.exists():
        return
    units.append({
        "id": f"{paper_id}:reference:references",
        "type": "reference",
        "page": None,
        "section": "References",
        "topic": "bibliography",
        "text_anchor": clean_anchor(read_text(path, limit=1000)),
        "bbox": None,
        "files": [rel(path, paper_dir)],
        "confidence": confidence_for_text(path),
        "repair_needed": True,
        "usable_for": ["related_work", "citation_verification"],
        "do_not_use_for": ["verified BibTeX metadata"],
        "notes": "Reference text requires citation verification before BibTeX use.",
    })


def add_artifact_unit(paper_id: str, paper_dir: Path, raw_dir: Path, units: list[dict[str, Any]], gaps: list[str]) -> None:
    inventory = raw_dir / "source_static_inventory.txt"
    if not inventory.exists():
        return
    symbol_index = raw_dir / "source_static_symbols.json"
    files = [inventory]
    if symbol_index.exists():
        files.append(symbol_index)
    text = read_text(inventory)
    if "[EXECUTION NOT REQUESTED]" in text:
        gaps.append("[EXECUTION NOT REQUESTED] source/artifact inspected statically only")
    if "[NEEDS ARTIFACT]" in text:
        gaps.append("[NEEDS ARTIFACT] local source inventory reports missing data or reproduction materials")
    units.append({
        "id": f"{paper_id}:artifact:source_static_inventory",
        "type": "artifact",
        "page": None,
        "section": "source_static_inventory",
        "topic": "local source and artifact static inventory",
        "text_anchor": clean_anchor(text, limit=260),
        "bbox": None,
        "files": [rel(path, paper_dir) for path in files],
        "confidence": confidence_for_text(inventory),
        "repair_needed": "[NEEDS ARTIFACT]" in text or "[EXECUTION NOT REQUESTED]" in text,
        "usable_for": ["method", "experiments", "artifact_consistency", "reproducibility"],
        "do_not_use_for": ["runtime behavior", "reproduced metric", "artifact completeness claim"],
        "notes": "Static source inventory only; do not use for executed/reproduced results unless an execution pass is explicitly requested.",
    })


def infer_profile(raw_dir: Path, gaps: list[str]) -> str:
    full_text = raw_dir / "full_text.txt"
    page_dir = raw_dir / "page_text"
    page_count = len(list(page_dir.glob("*.txt"))) if page_dir.exists() else 0
    if full_text.exists() and page_count > 0:
        pdf_text = "complete"
    elif full_text.exists() or page_count > 0:
        pdf_text = "partial"
    else:
        pdf_text = "missing"

    layout_dir = raw_dir / "layout_blocks"
    layout = "partial" if layout_dir.exists() and any(layout_dir.glob("*.json")) else "missing/not attempted"

    table_dir = raw_dir / "tables"
    table_files = [p for p in table_dir.iterdir() if p.is_file()] if table_dir.exists() else []
    table_has_repair_marker = group_has_marker(table_files, ["needs table repair", "caption-neighbor", "\"repair_needed\": true", "\"cells\": []"])
    if any(p.suffix.lower() == ".csv" or p.name.endswith("_cells.json") for p in table_files) and not table_has_repair_marker:
        table = "cells+csv"
    elif any(p.suffix.lower() == ".md" for p in table_files):
        table = "markdown+raw"
    elif any(p.suffix.lower() == ".txt" for p in table_files):
        table = "caption-only"
    else:
        table = "missing"

    figure_dir = raw_dir / "figures"
    figure_files = [p for p in figure_dir.iterdir() if p.is_file()] if figure_dir.exists() else []
    image_exts = {".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff"}
    has_image = any(p.suffix.lower() in image_exts for p in figure_files)
    has_caption = any("caption" in p.name.lower() for p in figure_files)
    figure_has_repair_marker = group_has_marker(figure_files, ["needs figure extraction", "page crop", "page-crop", "not precise figure crop", "not verified"])
    if has_image and has_caption and not figure_has_repair_marker:
        figure = "crop+caption"
    elif has_image:
        figure = "page-crop+caption"
    elif has_caption:
        figure = "caption-only"
    else:
        figure = "missing"

    def special_layer(name: str) -> str:
        path = raw_dir / name
        return "extracted" if path.exists() and any(path.iterdir()) else "not detected/not attempted"

    citation_readiness = "low"
    if table in {"cells+csv"} and figure in {"crop+caption", "page-crop+caption"}:
        citation_readiness = "medium"

    agent_usability = "high" if pdf_text == "complete" else ("medium" if pdf_text == "partial" else "low")
    repair_steps = sorted(set(gaps)) or ["none recorded"]

    lines = [
        "Primary Consumer: agent",
        f"Generated At: {datetime.now().isoformat(timespec='seconds')}",
        f"PDF Text Layer: {pdf_text}",
        f"Layout Block Layer: {layout}",
        f"Table Layer: {table}",
        f"Figure Layer: {figure}",
        f"Formula Layer: {special_layer('formulas')}",
        f"Algorithm Layer: {special_layer('algorithms')}",
        f"Prompt Layer: {special_layer('prompts')}",
        "Known Ordering Losses: multi-column reading order may be wrong unless layout blocks exist",
        "Known Layout Losses: table, figure, formula, algorithm, and prompt layout may be partial",
        f"Agent Retrieval Usability: {agent_usability}",
        f"Citation Readiness: {citation_readiness}",
        "Next Repair Step: " + "; ".join(repair_steps),
        "",
    ]
    return "\n".join(lines)


def build_for_paper(paper_dir: Path, force: bool = False) -> tuple[bool, str]:
    raw_dir = paper_dir / "raw_extraction"
    if not raw_dir.exists():
        return False, f"skip {paper_dir.name}: raw_extraction missing"

    agent_index_path = raw_dir / "agent_index.json"
    profile_path = raw_dir / "extraction_profile.txt"
    if not force and agent_index_path.exists() and profile_path.exists():
        return False, f"skip {paper_dir.name}: agent package already exists"

    paper_id = paper_dir.name
    metadata = load_metadata(raw_dir)
    units: list[dict[str, Any]] = []
    gaps: list[str] = []

    add_section_units(paper_id, paper_dir, raw_dir, units)
    add_table_units(paper_id, paper_dir, raw_dir, units, gaps)
    add_figure_units(paper_id, paper_dir, raw_dir, units, gaps)
    add_special_units("formula", paper_id, paper_dir, raw_dir, units)
    add_special_units("algorithm", paper_id, paper_dir, raw_dir, units)
    add_special_units("prompt", paper_id, paper_dir, raw_dir, units)
    add_reference_unit(paper_id, paper_dir, raw_dir, units)
    if (raw_dir / "references.txt").exists():
        gaps.append("[NEEDS CITATION VERIFICATION] reference text is extracted but official metadata/BibTeX is not verified")
    add_artifact_unit(paper_id, paper_dir, raw_dir, units, gaps)

    layout_dir = raw_dir / "layout_blocks"
    if not (layout_dir.exists() and any(layout_dir.glob("*.json"))):
        gaps.append("[NEEDS LAYOUT BLOCK EXTRACTION] layout blocks missing")

    data = {
        "paper_id": paper_id,
        "title": metadata.get("title", ""),
        "source_manifest": "00_source_manifest.txt",
        "extraction_profile": "extraction_profile.txt",
        "generated_by": "build_agent_index.py",
        "evidence_units": units,
        "known_gaps": sorted(set(gaps)),
    }
    agent_index_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    profile_path.write_text(infer_profile(raw_dir, gaps), encoding="utf-8")
    return True, f"built {paper_id}: {len(units)} evidence units, {len(set(gaps))} known gaps"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build initial agent indexes from existing extraction files.")
    parser.add_argument("--reference-root", type=Path, default=DEFAULT_REFERENCE_ROOT)
    parser.add_argument("--paper-id", default=None, help="Build only one paper ID.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing agent_index.json and extraction_profile.txt.")
    args = parser.parse_args()

    if not args.reference_root.exists():
        print(f"Reference root does not exist: {args.reference_root}", file=sys.stderr)
        return 1

    if args.paper_id:
        paper_dirs = [args.reference_root / args.paper_id]
    else:
        paper_dirs = sorted([p for p in args.reference_root.iterdir() if is_paper_dir(p)], key=lambda p: p.name)

    if not paper_dirs:
        print("No paper directories found.")
        return 1

    changed = 0
    for paper_dir in paper_dirs:
        ok, message = build_for_paper(paper_dir, force=args.force)
        print(message)
        changed += 1 if ok else 0
    print(f"Changed: {changed}/{len(paper_dirs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
