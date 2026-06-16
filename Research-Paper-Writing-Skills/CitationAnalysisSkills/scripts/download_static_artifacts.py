#!/usr/bin/env python3
"""Download small static artifact snapshots for CitationAnalysis papers.

Network-only helper. It stores downloads inside each paper's raw_extraction
directory and never executes downloaded code.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import urllib.request
import zipfile
from datetime import date
from pathlib import Path
from typing import Any


TASKS: dict[str, list[dict[str, str]]] = {
    "p16_agentszz_teaching_the_llm_agent_to_play_detective_with_bug_inducing_commits": [
        {"kind": "patch", "url": "https://github.com/torvalds/linux/commit/feb18e900f0048001ff375dca639eaa327ab3.patch"},
        {"kind": "patch", "url": "https://github.com/apache/accumulo/commit/a2c2d38aa.patch"},
        {"kind": "patch", "url": "https://github.com/torvalds/linux/commit/7ecb37f62fe5.patch"},
        {"kind": "patch", "url": "https://github.com/sebastiaanschool/sebastiaanschool-Android/commit/2454879bfb.patch"},
    ],
    "p20_cavulner_automated_context_aware_identification_of_vulnerable_versions": [
        {"kind": "html", "url": "https://sites.google.com/view/cavulner"},
    ],
    "p25_how_and_why_agents_can_identify_bug_introducing_commits": [
        {"kind": "zip", "url": "https://github.com/niklasrisse/agents-for-szz/archive/refs/heads/main.zip"},
    ],
}


TEXT_EXTS = {
    ".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini",
    ".csv", ".tex", ".env", ".template", ".gitignore", ".gitattributes", ".license",
}


def safe_name(url: str) -> str:
    name = re.sub(r"^https?://", "", url)
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return name[:180] or "download"


def download(url: str, out_path: Path) -> tuple[bool, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "CitationAnalysisStaticDownloader/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("wb") as handle:
                shutil.copyfileobj(response, handle)
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def extract_zip(zip_path: Path, dest: Path) -> tuple[bool, str]:
    try:
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    return False, f"unsafe zip member: {member.filename}"
            zf.extractall(dest)
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def iter_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return [path for path in root.rglob("*") if path.is_file()]


def classify_file(path: Path) -> str:
    lower = path.name.lower()
    if lower.startswith("readme"):
        return "readme"
    if lower in {"requirements.txt", "pyproject.toml", "package.json", "environment.yml", "setup.py"}:
        return "dependency_config"
    if lower.endswith((".sh", ".ps1", ".bat")):
        return "script"
    if lower.endswith((".json", ".csv", ".parquet", ".pkl", ".pickle")):
        return "data_or_result"
    if lower.endswith((".py", ".java", ".js", ".ts", ".go", ".rs", ".cpp", ".c", ".h")):
        return "source"
    return "other"


def read_snippet(path: Path, limit: int = 4000) -> str:
    try:
        if path.suffix.lower() in TEXT_EXTS or path.name.lower().startswith("readme") or path.name.lower() in {"license", "makefile"}:
            return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""
    return ""


def static_inventory(snapshot_dir: Path, paper_id: str) -> dict[str, Any]:
    files = iter_files(snapshot_dir)
    by_kind: dict[str, list[str]] = {}
    snippets: list[dict[str, str]] = []
    for path in files:
        kind = classify_file(path)
        rel = path.relative_to(snapshot_dir).as_posix()
        by_kind.setdefault(kind, []).append(rel)
        if kind in {"readme", "dependency_config", "script", "source", "data_or_result"} and len(snippets) < 80:
            snippet = read_snippet(path)
            if snippet:
                snippets.append({"path": rel, "kind": kind, "snippet": snippet})
    return {
        "paper_id": paper_id,
        "snapshot_dir": str(snapshot_dir),
        "file_count": len(files),
        "by_kind": {key: sorted(value)[:300] for key, value in sorted(by_kind.items())},
        "snippets": snippets,
        "execution": "[EXECUTION NOT REQUESTED]",
    }


def render_inventory(data: dict[str, Any]) -> str:
    lines = [
        f"Paper ID: {data['paper_id']}",
        f"Snapshot Dir: {data['snapshot_dir']}",
        "Analysis Mode: downloaded static snapshot only",
        f"File Count: {data['file_count']}",
        "Execution: [EXECUTION NOT REQUESTED]",
        "",
        "File Layout By Kind:",
    ]
    for kind, paths in data["by_kind"].items():
        lines.append(f"- {kind}: {len(paths)} listed")
        for path in paths[:40]:
            lines.append(f"  - {path}")
    lines.append("")
    lines.append("Key Static Snippets:")
    for item in data["snippets"][:30]:
        snippet = item["snippet"].replace("\r\n", "\n")
        lines.append(f"\n## {item['path']} ({item['kind']})\n{snippet[:1800]}")
    return "\n".join(lines)


def process_paper(reference_root: Path, paper_id: str) -> dict[str, Any]:
    raw_dir = reference_root / paper_id / "raw_extraction"
    snapshot_dir = raw_dir / "artifact_static_snapshot"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    download_log: list[dict[str, Any]] = []
    for task in TASKS.get(paper_id, []):
        url = task["url"]
        kind = task["kind"]
        suffix = ".zip" if kind == "zip" else (".patch" if kind == "patch" else ".html")
        out_path = snapshot_dir / "downloads" / f"{safe_name(url)}{suffix}"
        ok, error = download(url, out_path)
        item: dict[str, Any] = {"kind": kind, "url": url, "path": str(out_path), "ok": ok, "error": error}
        if ok and kind == "zip":
            extract_dir = snapshot_dir / "extracted" / out_path.stem
            extracted, extract_error = extract_zip(out_path, extract_dir)
            item["extracted"] = extracted
            item["extract_error"] = extract_error
            item["extract_dir"] = str(extract_dir)
        download_log.append(item)
    (snapshot_dir / "download_log.json").write_text(json.dumps({
        "generated_at": date.today().isoformat(),
        "paper_id": paper_id,
        "downloads": download_log,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    inv = static_inventory(snapshot_dir, paper_id)
    (raw_dir / "artifact_static_snapshot_inventory.json").write_text(json.dumps(inv, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (raw_dir / "artifact_static_snapshot_inventory.txt").write_text(render_inventory(inv) + "\n", encoding="utf-8")
    return {
        "paper_id": paper_id,
        "downloads": download_log,
        "file_count": inv["file_count"],
        "kinds": {key: len(value) for key, value in inv["by_kind"].items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Download static artifact snapshots for selected CitationAnalysis papers.")
    parser.add_argument("--reference-root", type=Path, required=True)
    parser.add_argument("--paper-ids", required=True)
    args = parser.parse_args()
    results = [process_paper(args.reference_root, paper_id.strip()) for paper_id in args.paper_ids.split(",") if paper_id.strip()]
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
