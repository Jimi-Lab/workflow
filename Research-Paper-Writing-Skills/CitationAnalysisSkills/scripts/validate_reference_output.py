#!/usr/bin/env python3
"""Validate CitationAnalysis reference-paper output completeness.

This script checks mechanical output requirements only. It does not judge paper
quality and does not run reference-paper code.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_REFERENCE_ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference")


def is_paper_dir(path: Path) -> bool:
    return path.is_dir() and re.match(r"^p\d+_", path.name) is not None


def iter_paper_dirs(reference_root: Path) -> list[Path]:
    if not reference_root.exists():
        return []
    return sorted([p for p in reference_root.iterdir() if is_paper_dir(p)], key=lambda p: p.name)


def validate_agent_index(path: Path) -> list[str]:
    issues: list[str] = []
    if not path.exists():
        return ["missing raw_extraction/agent_index.json"]
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report validation details
        return [f"invalid raw_extraction/agent_index.json: {exc}"]

    units = data.get("evidence_units")
    if not isinstance(units, list):
        issues.append("agent_index.json missing list field evidence_units")
        return issues
    if not units:
        issues.append("agent_index.json has zero evidence_units")

    seen: set[str] = set()
    for idx, unit in enumerate(units, start=1):
        if not isinstance(unit, dict):
            issues.append(f"agent_index evidence_units[{idx}] is not an object")
            continue
        unit_id = str(unit.get("id", "")).strip()
        if not unit_id:
            issues.append(f"agent_index evidence_units[{idx}] missing id")
        elif unit_id in seen:
            issues.append(f"agent_index duplicate evidence unit id: {unit_id}")
        else:
            seen.add(unit_id)
        if not unit.get("type"):
            issues.append(f"agent_index evidence unit {unit_id or idx} missing type")
        if unit.get("confidence") not in {"high", "medium", "partial", "low"}:
            issues.append(f"agent_index evidence unit {unit_id or idx} has invalid confidence")
        if "repair_needed" not in unit:
            issues.append(f"agent_index evidence unit {unit_id or idx} missing repair_needed")
        if "usable_for" not in unit:
            issues.append(f"agent_index evidence unit {unit_id or idx} missing usable_for")
        if "do_not_use_for" not in unit:
            issues.append(f"agent_index evidence unit {unit_id or idx} missing do_not_use_for")
    return issues


def validate_paper(paper_dir: Path) -> dict[str, Any]:
    raw_dir = paper_dir / "raw_extraction"
    analysis_dir = paper_dir / "analysis"
    missing: list[str] = []
    warnings: list[str] = []

    required_paths = [
        (raw_dir, "raw_extraction/"),
        (analysis_dir, "analysis/"),
        (raw_dir / "agent_index.json", "raw_extraction/agent_index.json"),
        (raw_dir / "extraction_profile.txt", "raw_extraction/extraction_profile.txt"),
        (analysis_dir / "13_completeness_audit.txt", "analysis/13_completeness_audit.txt"),
    ]
    for path, label in required_paths:
        if not path.exists():
            missing.append(f"missing {label}")

    if raw_dir.exists():
        if not (raw_dir / "full_text.txt").exists():
            warnings.append("raw_extraction/full_text.txt missing")
        page_dir = raw_dir / "page_text"
        if not page_dir.exists() or not any(page_dir.glob("*.txt")):
            warnings.append("raw_extraction/page_text/ missing or empty")

    if (raw_dir / "agent_index.json").exists():
        warnings.extend(validate_agent_index(raw_dir / "agent_index.json"))

    ok = not missing and not warnings
    return {
        "paper_id": paper_dir.name,
        "ok": ok,
        "missing": missing,
        "warnings": warnings,
    }


def render_text(results: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("# CitationAnalysis Reference Output Validation")
    lines.append("")
    if not results:
        lines.append("No paper directories found. Expected names like p01_short-title_year.")
        return "\n".join(lines)

    for result in results:
        status = "OK" if result["ok"] else "GAP"
        lines.append(f"## {result['paper_id']} [{status}]")
        if result["missing"]:
            lines.append("Missing:")
            for item in result["missing"]:
                lines.append(f"- {item}")
        if result["warnings"]:
            lines.append("Warnings:")
            for item in result["warnings"]:
                lines.append(f"- {item}")
        if result["ok"]:
            lines.append("- required outputs present")
        lines.append("")

    total = len(results)
    ok_count = sum(1 for r in results if r["ok"])
    lines.append(f"Summary: {ok_count}/{total} paper directories passed.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate CitationAnalysis reference outputs.")
    parser.add_argument("--reference-root", type=Path, default=DEFAULT_REFERENCE_ROOT)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()

    reference_root = args.reference_root
    results = [validate_paper(p) for p in iter_paper_dirs(reference_root)]

    if args.json:
        print(json.dumps({"reference_root": str(reference_root), "results": results}, indent=2, ensure_ascii=False))
    else:
        print(render_text(results))

    return 0 if results and all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
