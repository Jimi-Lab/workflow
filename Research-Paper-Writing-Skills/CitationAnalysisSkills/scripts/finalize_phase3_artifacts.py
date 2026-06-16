#!/usr/bin/env python3
"""Finalize phase-3 artifact/table notes after static downloads."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(r"E:\AI\Agent\workflow")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def update_agent_unit(paper: Path, files: list[str], anchor: str, confidence: str, repair_needed: bool) -> None:
    idx = paper / "raw_extraction" / "agent_index.json"
    data = json.loads(read(idx))
    units = data.setdefault("evidence_units", [])
    uid = f"{paper.name}:artifact:phase3_drive_or_eval_table_audit"
    if not any(isinstance(unit, dict) and unit.get("id") == uid for unit in units):
        units.append({
            "id": uid,
            "type": "artifact",
            "page": None,
            "section": "phase3_artifact_audit",
            "topic": "static artifact enhancement",
            "text_anchor": anchor,
            "bbox": None,
            "files": files,
            "confidence": confidence,
            "repair_needed": repair_needed,
            "usable_for": ["evaluation", "artifact_consistency", "reproducibility"],
            "do_not_use_for": ["runtime behavior", "reproduced metric"],
            "notes": "Static-only artifact inspection. [EXECUTION NOT REQUESTED]",
        })
    write(idx, json.dumps(data, ensure_ascii=False, indent=2))


def finalize_p20() -> int:
    paper = ROOT / "Paper/reference/p20_cavulner_automated_context_aware_identification_of_vulnerable_versions"
    raw = paper / "raw_extraction"
    gd = raw / "artifact_static_snapshot/downloads/google_drive"
    lines = [
        "Paper ID: p20_cavulner_automated_context_aware_identification_of_vulnerable_versions",
        "Google Drive Artifact Download Audit",
        "Analysis Mode: static-only",
        "Execution: [EXECUTION NOT REQUESTED]",
        "",
    ]
    files = sorted(gd.glob("*"))
    for path in files:
        prefix = path.read_bytes()[:16]
        kind = "7z archive" if prefix.startswith(b"7z") else ("html/download gate" if prefix.startswith(b"<!DOCTYPE html") else "unknown")
        lines.append(f"- {path.name}: size={path.stat().st_size}; type={kind}")
    lines += [
        "",
        "Result:",
        "- Two Drive links returned small HTML pages rather than direct artifacts; keep [NEEDS ARTIFACT].",
        "- Two Drive links returned 7z archives, downloaded successfully, but this environment has no 7z/py7zr extractor; archive contents were not read. [NEEDS ARTIFACT]",
        "- No code was executed and no dependency was installed. [EXECUTION NOT REQUESTED]",
    ]
    write(raw / "source_static_inventory_phase3_drive.txt", "\n".join(lines))
    ssi = raw / "source_static_inventory.txt"
    text = read(ssi)
    if "Phase-3 Google Drive Artifact Download Audit:" not in text:
        write(ssi, text.rstrip() + "\n\nPhase-3 Google Drive Artifact Download Audit:\n" + "\n".join(lines[5:]))
    update_agent_unit(
        paper,
        ["raw_extraction/source_static_inventory_phase3_drive.txt"],
        "Google Drive artifact candidates downloaded; 7z archives require extraction tooling.",
        "partial",
        True,
    )
    return len(files)


def finalize_p25() -> tuple[int, int]:
    paper = ROOT / "Paper/reference/p25_how_and_why_agents_can_identify_bug_introducing_commits"
    repo = paper / "raw_extraction/artifact_static_snapshot/selected_repo"
    tex_files = sorted((repo / "experiments").rglob("*.tex"))
    report = [
        "Paper ID: p25_how_and_why_agents_can_identify_bug_introducing_commits",
        "Artifact Evaluation Tables Audit",
        "Mode: static inspection of downloaded repo pre-generated tables/figures",
        "Execution: [EXECUTION NOT REQUESTED]",
        "",
        f"TeX table/figure files checked: {len(tex_files)}",
        "",
    ]
    ready = 0
    for path in tex_files:
        text = read(path)
        is_table = "\\begin{table" in text or "\\begin{table*" in text
        numeric_tokens = len(re.findall(r"(?<![A-Za-z])\d+\.\d+|\$?\d+(?:,\d{3})*k?|\d+%", text))
        caption = ""
        match = re.search(r"\\caption\{([^}]*)\}", text, re.S)
        if match:
            caption = re.sub(r"\\\w+\{([^}]*)\}", r"\1", match.group(1)).strip()
        status = "artifact-backed citation-ready candidate" if is_table and numeric_tokens > 0 else "figure/plot source or non-table; use for visual follow-up"
        if status.startswith("artifact-backed"):
            ready += 1
        rel = path.relative_to(repo).as_posix()
        report += [
            f"## {rel}",
            f"Status: {status}",
            f"Numeric tokens: {numeric_tokens}",
            f"Caption: {caption or '[NEEDS EVIDENCE]'}",
            "",
        ]
    report += [
        "Conclusion:",
        f"- Artifact-backed table candidates: {ready}",
        "- These are stronger than PDF OCR/crop extraction because they come from the authors' released pre-generated LaTeX tables/figures.",
        "- Still do not claim experiment reproduction; only claim static artifact availability and table values as author-provided artifact evidence. [EXECUTION NOT REQUESTED]",
    ]
    write(paper / "analysis/17_artifact_evaluation_tables_audit.txt", "\n".join(report))
    audit = paper / "analysis/16_table_numeric_verification_audit.txt"
    audit_text = read(audit)
    if "Artifact-backed table supplement:" not in audit_text:
        write(audit, audit_text.rstrip() + "\n\nArtifact-backed table supplement:\n- See analysis/17_artifact_evaluation_tables_audit.txt. Author-released TeX tables and result JSON files provide stronger static evidence than PDF table crops. [EXECUTION NOT REQUESTED]")
    update_agent_unit(
        paper,
        ["analysis/17_artifact_evaluation_tables_audit.txt", "analysis/16_table_numeric_verification_audit.txt"],
        "Author-released TeX tables and result JSON files inspected statically.",
        "medium",
        False,
    )
    return len(tex_files), ready


def main() -> None:
    p20_files = finalize_p20()
    p25_tex, p25_ready = finalize_p25()
    print(json.dumps({
        "p20_drive_files": p20_files,
        "p25_tex_files": p25_tex,
        "p25_ready_artifact_tables": p25_ready,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
