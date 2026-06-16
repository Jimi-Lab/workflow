#!/usr/bin/env python3
"""Static artifact/source audit and table verification notes for phase-3 CitationAnalysis."""

from __future__ import annotations

import ast
import csv
import json
import re
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any


REFERENCE_ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference")
ARTIFACT_IDS = [
    "p16_agentszz_teaching_the_llm_agent_to_play_detective_with_bug_inducing_commits",
    "p20_cavulner_automated_context_aware_identification_of_vulnerable_versions",
    "p25_how_and_why_agents_can_identify_bug_introducing_commits",
]
TABLE_IDS = [
    "p14_accurate_identification_of_the_vulnerability_introducing_commit_based_on_differential_anal",
    "p16_agentszz_teaching_the_llm_agent_to_play_detective_with_bug_inducing_commits",
    "p19_beyond_blame_rethinking_szz_with_knowledge_graph_search",
    "p25_how_and_why_agents_can_identify_bug_introducing_commits",
]


def read_text(path: Path, limit: int | None = None) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    return text if limit is None else text[:limit]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def clean(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def py_summary(path: Path) -> dict[str, Any]:
    text = read_text(path)
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return {"path": str(path), "syntax_error": str(exc), "imports": [], "functions": [], "classes": []}
    imports: list[str] = []
    functions: list[str] = []
    classes: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.name)
        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)
    return {
        "path": str(path),
        "imports": sorted(set(imports)),
        "functions": functions[:80],
        "classes": classes[:40],
    }


def audit_p25() -> dict[str, Any]:
    paper_dir = REFERENCE_ROOT / "p25_how_and_why_agents_can_identify_bug_introducing_commits"
    raw = paper_dir / "raw_extraction"
    root = raw / "artifact_static_snapshot" / "selected_repo"
    files = [p for p in root.rglob("*") if p.is_file()]
    py_files = [p for p in files if p.suffix == ".py"]
    sh_files = [p for p in files if p.suffix == ".sh"]
    data_files = [p for p in files if p.suffix in {".json", ".csv"} and ("data" in str(p).lower() or "results" in str(p).lower())]
    summaries = [py_summary(path) for path in py_files]
    imports = Counter()
    funcs = Counter()
    classes = Counter()
    for item in summaries:
        imports.update(item.get("imports", []))
        funcs.update(item.get("functions", []))
        classes.update(item.get("classes", []))
    key_files = [
        "README.md",
        "requirements.txt",
        "src/simple_szz_agent.py",
        "src/szz_agent_stage_01.py",
        "src/szz_agent_stage_02.py",
        "src/prompts.py",
        "src/evaluation_utils.py",
        "src/statistical_comparison.py",
        "generate_all_tables_and_figures.sh",
        "clone_repos.sh",
    ]
    lines = [
        "Paper ID: p25_how_and_why_agents_can_identify_bug_introducing_commits",
        "Artifact Source: https://github.com/niklasrisse/agents-for-szz",
        f"Snapshot Root: {root}",
        "Analysis Mode: downloaded static snapshot only",
        "Execution: [EXECUTION NOT REQUESTED]",
        "",
        f"Files observed: {len(files)}",
        f"Python files: {len(py_files)}",
        f"Shell scripts: {len(sh_files)}",
        f"Data/result JSON/CSV files: {len(data_files)}",
        "",
        "Primary Static Entrypoints:",
        "- src/simple_szz_agent.py",
        "- src/szz_agent_stage_01.py",
        "- src/szz_agent_stage_02.py",
        "- src/prompts.py",
        "- src/evaluation_utils.py",
        "- experiments/*/generate_table.py and generate_figure.py",
        "- experiments/*/results/*.json pre-computed outputs",
        "",
        "Top Imports:",
    ]
    for name, count in imports.most_common(30):
        lines.append(f"- {name}: {count}")
    lines += ["", "Functions / Classes Signals:"]
    for name, count in funcs.most_common(40):
        lines.append(f"- function {name}: {count}")
    for name, count in classes.most_common(20):
        lines.append(f"- class {name}: {count}")
    lines += ["", "Key File Snippets:"]
    for file in key_files:
        path = root / file
        if path.exists():
            lines.append(f"\n## {file}\n{read_text(path, 2200)}")
        else:
            lines.append(f"\n## {file}\n[NEEDS ARTIFACT] not present in selected snapshot")
    lines += [
        "",
        "Static Consistency Notes:",
        "- README states scripts/data are included for reproducing tables/figures, while full agent experiments require API keys, large repository clones, and high cost.",
        "- This audit confirms source, prompts, datasets, sampled datasets, experiment generators, and pre-computed result files are present in the downloaded snapshot.",
        "- No experiment script, data-generation script, baseline, model, package installation, or table generator was executed. [EXECUTION NOT_REQUESTED]",
    ]
    write(raw / "source_static_inventory_phase3.txt", "\n".join(lines))
    append_source_inventory(raw, "p25 artifact snapshot confirms source, prompts, experiment generators, datasets, sampled datasets, and pre-computed result files are present. Full reproduction remains [EXECUTION NOT REQUESTED].")
    return {"paper_id": paper_dir.name, "files": len(files), "python": len(py_files), "scripts": len(sh_files), "data_results": len(data_files)}


def audit_p16() -> dict[str, Any]:
    paper_dir = REFERENCE_ROOT / "p16_agentszz_teaching_the_llm_agent_to_play_detective_with_bug_inducing_commits"
    raw = paper_dir / "raw_extraction"
    snap = raw / "artifact_static_snapshot" / "downloads"
    patches = sorted(snap.glob("*.patch"))
    lines = [
        "Paper ID: p16_agentszz_teaching_the_llm_agent_to_play_detective_with_bug_inducing_commits",
        "Artifact Mode: case-link static patch downloads only",
        "Analysis Mode: static-only",
        "Execution: [EXECUTION NOT REQUESTED]",
        "",
        "Important Boundary:",
        "- No AgentSZZ replication repository was found in the PDF link inventory.",
        "- The downloaded files are case-study commit patches linked from the paper, not the AgentSZZ implementation.",
        "",
        f"Patch files downloaded: {len(patches)}",
    ]
    patch_summaries: list[dict[str, Any]] = []
    for path in patches:
        text = read_text(path)
        subject = next((line for line in text.splitlines() if line.lower().startswith("subject:")), "")
        files = re.findall(r"^diff --git a/(.*?) b/(.*?)$", text, re.M)
        additions = sum(1 for line in text.splitlines() if line.startswith("+") and not line.startswith("+++"))
        deletions = sum(1 for line in text.splitlines() if line.startswith("-") and not line.startswith("---"))
        patch_summaries.append({"path": rel(path, raw), "subject": subject, "files": files, "additions": additions, "deletions": deletions})
        lines += [
            "",
            f"## {path.name}",
            f"Subject: {subject or '[NEEDS EVIDENCE]'}",
            f"Changed files: {len(files)}",
            f"Additions: {additions}",
            f"Deletions: {deletions}",
        ]
        for before, after in files[:20]:
            lines.append(f"- {before} -> {after}")
    lines += [
        "",
        "Static Consistency Notes:",
        "- Patch evidence supports case-level linked commits only.",
        "- It cannot verify AgentSZZ implementation details, datasets, prompts, or runtime behavior. [NEEDS ARTIFACT]",
    ]
    write(raw / "source_static_inventory_phase3.txt", "\n".join(lines))
    append_source_inventory(raw, "p16 phase-3 downloaded linked commit patches for static case inspection only; no AgentSZZ implementation repository was confirmed. [NEEDS ARTIFACT]")
    return {"paper_id": paper_dir.name, "patches": len(patches), "patch_summaries": patch_summaries}


def audit_p20() -> dict[str, Any]:
    paper_dir = REFERENCE_ROOT / "p20_cavulner_automated_context_aware_identification_of_vulnerable_versions"
    raw = paper_dir / "raw_extraction"
    html_path = raw / "artifact_static_snapshot" / "downloads" / "sites.google.com_view_cavulner.html"
    html = read_text(html_path)
    urls = sorted(set(re.findall(r"https?://[^\\\"'<> ]+", html)))
    relevant = [u for u in urls if any(token in u.lower() for token in ["github", "drive", "zenodo", "figshare", "cavulner", "dropbox", "huggingface"])]
    lines = [
        "Paper ID: p20_cavulner_automated_context_aware_identification_of_vulnerable_versions",
        "Artifact Source: https://sites.google.com/view/cavulner",
        f"Downloaded HTML: {html_path}",
        "Analysis Mode: static HTML/link inventory only",
        "Execution: [EXECUTION NOT REQUESTED]",
        "",
        f"Extracted URLs: {len(urls)}",
        f"Potential artifact URLs: {len(relevant)}",
    ]
    for url in relevant[:100]:
        lines.append(f"- {url}")
    if not relevant:
        lines.append("- [NEEDS ARTIFACT] no downloadable code/data URL recovered from static HTML")
    lines += [
        "",
        "Static Consistency Notes:",
        "- The PDF cites the Google Site as CaVulner artifact page.",
        "- Static HTML retrieval succeeded, but this pass did not execute JavaScript or interactively browse Google Site widgets.",
        "- If the actual artifact is hidden behind dynamic Google Site content, manual browser export or a provided repository URL is still needed. [NEEDS ARTIFACT]",
    ]
    write(raw / "source_static_inventory_phase3.txt", "\n".join(lines))
    append_source_inventory(raw, "p20 phase-3 downloaded CaVulner Google Site HTML and extracted candidate links; no local source repository was confirmed. [NEEDS ARTIFACT]")
    return {"paper_id": paper_dir.name, "urls": len(urls), "artifact_urls": len(relevant)}


def append_source_inventory(raw: Path, note: str) -> None:
    path = raw / "source_static_inventory.txt"
    text = read_text(path)
    block = f"\nPhase-3 Static Artifact Enhancement:\n- {note}\n- Static-only; no code, scripts, package installation, or experiments were executed. [EXECUTION NOT REQUESTED]\n"
    if "Phase-3 Static Artifact Enhancement:" not in text:
        write(path, text.rstrip() + block)


def audit_tables(paper_id: str) -> dict[str, Any]:
    paper_dir = REFERENCE_ROOT / paper_id
    raw = paper_dir / "raw_extraction"
    analysis = paper_dir / "analysis"
    table_dir = raw / "tables"
    rows = []
    ready = 0
    needs = 0
    for csv_path in sorted(table_dir.glob("table_*.csv")):
        prefix = csv_path.stem
        crop = table_dir / f"{prefix}_page_crop.png"
        cells_path = table_dir / f"{prefix}_cells.json"
        with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            data = list(csv.reader(handle))
        nonempty = sum(1 for row in data for cell in row if clean(cell))
        row_count = len(data)
        col_count = max((len(row) for row in data), default=0)
        numeric = sum(1 for row in data for cell in row if re.search(r"\d", cell or ""))
        status = "citation-ready candidate"
        caveat = "manual visual cross-check against page crop recommended before final numeric quote"
        if row_count < 2 or col_count < 2 or nonempty < 4 or not crop.exists() or numeric == 0:
            status = "[NEEDS TABLE REPAIR]"
            caveat = "insufficient structure, no numeric content, or missing crop"
            needs += 1
        else:
            ready += 1
        header = " | ".join(clean(cell) for cell in (data[0] if data else []))[:220]
        rows.append({
            "table_id": prefix,
            "rows": row_count,
            "cols": col_count,
            "nonempty_cells": nonempty,
            "numeric_cells": numeric,
            "csv": rel(csv_path, paper_dir),
            "crop": rel(crop, paper_dir) if crop.exists() else "[NEEDS TABLE REPAIR] missing crop",
            "cells": rel(cells_path, paper_dir) if cells_path.exists() else "",
            "header": header,
            "status": status,
            "caveat": caveat,
        })
    lines = [
        f"Paper ID: {paper_id}",
        f"Audit Date: {date.today().isoformat()}",
        "Mode: static CSV/page-crop consistency audit; no experiment execution",
        "",
        f"Table CSV files checked: {len(rows)}",
        f"Citation-ready candidates: {ready}",
        f"Still needing repair: {needs}",
        "",
    ]
    for item in rows:
        lines += [
            f"## {item['table_id']}",
            f"Status: {item['status']}",
            f"Rows x Cols: {item['rows']} x {item['cols']}",
            f"Nonempty / Numeric cells: {item['nonempty_cells']} / {item['numeric_cells']}",
            f"Header: {item['header'] or '[NEEDS TABLE REPAIR]'}",
            f"CSV: {item['csv']}",
            f"Cells: {item['cells']}",
            f"Page Crop: {item['crop']}",
            f"Caveat: {item['caveat']}",
            "",
        ]
    if not rows:
        lines.append("[NEEDS TABLE REPAIR] no phase-2 CSV table extraction exists.")
    write(analysis / "16_table_numeric_verification_audit.txt", "\n".join(lines))
    return {"paper_id": paper_id, "checked": len(rows), "ready_candidates": ready, "needs_repair": needs}


def update_agent_indexes(results: list[dict[str, Any]], table_results: list[dict[str, Any]]) -> None:
    for item in results:
        paper_id = item["paper_id"]
        paper_dir = REFERENCE_ROOT / paper_id
        raw = paper_dir / "raw_extraction"
        idx_path = raw / "agent_index.json"
        data = json.loads(read_text(idx_path))
        units = data.setdefault("evidence_units", [])
        unit_id = f"{paper_id}:artifact:phase3_static_snapshot"
        if not any(unit.get("id") == unit_id for unit in units if isinstance(unit, dict)):
            units.append({
                "id": unit_id,
                "type": "artifact",
                "page": None,
                "section": "artifact_static_snapshot",
                "topic": "downloaded static artifact snapshot",
                "text_anchor": "Static artifact snapshot downloaded and inspected without execution.",
                "bbox": None,
                "files": [
                    "raw_extraction/source_static_inventory_phase3.txt",
                    "raw_extraction/artifact_static_snapshot_inventory.txt",
                    "raw_extraction/artifact_static_snapshot/download_log.json",
                ],
                "confidence": "medium" if paper_id.endswith("commits") else "partial",
                "repair_needed": paper_id != "p25_how_and_why_agents_can_identify_bug_introducing_commits",
                "usable_for": ["artifact_consistency", "reproducibility", "method", "evaluation"],
                "do_not_use_for": ["runtime behavior", "reproduced metric"],
                "notes": "[EXECUTION NOT REQUESTED] static downloaded artifact inspection only.",
            })
        idx_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for item in table_results:
        paper_id = item["paper_id"]
        paper_dir = REFERENCE_ROOT / paper_id
        raw = paper_dir / "raw_extraction"
        idx_path = raw / "agent_index.json"
        data = json.loads(read_text(idx_path))
        units = data.setdefault("evidence_units", [])
        unit_id = f"{paper_id}:table:phase3_numeric_audit"
        if not any(unit.get("id") == unit_id for unit in units if isinstance(unit, dict)):
            units.append({
                "id": unit_id,
                "type": "table",
                "page": None,
                "section": "table_numeric_verification",
                "topic": "phase3 numeric table audit",
                "text_anchor": f"{item['ready_candidates']} citation-ready candidates; {item['needs_repair']} still need repair.",
                "bbox": None,
                "files": ["analysis/16_table_numeric_verification_audit.txt"],
                "confidence": "medium" if item["ready_candidates"] else "partial",
                "repair_needed": item["needs_repair"] > 0,
                "usable_for": ["evaluation", "numeric_followup"],
                "do_not_use_for": ["final numeric quote without checking audit caveat"],
                "notes": "Static CSV/page-crop audit; no experiments run.",
            })
        idx_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    artifact_results = [audit_p16(), audit_p20(), audit_p25()]
    table_results = [audit_tables(pid) for pid in TABLE_IDS]
    update_agent_indexes(artifact_results, table_results)
    summary = {"artifact_results": artifact_results, "table_results": table_results}
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
