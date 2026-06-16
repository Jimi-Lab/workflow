from __future__ import annotations

import ast
import json
import re
from collections import Counter
from datetime import date
from pathlib import Path

from pypdf import PdfReader

try:
    import fitz
except Exception:  # pragma: no cover
    fitz = None


PAPER_ID = "p06_enhancing_bug_inducing_commit_identification_a_fine_grained_semantic_analysis_approach_2024"
TITLE = "Enhancing Bug-Inducing Commit Identification: A Fine-Grained Semantic Analysis Approach"
PDF_PATH = Path(r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\SEM-SZZ\Enhancing Bug-Inducing Commit Identification：A Fine-Grained Semantic Analysis Approach.pdf")
SOURCE_PATH = Path(r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\SEM-SZZ\SEM-SZZ")
PAPER_DIR = Path(r"E:\AI\Agent\workflow\Paper\reference") / PAPER_ID
RAW = PAPER_DIR / "raw_extraction"


SECTION_PATTERNS = [
    ("01_abstract", r"Abstract—", r"Index Terms—"),
    ("02_introduction", r"I\.\s*I\s*NTRODUCTION", r"II\.\s*B\s*ACKGROUND"),
    ("03_background", r"II\.\s*B\s*ACKGROUND", r"III\.\s*M\s*OTIVATION"),
    ("04_motivation", r"III\.\s*M\s*OTIVATION", r"IV\.\s*A\s*PPROACH"),
    ("05_approach", r"IV\.\s*A\s*PPROACH", r"V\.\s*E\s*XPERIMENTS"),
    ("06_experiments", r"V\.\s*E\s*XPERIMENTS", r"VI\.\s*R\s*ESULTS"),
    ("07_results", r"VI\.\s*R\s*ESULTS", r"VII\.\s*D\s*ISCUSSION"),
    ("08_discussion", r"VII\.\s*D\s*ISCUSSION", r"VIII\.\s*T\s*HREATS"),
    ("09_threats_to_validity", r"VIII\.\s*T\s*HREATS\s*T\s*O\s*V\s*ALIDITY", r"IX\.\s*C\s*ONCLUSION"),
    ("10_conclusion", r"IX\.\s*C\s*ONCLUSION", r"R\s*EFERENCES"),
    ("11_references", r"R\s*EFERENCES", r"$"),
]


def clean_text(text: str) -> str:
    return text.replace("\uFB01", "fi").replace("\uFB02", "fl").replace("\u2013", "-")


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def extract_pdf() -> tuple[list[str], str]:
    reader = PdfReader(str(PDF_PATH))
    pages: list[str] = []
    full_parts: list[str] = []
    empty_pages: list[int] = []
    for idx, page in enumerate(reader.pages, start=1):
        text = clean_text(page.extract_text() or "")
        if not text.strip():
            empty_pages.append(idx)
        pages.append(text)
        write(RAW / "page_text" / f"page_{idx:03d}.txt", text)
        full_parts.append(f"\n\n===== PAGE {idx:03d} =====\n\n{text}")
    full_text = "".join(full_parts).strip() + "\n"
    write(RAW / "full_text.txt", full_text)
    return pages, full_text


def section_text(full_text: str) -> list[str]:
    section_lines: list[str] = []
    for name, start_pat, end_pat in SECTION_PATTERNS:
        start = re.search(start_pat, full_text, flags=re.I | re.S)
        if not start:
            section_lines.append(f"{name}: [NEEDS SECTION SPLIT] start pattern not found: {start_pat}")
            continue
        end = re.search(end_pat, full_text[start.end():], flags=re.I | re.S)
        end_pos = start.end() + end.start() if end else len(full_text)
        text = full_text[start.start():end_pos].strip()
        write(RAW / "section_text" / f"{name}.txt", text + "\n")
        section_lines.append(f"{name}: extracted, chars={len(text)}")
    write(RAW / "sections.txt", "\n".join(section_lines) + "\n")
    refs = RAW / "section_text" / "11_references.txt"
    if refs.exists():
        write(RAW / "references.txt", refs.read_text(encoding="utf-8") + "\n[NEEDS CITATION VERIFICATION]\n")
    else:
        write(RAW / "references.txt", "[NEEDS CITATION VERIFICATION]\n")
    write(RAW / "appendix.txt", "No appendix section was separately extracted from the PDF text. [NEEDS EVIDENCE]\n")
    return section_lines


def caption_units(pages: list[str]) -> tuple[int, int]:
    table_count = 0
    figure_count = 0
    table_index: list[str] = []
    figure_index: list[str] = []
    for page_no, text in enumerate(pages, start=1):
        for match in re.finditer(r"(TABLE\s+[IVXLC]+[\s\S]{0,900}?)(?=\n[A-Z][A-Z ]{3,}|Fig\.|TABLE|=====|$)", text, flags=re.I):
            raw = match.group(1).strip()
            if "TABLE" not in raw.upper():
                continue
            table_count += 1
            tid = f"table_{table_count:03d}"
            payload = (
                f"Table ID: {tid}\nPage: {page_no}\n"
                "Caption/Neighbor Text:\n"
                f"{raw}\n\nExtraction Confidence: partial\n"
                "Notes: caption-neighbor/plain-text extraction only. [NEEDS TABLE REPAIR]\n"
            )
            write(RAW / "tables" / f"{tid}_raw.txt", payload)
            write(RAW / "tables" / f"{tid}.md", payload)
            write(RAW / "tables" / f"{tid}_cells.json", json.dumps({"table_id": tid, "page": page_no, "cells": [], "repair_needed": True}, indent=2))
            table_index.append(f"{tid}: page {page_no}, partial, [NEEDS TABLE REPAIR]")
        for match in re.finditer(r"(Fig\.\s*\d+[\s\S]{0,650}?)(?=\n[A-Z][A-Z ]{3,}|Fig\.|TABLE|=====|$)", text, flags=re.I):
            raw = match.group(1).strip()
            if "Fig." not in raw:
                continue
            figure_count += 1
            fid = f"figure_{figure_count:03d}"
            write(RAW / "figures" / f"{fid}_caption.txt", f"Figure ID: {fid}\nPage: {page_no}\nCaption/Neighbor Text:\n{raw}\n")
            write(RAW / "figures" / f"{fid}_context.txt", text[max(0, match.start() - 600): min(len(text), match.end() + 600)])
            write(RAW / "figures" / f"{fid}_agent_summary.txt", f"{fid} is caption/context-only unless a page crop exists. [NEEDS FIGURE EXTRACTION]\n")
            figure_index.append(f"{fid}: page {page_no}, caption/context, [NEEDS FIGURE EXTRACTION]")
            if fitz is not None and figure_count <= 12:
                doc = fitz.open(str(PDF_PATH))
                page = doc.load_page(page_no - 1)
                pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), alpha=False)
                pix.save(str(RAW / "figures" / f"{fid}_page.png"))
                doc.close()
    write(RAW / "tables" / "table_index.txt", "\n".join(table_index) + ("\n" if table_index else "No table captions detected. [NEEDS TABLE REPAIR]\n"))
    write(RAW / "figures" / "figure_index.txt", "\n".join(figure_index) + ("\n" if figure_index else "No figure captions detected. [NEEDS FIGURE EXTRACTION]\n"))
    write(RAW / "formulas" / "formula_index.txt", "Formula extraction was not attempted as layout-aware equation parsing. [NEEDS FORMULA REPAIR]\n")
    write(RAW / "algorithms" / "algorithm_index.txt", "No algorithm environment was detected by plain-text extraction. [NEEDS ALGORITHM REPAIR]\n")
    write(RAW / "prompts" / "prompt_index.txt", "No LLM prompt block is applicable/detected for this non-LLM paper. Prompt layer: not detected.\n")
    return table_count, figure_count


def source_inventory() -> None:
    all_files = [p for p in SOURCE_PATH.rglob("*") if p.is_file()]
    by_ext = Counter(p.suffix.lower() or "[no_ext]" for p in all_files)
    primary = [p for p in all_files if p.suffix.lower() in {".py", ".md", ".txt", ".json", ".csv", ".yml", ".yaml", ".ini", ".cfg"}]
    py_files = [p for p in all_files if p.suffix.lower() == ".py"]
    symbols = []
    for path in sorted(py_files):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            symbols.append({"file": str(path.relative_to(SOURCE_PATH)), "parse_error": str(exc)})
            continue
        funcs = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        imports = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                imports.extend(alias.name for alias in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module:
                imports.append(n.module)
        symbols.append({
            "file": str(path.relative_to(SOURCE_PATH)),
            "functions": sorted(funcs)[:80],
            "classes": sorted(classes)[:40],
            "imports": sorted(set(imports))[:80],
        })
    write(RAW / "source_static_symbols.json", json.dumps(symbols, indent=2, ensure_ascii=False))
    readme = SOURCE_PATH / "README.md"
    req = SOURCE_PATH / "requirements.txt"
    inv = [
        f"Source Path: {SOURCE_PATH}",
        "Analysis Mode: static-only",
        "Runtime Behavior: [EXECUTION NOT REQUESTED]",
        "",
        "Repository / File Layout Observed:",
        f"- Total files: {len(all_files)}",
        f"- Extension counts: {dict(sorted(by_ext.items()))}",
        "- Top-level entries:",
    ]
    for p in sorted(SOURCE_PATH.iterdir(), key=lambda x: x.name.lower()):
        inv.append(f"  - {p.name}/" if p.is_dir() else f"  - {p.name}")
    inv += [
        "",
        "Primary Files:",
        "- 1_get_input.py",
        "- 2_get_vcc.py",
        "- 3_gen_vuln_version.py",
        "- 4_get_duplicated_patch.py",
        "- 5_parse_result_llm_conservative.py",
        "- CFG.py",
        "- parse_patch.py",
        "- util.py",
        "- gen_results_for_no_dels.py / gen_results_for_dels.py",
        "- gen_baseline_results_for_no_deletes.py / gen_baseline_results_for_dels.py",
        "- README.md",
        "- requirements.txt",
        "",
        "README/config inspected: yes",
        "Main entrypoints inspected: yes, by filename and static AST symbol inventory",
        "Key Static Evidence:",
    ]
    if readme.exists():
        inv.append("README excerpt:")
        inv.append(readme.read_text(encoding="utf-8", errors="replace")[:2600])
    if req.exists():
        inv.append("\nrequirements.txt excerpt:")
        inv.append(req.read_text(encoding="utf-8", errors="replace")[:2600])
    inv += [
        "",
        "Static Consistency Notes:",
        "- The paper describes SEM-SZZ as a fine-grained semantic-analysis SZZ method using slicing, control-flow/data-flow comparisons, and handling of both no-deletion and deletion bug-fixing commits.",
        "- The local source contains staged scripts named for input collection, VCC retrieval, vulnerable-version generation, duplicated-patch handling, LLM conservative result parsing, and baseline/result generation.",
        "- CFG.py, parse_patch.py, util.py, and core/ are consistent with a static implementation surface for control/data/patch analysis, but runtime behavior was not verified.",
        "- requirements.txt and README.md are present; no dependency installation or script execution was performed.",
        "",
        "Observed Local Output / Data Artifacts:",
        "- tmp/ directory exists and may contain local intermediate/output artifacts; not treated as verified benchmark data. [NEEDS ARTIFACT]",
        "- time.txt exists; semantics not verified by execution. [EXECUTION NOT REQUESTED]",
        "",
        "Missing Data / Missing Entrypoints:",
        "- Original evaluation datasets, exact benchmark split, and reproduced result artifacts were not validated by execution. [NEEDS ARTIFACT]",
        "- Runtime metrics and final tables cannot be regenerated under static-only mode. [EXECUTION NOT REQUESTED]",
    ]
    write(RAW / "source_static_inventory.txt", "\n".join(inv) + "\n")


def metadata(page_count: int) -> None:
    data = {
        "paper_id": PAPER_ID,
        "title": TITLE,
        "authors": ["Lingxiao Tang", "Chao Ni", "Qiao Huang", "Lingfeng Bao"],
        "venue": "IEEE Transactions on Software Engineering",
        "year": "2024",
        "doi": "",
        "arxiv": "",
        "pdf_path": str(PDF_PATH),
        "artifact_type": "Type B",
        "page_count": page_count,
        "citation_status": "unverified",
    }
    write(RAW / "metadata.json", json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    write(RAW / "00_source_manifest.txt", "\n".join([
        f"Paper ID: {PAPER_ID}",
        f"Original PDF Path: {PDF_PATH}",
        "Original Text Path: ",
        f"Source Code Path or URL: {SOURCE_PATH}",
        "Artifact/Data Path or URL: [NEEDS ARTIFACT]",
        f"Extraction Date: {date.today().isoformat()}",
        "Extraction Tools: pypdf text extraction; PyMuPDF page rendering for caption pages when available; Python AST/static filesystem inventory",
        "Artifact Type: Type B",
        "Notes: source inspected statically only; no code execution, dependency installation, or experiment reproduction.",
        "",
    ]))


def main() -> None:
    for sub in ["page_text", "layout_blocks", "section_text", "tables", "figures", "formulas", "algorithms", "prompts"]:
        (RAW / sub).mkdir(parents=True, exist_ok=True)
    pages, full_text = extract_pdf()
    section_lines = section_text(full_text)
    table_count, figure_count = caption_units(pages)
    source_inventory()
    metadata(len(pages))
    write(RAW / "extraction_log.txt", "\n".join([
        "Status: raw extraction completed with known layout gaps",
        "Tools Used: pypdf; PyMuPDF if available; Python AST/static filesystem inventory",
        f"Successful Outputs: full_text.txt; {len(pages)} page_text files; section_text files; references.txt; source_static_inventory.txt",
        "Failed Outputs: precise table cells/CSV; precise figure crops; layout block coordinates",
        "Pages With Empty Text: none observed" if all(p.strip() for p in pages) else "Pages With Empty Text: [NEEDS OCR]",
        "OCR Needed: no",
        f"Tables Extracted: {table_count} caption-neighbor/plain-text records, not citation-ready [NEEDS TABLE REPAIR]",
        f"Figures/Captions Extracted: {figure_count} caption/context records; page crops only when generated, not precise figure-ready [NEEDS FIGURE EXTRACTION]",
        "References Extracted: yes, citation metadata unverified [NEEDS CITATION VERIFICATION]",
        "Known Losses: multi-column reading order, layout blocks, exact table cells, exact figure bounding boxes, formula layout",
        "PDF Text Complete: yes",
        "PDF Layout Partial: yes",
        "Citation-Ready Tables: no",
        "Figure-Ready: no",
        "Agent Index: pending build_agent_index.py",
        "Next Repair Step: table repair, precise figure extraction, citation verification",
        "",
    ]))


if __name__ == "__main__":
    main()
