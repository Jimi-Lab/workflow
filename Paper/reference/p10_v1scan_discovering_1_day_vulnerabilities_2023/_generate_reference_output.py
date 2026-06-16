import json
import os
import re
from datetime import datetime
from pathlib import Path

import fitz


PAPER_ID = "p10_v1scan_discovering_1_day_vulnerabilities_2023"
REF_ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference")
PAPER_DIR = REF_ROOT / PAPER_ID
RAW = PAPER_DIR / "raw_extraction"
ANALYSIS = PAPER_DIR / "analysis"
TARGET = Path(r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\V1SCAN")
SOURCE = TARGET / "V1SCAN"
TITLE = "V1SCAN: Discovering 1-day Vulnerabilities in Reused C/C++ Open-source Software Components Using Code Classification Techniques"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def jwrite(path: Path, data) -> None:
    write(path, json.dumps(data, ensure_ascii=False, indent=2))


def find_pdf() -> Path:
    for entry in os.scandir(str(TARGET)):
        if entry.name.lower().endswith(".pdf"):
            return TARGET / entry.name
    raise FileNotFoundError("No PDF found")


def read_long_path(path: Path) -> bytes:
    long_path = "\\\\?\\" + str(path)
    with open(long_path, "rb") as f:
        return f.read()


def extract_pdf():
    for d in [
        RAW,
        ANALYSIS,
        RAW / "page_text",
        RAW / "layout_blocks",
        RAW / "section_text",
        RAW / "tables",
        RAW / "figures",
        RAW / "formulas",
        RAW / "algorithms",
        RAW / "prompts",
    ]:
        d.mkdir(parents=True, exist_ok=True)

    pdf = find_pdf()
    doc = fitz.open(stream=read_long_path(pdf), filetype="pdf")
    pages = []
    full_parts = []
    for i, page in enumerate(doc, start=1):
        text = page.get_text("text")
        pages.append(text)
        write(RAW / "page_text" / f"page_{i:03d}.txt", text)
        full_parts.append(f"===== PAGE {i:03d} =====\n{text}")
        blocks = []
        for j, b in enumerate(page.get_text("blocks"), start=1):
            if len(b) >= 5 and str(b[4]).strip():
                blocks.append(
                    {
                        "page": i,
                        "block_id": f"{PAPER_ID}:block:{i:03d}:{j:03d}",
                        "block_type": "text",
                        "text": str(b[4]).strip(),
                        "bbox": [round(float(x), 2) for x in b[:4]],
                        "reading_order": j,
                        "column_guess": None,
                        "confidence": "partial",
                    }
                )
        jwrite(RAW / "layout_blocks" / f"page_{i:03d}_blocks.json", blocks)
    write(RAW / "full_text.txt", "\n\n".join(full_parts))
    return pdf, doc.metadata or {}, pages


def page_range(pages, start, end):
    return "\n\n".join(
        f"===== PAGE {i:03d} =====\n{pages[i - 1]}"
        for i in range(start, min(end, len(pages)) + 1)
    )


def write_pdf_artifacts(pdf, metadata, pages):
    sections = {
        "01_abstract.txt": page_range(pages, 1, 1),
        "02_introduction.txt": page_range(pages, 1, 2),
        "03_background.txt": page_range(pages, 2, 3),
        "04_method.txt": page_range(pages, 4, 8),
        "05_experiments.txt": page_range(pages, 8, 9),
        "06_evaluation.txt": page_range(pages, 10, 12),
        "07_related_work.txt": page_range(pages, 2, 3),
        "08_limitations.txt": page_range(pages, 12, 13),
        "09_references.txt": page_range(pages, 13, 16),
    }
    for name, text in sections.items():
        write(RAW / "section_text" / name, text)
    write(
        RAW / "sections.txt",
        """Section Map (heuristic from PDF headings)
01_abstract.txt: page 1 abstract.
02_introduction.txt: pages 1-2, Introduction.
03_background.txt: pages 2-3, background on OSS reuse and version/code-based vulnerability detection.
04_method.txt: pages 4-8, V1SCAN design and code classification workflow.
05_experiments.txt: pages 8-9, dataset/target software/evaluation setup.
06_evaluation.txt: pages 10-12, accuracy and efficiency results.
07_related_work.txt: pages 2-3, related detection approaches embedded in background.
08_limitations.txt: pages 12-13, discussion/limitations/conclusion area.
09_references.txt: pages 13-16, references.
Boundary Confidence: medium for top-level sections; partial for subsection/table/figure boundaries.
""",
    )
    write(RAW / "references.txt", sections["09_references.txt"] + "\n\n[NEEDS CITATION VERIFICATION] Text-only references; no BibTeX verification.\n")
    write(RAW / "appendix.txt", "[NEEDS EVIDENCE] No separate appendix was identified in the extracted PDF text.\n")

    lines = []
    for pno, text in enumerate(pages, start=1):
        for line in text.splitlines():
            lines.append((pno, line.strip()))

    tables = []
    for idx, (pno, line) in enumerate(lines):
        if line.startswith("Table"):
            ctx = "\n".join(lines[q][1] for q in range(idx, min(idx + 14, len(lines))))
            tables.append((pno, ctx))
    table_index = []
    for n, (pno, ctx) in enumerate(tables, start=1):
        stem = f"table_{n:03d}"
        table_index.append(f"{stem}: page {pno}; caption-neighbor/raw text only; [NEEDS TABLE REPAIR]")
        write(RAW / "tables" / f"{stem}_raw.txt", f"Table ID: {stem}\nPage: {pno}\nRepair Needed: [NEEDS TABLE REPAIR]\n\n{ctx}\n")
        jwrite(RAW / "tables" / f"{stem}_cells.json", {"table_id": stem, "page": pno, "cells": [], "repair_needed": True})
    write(RAW / "tables" / "table_index.txt", "\n".join(table_index or ["[NEEDS TABLE REPAIR] No table captions detected."]) + "\n")

    figures = []
    for pno, text in enumerate(pages, start=1):
        for m in re.finditer(r"Figure\s*\d+:[^\n]*(?:\n[^\n]{0,200})?", text):
            figures.append((pno, m.group(0).strip()))
    figure_index = []
    for n, (pno, cap) in enumerate(figures, start=1):
        stem = f"figure_{n:03d}"
        figure_index.append(f"{stem}: page {pno}; caption/context only; [NEEDS FIGURE EXTRACTION]")
        write(RAW / "figures" / f"{stem}_caption.txt", f"Figure ID: {stem}\nPage: {pno}\nCaption/Text Anchor:\n{cap}\n")
        write(RAW / "figures" / f"{stem}_context.txt", f"Page: {pno}\nRepair Needed: [NEEDS FIGURE EXTRACTION]\n\n{pages[pno - 1][:1600]}\n")
        write(RAW / "figures" / f"{stem}_agent_summary.txt", f"{stem} is caption/context evidence only; do not use for visual-detail claims. [NEEDS FIGURE EXTRACTION]\n")
    write(RAW / "figures" / "figure_index.txt", "\n".join(figure_index or ["[NEEDS FIGURE EXTRACTION] No figure captions detected."]) + "\n")

    write(RAW / "formulas" / "formula_index.txt", "[NEEDS EVIDENCE] No citation-ready formula extraction was produced.\n")
    write(RAW / "algorithms" / "algorithm_index.txt", "[NEEDS EVIDENCE] No standalone pseudocode algorithm block was identified.\n")
    write(RAW / "prompts" / "prompt_index.txt", "[NEEDS EVIDENCE] No prompt block was identified.\n")

    jwrite(
        RAW / "metadata.json",
        {
            "paper_id": PAPER_ID,
            "title": TITLE,
            "authors": ["Seunghoon Woo", "Eunjin Choi", "Heejo Lee", "Hakjoo Oh"],
            "venue": "",
            "year": "2023",
            "doi": "",
            "arxiv": "",
            "pdf_path": str(pdf),
            "artifact_type": "Type B",
            "page_count": len(pages),
            "citation_status": "[NEEDS CITATION VERIFICATION]",
        },
    )
    write(
        RAW / "00_source_manifest.txt",
        f"""Paper ID: {PAPER_ID}
Original PDF Path: {pdf}
Original Text Path: {RAW / 'full_text.txt'}
Source Code Path or URL: {SOURCE}
Artifact/Data Path or URL: {SOURCE / 'dataset'}; {SOURCE / 'target'}
Extraction Date: {datetime.now().isoformat(timespec='seconds')}
Extraction Tools: PyMuPDF/fitz static PDF text extraction; PowerShell/Python filesystem inventory
Artifact Type: Type B with partial local artifact directories
Notes: Target source/artifact inspected statically only. [EXECUTION NOT REQUESTED]
""",
    )
    write(
        RAW / "extraction_log.txt",
        f"""Status: PDF text extracted; section split heuristic; layout/table/figure extraction partial.
Tools Used: PyMuPDF/fitz via long-path byte read; static filesystem/code reads.
Successful Outputs: full_text.txt; page_text for {len(pages)} pages; layout_blocks JSON; section_text; metadata.json; source manifest; caption-neighbor table/figure indexes; source_static_inventory.txt.
Failed Outputs: citation-ready tables; exact figure crops; verified bibliography; executable reproduction.
Pages With Empty Text: none observed.
OCR Needed: no.
Tables Extracted: {len(tables)} caption-neighbor/raw table units, all [NEEDS TABLE REPAIR].
Figures/Captions Extracted: {len(figures)} caption/context units, all [NEEDS FIGURE EXTRACTION].
References Extracted: yes, text-only, [NEEDS CITATION VERIFICATION].
Known Losses: multi-column ordering may be imperfect; table cells and figure visuals are not repaired/extracted.
Next Repair Step: table repair/manual PDF verification for Tables 1-8 and figure/page crop extraction.
PDF Text Complete: yes
PDF Layout Partial: yes
Citation-Ready Tables: no
Figure-Ready: no
Agent Index: generated after build_agent_index.py run
""",
    )
    return len(tables), len(figures), len(sections)


def write_source_inventory():
    key_files = [
        SOURCE / "Detector.py",
        SOURCE / "Detector_wrong.py",
        SOURCE / "32_v1scan_auto.py",
        SOURCE / "ctags",
        SOURCE / "optscript",
        SOURCE / "readtags",
    ] + sorted(SOURCE.glob("*_OSSList.txt"))

    symbols = []
    for fp in [SOURCE / "Detector.py", SOURCE / "Detector_wrong.py", SOURCE / "32_v1scan_auto.py"]:
        if fp.exists():
            for ln, line in enumerate(fp.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                if re.match(r"\s*(class|def)\s+", line):
                    symbols.append({"file": str(fp), "line": ln, "symbol": line.strip()})
    jwrite(RAW / "source_static_symbols.json", {"symbols": symbols})

    dataset_children = list((SOURCE / "dataset").iterdir()) if (SOURCE / "dataset").exists() else []
    target_children = list((SOURCE / "target").iterdir()) if (SOURCE / "target").exists() else []
    oss_lists = [p.name for p in sorted(SOURCE.glob("*_OSSList.txt"))]
    write(
        RAW / "source_static_inventory.txt",
        f"""Source Path: {SOURCE}
Analysis Mode: static-only [EXECUTION NOT REQUESTED]
Repository / File Layout Observed:
- Top-level code files: Detector.py, Detector_wrong.py, 32_v1scan_auto.py.
- Bundled native tools: ctags, optscript, readtags.
- OSS list files visible: {', '.join(oss_lists) if oss_lists else '[NEEDS ARTIFACT] none'}.
- dataset/ exists but contains {len(dataset_children)} immediate entries in this local snapshot. [NEEDS ARTIFACT]
- target/ exists but contains {len(target_children)} immediate entries in this local snapshot. [NEEDS ARTIFACT]
- README file was not observed in the local source root. [NEEDS ARTIFACT]
Primary Files:
{chr(10).join('- ' + str(p) for p in key_files if p.exists())}
Key Static Evidence:
- Detector.py defines configuration paths for Git2CPE, CPE2CVE, OSS function hashes, vulnerable/patch hashes, vulnerable files, and target outputs.
- Detector.py imports tlsh, ast, json, re, subprocess, os, and sys, suggesting hash-based and external-tool-assisted static analysis.
- targetHashing parses C/C++ files and uses ctags to collect functions, macros, structs, and variables for hashing/indexing.
- representingOSS maps target OSS to CPE/CVE information and candidate vulnerability records.
- ver_detectVuls, codeVerification, and code_detectVuls implement version-based filtering, code-based verification, and combined detection logic by static code inspection.
- 32_v1scan_auto.py iterates over an input folder and invokes Detector.py, but it was not executed.
Static Consistency Notes:
- Paper claim that V1SCAN combines version- and code-based detection is supported by Detector.py function names and configuration paths.
- Paper claim that reused code is classified into code entities is partially supported by targetHashing and ctags-based function/macro/struct/variable extraction.
- Local dataset/CPE/vulnerability hash directories required by Detector.py are absent or empty in this snapshot. [NEEDS ARTIFACT]
- No README/config documentation was visible locally; run commands and environment assumptions are inferred only from code. [NEEDS ARTIFACT]
Observed Local Output / Data Artifacts:
- OSSList files for curl, FFmpeg, httpd, ImageMagick, linux, openjpeg, openssl, qemu, tcpdump, and wireshark.
- Empty or placeholder dataset/ and target/ directories were observed.
Missing Data / Missing Entrypoints:
- Git2CPE, CPE2CVE, OSSallFuncs, OSSverList, vulHashes, vulFiles datasets referenced by Detector.py are missing locally. [NEEDS ARTIFACT]
- Runtime behavior and reported metrics were not reproduced. [EXECUTION NOT REQUESTED]
""",
    )
    return len(symbols)


def write_analysis(table_count, figure_count, section_count):
    anchor = "Agent Evidence Anchors: raw_extraction/full_text.txt; raw_extraction/section_text; raw_extraction/source_static_inventory.txt; raw_extraction/tables; raw_extraction/figures."
    files = {
        "00_meta.txt": f"""Paper ID: {PAPER_ID}
Title: {TITLE}
Venue / Year: [NEEDS CITATION VERIFICATION] / 2023
Authors: Seunghoon Woo; Eunjin Choi; Heejo Lee; Hakjoo Oh
Artifact Type: Type B with partial local artifact directories
Input Files: {find_pdf()}
Source / Artifact Path: {SOURCE}
Analysis Status: complete for static citation-analysis pass; runtime reproduction not requested.
Agent Index Status: generated by build_agent_index.py after extraction files.
Main Topic: discovering propagated 1-day vulnerabilities in reused C/C++ OSS components using version- and code-based classification.
Citation Metadata Status: [NEEDS CITATION VERIFICATION].
Missing Evidence: [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]; [NEEDS ARTIFACT]; [EXECUTION NOT REQUESTED].
""",
        "01_abstract.txt": f"""Problem: reused C/C++ OSS components can propagate known 1-day vulnerabilities into downstream software.
Gap: prior version-based and code-based detectors produce false positives or false negatives when reused OSS is modified.
Core Idea: V1SCAN improves and combines version-based and code-based approaches by classifying reused code and vulnerable code.
Method: classify reused code entities, narrow vulnerabilities contained in target software, then verify propagated vulnerabilities with code-level evidence.
Evaluation Setup: GitHub popular C/C++ software and comparisons against state-of-the-art detectors, according to extracted abstract.
Main Results: abstract reports improved vulnerability discovery and lower FP/FN rates; exact numeric reuse requires table repair/manual verification. [NEEDS TABLE REPAIR]
Reusable Writing Pattern: start from supply-chain risk, separate existing approaches into families, expose their failure modes, then argue for a combined evidence pipeline.
Relevance to Our Paper: directly relevant as a vulnerability-version/code-reuse baseline for distinguishing version metadata from code evidence.
Do Not Borrow: exact percentages or table metrics before table repair.
{anchor}
""",
        "02_introduction.txt": f"""Opening Context: OSS reuse is widespread and beneficial but creates vulnerability propagation risk.
Why the Problem Matters: downstream software may inherit known vulnerabilities from reused C/C++ components.
Prior Work Framing: version-based approaches identify vulnerable component versions; code-based approaches compare vulnerable code.
Why Prior Work Is Insufficient: version-only detection can over-report unused vulnerable code; code-only detection can miss modified or relocated vulnerable code.
Key Insight: classifying reused code and vulnerable code can combine the strengths of version and code evidence.
Contribution List: V1SCAN approach, code classification, improved vulnerability detection, empirical comparison, scalability study.
Risks for Our Paper: do not equate component version detection with affected versions unless code-level evidence and version boundaries are explicit.
{anchor}
""",
        "03_background_motivation.txt": f"""Domain Concepts Introduced: 1-day vulnerabilities, OSS reuse, C/C++ components, version-based detection, code-based detection, code classification.
Task Definition: discover known vulnerabilities propagated into target software through reused OSS components.
Motivating Case: ReactOS example appears in Table 1, but exact cells need repair. [NEEDS TABLE REPAIR]
Definitions Needed by Readers: reused code, vulnerable code, patched code, function/macro/structure/variable classification, CPE/CVE mapping.
Writing Pattern: explain two competing baseline families, then motivate a hybrid method by showing each family's blind spot.
Relevance to Our Paper: strong related-work material for affected versions plus code-evidence verification.
{anchor}
""",
        "04_problem_definition.txt": """Input: target C/C++ software, OSS component list, CPE/CVE mapping, vulnerable and patched code/hash databases.
Output: CVEs detected as present in the target software.
Objects / Entities: target program, OSS component, CPE, CVE, vulnerable function/structure, patch hash, TLSH hash, code-classification entity.
Objective: reduce false positives and false negatives in propagated vulnerability detection.
Boundary Conditions: local dataset directories required by code are absent or empty. [NEEDS ARTIFACT]
What Is Not Solved: this paper does not directly solve affected versions across release tags; it detects propagated vulnerabilities in reused code.
""",
        "05_method.txt": f"""System Overview: V1SCAN combines improved version-based detection with code-based verification through code classification.
Pipeline Stages: hash target code; represent OSS/CPE/CVE candidates; perform version-based candidate filtering; perform code-based verification; report unique CVEs.
Core Algorithm: Detector.py statically shows ctags-based extraction of functions/macros/structs/variables, normalization, TLSH hashing, CPE/CVE lookup, and vulnerability/patch hash matching.
Data Structures: dictionaries for vulnerable hashes, patch hashes, reverse CVE mapping, target hashes, manual OSS-CPE mapping, and OSS list files.
Design Choices: use entity-level code classification to distinguish reused code categories; combine version and code checks to reduce single-family detector errors.
Static Reproducibility Signals: Detector.py, Detector_wrong.py, 32_v1scan_auto.py, ctags/readtags/optscript, OSSList files. Required dataset directories are missing. [NEEDS ARTIFACT]
Execution Status: [EXECUTION NOT REQUESTED]
{anchor}
""",
        "06_experiments.txt": f"""Research Questions / Evaluation Focus: detection accuracy, comparison to MOVERY/V0Finder and improved baseline variants, and scalability over popular GitHub C/C++ software.
Datasets: CVE dataset and target software overview are present in Tables 3 and 4, but table cells need repair. [NEEDS TABLE REPAIR]
Baselines: MOVERY, V0Finder, CENTRIS, VUDDY, and combined version/code baselines appear in extracted table captions/context.
Metrics: precision, recall, F1-like accuracy measures, TP/FP/FN, elapsed time.
Implementation Details: local Detector.py and ctags-based tooling are visible; data needed for reproduction is missing. [NEEDS ARTIFACT]
Execution Status: [EXECUTION NOT REQUESTED]
{anchor}
""",
        "07_evaluation.txt": f"""Main Results: abstract reports that V1SCAN discovered more vulnerabilities than state-of-the-art approaches and reduced FP/FN rates; exact values require table repair. [NEEDS TABLE REPAIR]
Per-Section Findings: extracted pages show comparisons against MOVERY, V0Finder, improved version-based detection, improved code-based detection, combined approaches, and elapsed-time measurement.
Ablation / Comparison: Tables 6-8 appear to isolate improved version-based, improved code-based, and combined V1SCAN behavior. [NEEDS TABLE REPAIR]
Efficiency: Figure 5 covers elapsed time for 4,434 popular C/C++ software, but visual extraction is caption/context only. [NEEDS FIGURE EXTRACTION]
Unsupported or Weakly Supported Claims: any exact metric/table claim remains weak until table repair/manual PDF verification.
{anchor}
""",
        "08_limitations_ethics.txt": """Stated Limitations: [NEEDS EVIDENCE] No dedicated limitations/threats section was cleanly extracted in this pass.
Threats to Validity: likely tied to CVE/CPE mapping, OSS reuse detection, code modification, target selection, and dataset completeness, but exact wording needs manual verification. [NEEDS EVIDENCE]
Ethical Considerations: [NEEDS EVIDENCE] No standalone ethics section was identified.
Security / Misuse Discussion: paper is defensive vulnerability detection; do not infer disclosure or exploit workflow details.
Scope Boundaries: C/C++ OSS reuse and known 1-day vulnerabilities; not a general vulnerability discovery or affected versions system.
""",
        "09_figures_tables.txt": f"""Figure / Table Inventory:
- Tables detected: {table_count} caption-neighbor/raw units under raw_extraction/tables. All require [NEEDS TABLE REPAIR].
- Figures detected: {figure_count} caption/context units under raw_extraction/figures. All require [NEEDS FIGURE EXTRACTION].
Citation Readiness: low for exact numbers.
Figure Readiness: low.
Design Pattern: figures explain code classification/workflow/runtime; tables carry detection accuracy, dataset, and target-program evidence.
Required Figures for Our Paper: separate version-evidence and code-evidence channels, then show verifier-gated merge into affected versions.
""",
        "10_writing_patterns.txt": """Best Structural Moves: supply-chain risk -> limits of version/code baselines -> hybrid method -> empirical reduction of FP/FN.
Best Transition Moves: contrast two baseline families before presenting the combined design.
Best Contribution Wording Pattern: method improvement plus empirical comparison plus scalability evidence.
Patterns to Avoid: do not claim table metrics or artifact reproducibility until data directories and tables are repaired.
""",
        "11_relevance_to_our_paper.txt": """Direct Relevance: high for explaining why version metadata alone is insufficient for vulnerability impact/affected versions reasoning.
Indirect Relevance: useful for code-reuse and code-classification evidence design.
Useful for Which Section: motivation, related work, method contrast, evaluation framing.
What We Can Borrow Structurally: hybrid evidence pipeline framing and FP/FN reduction argument structure.
What We Cannot Borrow: exact numeric results, reproducibility claims, or affected versions claims without local evidence.
Priority: high.
""",
        "12_artifact_consistency.txt": """Paper Claims:
- V1SCAN combines version- and code-based approaches: partially supported by Detector.py function names and data paths.
- V1SCAN classifies reused/vulnerable code: partially supported by ctags/TLSH/entity extraction code.
- Evaluation datasets and results: paper text has tables, but local required dataset directories are empty/missing. [NEEDS ARTIFACT]
Implemented Components: Detector.py, Detector_wrong.py, 32_v1scan_auto.py, ctags/readtags/optscript, OSSList files.
Unimplemented or Missing Components: README not observed; Git2CPE/CPE2CVE/OSSallFuncs/OSSverList/vulHashes/vulFiles data not visible. [NEEDS ARTIFACT]
Static Reproduction Instructions or Missing Instructions: no README observed; execution not performed. [EXECUTION NOT REQUESTED]
Engineering Lessons for Our Paper: keep version-data, code-evidence, and artifact completeness as separate evidence channels.
""",
        "13_completeness_audit.txt": f"""Raw Extraction:
- PDF text extracted: yes
- Page text extracted: yes, page count 16
- Section text extracted: yes, section file count {section_count}
- Agent index exists: generated by required build_agent_index.py step after this file is written
- Extraction profile exists: generated by required build_agent_index.py step after this file is written
- Layout blocks extracted: partial
- References extracted: yes, text-only/uncertain
- Table extraction: caption-neighbor/raw only; [NEEDS TABLE REPAIR]
- Figure extraction: caption-only/context-only; [NEEDS FIGURE EXTRACTION]
- Formula/algorithm/prompt extraction: not detected; [NEEDS EVIDENCE]
- OCR needed: no

Section Analysis:
- 00_meta.txt through 12_artifact_consistency.txt: complete
- Are analysis files section-oriented enough for writing? yes

Source / Artifact Static Analysis:
- Source inventory exists: yes
- README/config inspected: README not observed [NEEDS ARTIFACT]
- Main entrypoints inspected: yes, statically
- Runtime behavior: [EXECUTION NOT REQUESTED]

Writing Readiness:
- Abstract support: strong
- Introduction support: strong
- Background/motivation support: strong
- Method support: partial
- Experiment/evaluation support: partial
- Limitations support: weak
- Related work support: partial

Known Gaps:
- [NEEDS TABLE REPAIR]
- [NEEDS FIGURE EXTRACTION]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade: medium, because paper text and visible source are useful for method/related-work framing, but tables, figures, citation metadata, and required datasets are not citation-ready.
""",
        "14_section_retrieval_map.txt": """For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/02_introduction.txt
- Must not claim: exact FP/FN reduction without table repair.

For Background / Motivation:
- Read analysis/03_background_motivation.txt
- Read raw_extraction/section_text/03_background.txt

For Method:
- Read analysis/05_method.txt
- Read raw_extraction/source_static_inventory.txt
- Read raw_extraction/source_static_symbols.json

For Experiments / Evaluation:
- Read analysis/06_experiments.txt and analysis/07_evaluation.txt
- Read raw_extraction/tables/table_index.txt
- Must not claim: citation-ready numbers until [NEEDS TABLE REPAIR] is resolved.

For Limitations:
- Read analysis/08_limitations_ethics.txt and analysis/13_completeness_audit.txt

For Related Work:
- Read raw_extraction/references.txt
- Must not claim: verified bibliography metadata until [NEEDS CITATION VERIFICATION] is resolved.
""",
    }
    for name, text in files.items():
        write(ANALYSIS / name, text)


def main():
    pdf, metadata, pages = extract_pdf()
    table_count, figure_count, section_count = write_pdf_artifacts(pdf, metadata, pages)
    symbol_count = write_source_inventory()
    write_analysis(table_count, figure_count, section_count)
    print(f"WROTE={PAPER_DIR}")
    print(f"PDF={pdf}")
    print(f"PAGES={len(pages)} TABLE_UNITS={table_count} FIGURE_UNITS={figure_count} SYMBOLS={symbol_count}")


if __name__ == "__main__":
    main()
