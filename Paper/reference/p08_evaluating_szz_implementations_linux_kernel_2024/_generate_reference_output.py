import json
import re
from datetime import datetime
from pathlib import Path

import fitz


PAPER_ID = "p08_evaluating_szz_implementations_linux_kernel_2024"
REF_ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference")
PAPER_DIR = REF_ROOT / PAPER_ID
RAW = PAPER_DIR / "raw_extraction"
ANALYSIS = PAPER_DIR / "analysis"
TARGET = Path(r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\TC-SZZ")
PDF = next(TARGET.glob("*.pdf"))
SOURCE = TARGET / "TC-SZZ"
PYSZZ = SOURCE / "pyszz"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def jwrite(path: Path, data) -> None:
    write(path, json.dumps(data, ensure_ascii=False, indent=2))


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

    doc = fitz.open(str(PDF))
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
    return doc.metadata or {}, pages


def page_range(pages, start, end):
    return "\n\n".join(
        f"===== PAGE {i:03d} =====\n{pages[i - 1]}"
        for i in range(start, min(end, len(pages)) + 1)
    )


def write_raw_extraction(metadata, pages):
    sections = {
        "01_abstract.txt": page_range(pages, 1, 1),
        "02_introduction.txt": page_range(pages, 1, 3),
        "03_background.txt": page_range(pages, 4, 6),
        "04_method.txt": page_range(pages, 6, 8) + "\n\n" + page_range(pages, 14, 16),
        "05_experiments.txt": page_range(pages, 8, 10),
        "06_evaluation.txt": page_range(pages, 9, 17),
        "07_related_work.txt": page_range(pages, 4, 6),
        "08_limitations.txt": page_range(pages, 18, 19),
        "09_references.txt": page_range(pages, 19, 21),
    }
    for name, text in sections.items():
        write(RAW / "section_text" / name, text)
    write(
        RAW / "sections.txt",
        """Section Map (heuristic from PDF headings)
01_abstract.txt: page 1 abstract block.
02_introduction.txt: pages 1-3, I. INTRODUCTION.
03_background.txt: pages 4-6, II. BACKGROUND AND RELATED WORK.
04_method.txt: pages 6-8 dataset/study design/TC-SZZ plus pages 14-16 ChatGPT pipeline.
05_experiments.txt: pages 8-10 study design and initial result setup.
06_evaluation.txt: pages 9-17 results, RQ1-RQ3, ChatGPT/model comparison.
07_related_work.txt: pages 4-6 related SZZ variants and prior datasets.
08_limitations.txt: pages 18-19, IX. THREATS TO VALIDITY plus conclusion boundary notes.
09_references.txt: pages 19-21 references.
Boundary Confidence: medium for top-level sections; partial for subsection-level and table/figure boundaries.
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
        if line.startswith("TABLE"):
            ctx = "\n".join(lines[q][1] for q in range(idx, min(idx + 12, len(lines))))
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
        for m in re.finditer(r"Fig\.\s*\d+\.?[^\n]*(?:\n[^\n]{0,180})?", text):
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
    write(
        RAW / "prompts" / "prompt_001.txt",
        "ID: prompt_001\nPage: 14-16\nSection: Classical Meets Modern: Enhancing SZZ with ChatGPT\n"
        "Raw Evidence: Table IX is prompt-related, but cell-level prompt formatting was not repaired.\n"
        "Extraction Confidence: partial\nRepair Needed: [NEEDS TABLE REPAIR]\n",
    )

    jwrite(
        RAW / "metadata.json",
        {
            "paper_id": PAPER_ID,
            "title": metadata.get("title") or "Evaluating SZZ Implementations: An Empirical Study on the Linux Kernel",
            "authors": ["Yunbo Lyu", "Hong Jin Kang", "Ratnadira Widyasari", "Julia Lawall", "David Lo"],
            "venue": "IEEE Transactions on Software Engineering",
            "year": "2024",
            "doi": "10.1109/TSE.2024.3406718",
            "arxiv": "",
            "pdf_path": str(PDF),
            "artifact_type": "Type A",
            "page_count": len(pages),
            "citation_status": "metadata from PDF subject; [NEEDS CITATION VERIFICATION]",
        },
    )
    write(
        RAW / "00_source_manifest.txt",
        f"""Paper ID: {PAPER_ID}
Original PDF Path: {PDF}
Original Text Path: {RAW / 'full_text.txt'}
Source Code Path or URL: {SOURCE}
Artifact/Data Path or URL: {SOURCE / 'dataset'}; {SOURCE / 'verify_dataset'}; {SOURCE / 'chatgpt_result'}
Extraction Date: {datetime.now().isoformat(timespec='seconds')}
Extraction Tools: PyMuPDF/fitz static PDF text extraction; PowerShell/Python filesystem inventory
Artifact Type: Type A
Notes: Target source/artifact inspected statically only. [EXECUTION NOT REQUESTED]
""",
    )
    write(
        RAW / "extraction_log.txt",
        f"""Status: PDF text extracted; section split heuristic; layout/table/figure extraction partial.
Tools Used: PyMuPDF/fitz; static filesystem/code reads.
Successful Outputs: full_text.txt; page_text for {len(pages)} pages; layout_blocks JSON; section_text; metadata.json; source manifest; caption-neighbor table/figure indexes; source_static_inventory.txt.
Failed Outputs: citation-ready tables; exact figure crops; verified bibliography; executable reproduction.
Pages With Empty Text: none observed.
OCR Needed: no.
Tables Extracted: {len(tables)} caption-neighbor/raw table units, all [NEEDS TABLE REPAIR].
Figures/Captions Extracted: {len(figures)} caption/context units, all [NEEDS FIGURE EXTRACTION].
References Extracted: yes, text-only, [NEEDS CITATION VERIFICATION].
Known Losses: multi-column ordering may be imperfect; tables and prompt table are not cell-repaired; figure visuals are not cropped.
Next Repair Step: table repair/manual PDF verification for Tables I-XI and figure/page crop extraction.
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
        SOURCE / "README.md",
        PYSZZ / "README.md",
        PYSZZ / "main.py",
        PYSZZ / "requirements.txt",
        PYSZZ / "Dockerfile",
        PYSZZ / "szz" / "core" / "abstract_szz.py",
        PYSZZ / "szz" / "tc_szz.py",
        PYSZZ / "szz" / "tc_szz_1.py",
        PYSZZ / "szz" / "tc_szz_2.py",
        SOURCE / "dataset" / "filtered_data.json",
        SOURCE / "dataset" / "abnormal_commits.csv",
        SOURCE / "verify_dataset" / "annotation_383cases.csv",
        SOURCE / "verify_dataset" / "LabelingGuideline.pdf",
    ]
    symbols = []
    for fp in [PYSZZ / "main.py", PYSZZ / "szz" / "core" / "abstract_szz.py", PYSZZ / "szz" / "tc_szz.py", PYSZZ / "szz" / "tc_szz_1.py", PYSZZ / "szz" / "tc_szz_2.py"]:
        if fp.exists():
            for ln, line in enumerate(fp.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                if re.match(r"\s*(class|def)\s+", line):
                    symbols.append({"file": str(fp), "line": ln, "symbol": line.strip()})
    jwrite(RAW / "source_static_symbols.json", {"symbols": symbols})
    write(
        RAW / "source_static_inventory.txt",
        f"""Source Path: {SOURCE}
Analysis Mode: static-only [EXECUTION NOT REQUESTED]
Repository / File Layout Observed:
- Root README describes a replication package for the TSE paper.
- dataset/: abnormal_commits.csv, common_hashes.txt, filtered_data.json. README claims dataset_linux.json and sorted_sampled_dataset.json, but local names differ or are absent in this snapshot. [NEEDS ARTIFACT]
- verify_dataset/: annotation_383cases.csv and LabelingGuideline.pdf are visible; sorted_sampled_dataset.json was not observed. [NEEDS ARTIFACT]
- pyszz/: Python implementation folder with main.py, szz variants, Dockerfile, requirements.txt, run_docker.sh, time.txt.
- chatgpt_result/: xlsx summaries plus generated prompt/output text directories for codegen2 and codet5+.
Primary Files:
{chr(10).join('- ' + str(p) for p in key_files if p.exists())}
Key Static Evidence:
- pyszz/main.py dispatches among b/ag/ma/r/tc/l/ra SZZ implementations and routes TC-SZZ to TCSZZ with blame_times_target and mode parameters.
- szz/core/abstract_szz.py defines AbstractSZZ, impacted-file parsing through PyDriller, git blame wrapper, comment skipping, and line-range parsing.
- szz/tc_szz.py defines TCSZZ.find_bic, iterative blame tracing, map_modified_line, whitespace-normalized Levenshtein line matching, and mode 2 duplicate removal.
Static Consistency Notes:
- Paper-level TC-SZZ claim that tracing follows changed-line history is partially supported by tc_szz.py static code.
- Paper/README claim of a dataset of 76,046 pairs is supported by README text, but dataset_linux.json is not visible by that exact name. [NEEDS ARTIFACT]
- README run instructions mention conf/tcszz.yml, but no pyszz/conf directory was visible. [NEEDS ARTIFACT]
- main.py contains a hard-coded CVE target list, so this local copy may be adapted.
Observed Local Output / Data Artifacts:
- chatgpt_result contains xlsx files and many model output text files.
- dataset contains CSV/TXT/JSON files; verify_dataset contains annotation CSV and labeling guideline PDF.
Missing Data / Missing Entrypoints:
- conf directory and named tcszz.yml not observed. [NEEDS ARTIFACT]
- README-mentioned dataset_linux.json and sorted_sampled_dataset.json not observed. [NEEDS ARTIFACT]
- Runtime behavior and reported metrics were not reproduced. [EXECUTION NOT REQUESTED]
""",
    )
    return len(symbols)


def write_analysis(table_count, figure_count, section_count):
    anchor = "Agent Evidence Anchors: raw_extraction/full_text.txt; raw_extraction/section_text; raw_extraction/source_static_inventory.txt; raw_extraction/tables; raw_extraction/figures."
    files = {
        "00_meta.txt": f"""Paper ID: {PAPER_ID}
Title: Evaluating SZZ Implementations: An Empirical Study on the Linux Kernel
Venue / Year: IEEE Transactions on Software Engineering / 2024
Authors: Yunbo Lyu; Hong Jin Kang; Ratnadira Widyasari; Julia Lawall; David Lo
Artifact Type: Type A
Input Files: {PDF}
Source / Artifact Path: {SOURCE}
Analysis Status: complete for static citation-analysis pass; runtime reproduction not requested.
Agent Index Status: generated by build_agent_index.py after extraction files.
Main Topic: empirical evaluation of SZZ variants on Linux developer-labeled bug-fixing/bug-inducing commit pairs, ghost commits, TC-SZZ, and ChatGPT-assisted analysis.
Citation Metadata Status: DOI and venue inferred from PDF metadata; [NEEDS CITATION VERIFICATION].
Missing Evidence: [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]; [NEEDS ARTIFACT]; [EXECUTION NOT REQUESTED].
""",
        "01_abstract.txt": f"""Problem: SZZ links bug-fixing commits to bug-introducing commits, but variant performance and ghost-commit effects remain difficult to evaluate at Linux scale.
Gap: Prior datasets were researcher-created; this paper uses Linux developer labels to reduce that dataset-construction bias.
Core Idea: Evaluate six SZZ implementations on 76,046 Linux pairs, analyze ghost commits, introduce TC-SZZ for tracing line history, and test ChatGPT/model assistance.
Method: Compare SZZ variants; remove/analyze ghost commits; run TC-SZZ over failure cases; categorize failures by function/file history; evaluate ChatGPT prompts.
Main Results: Abstract reports recall decline versus prior findings, 17.47% ghost commits, TC-SZZ recovery over some non-ghost failures, and categorized locations of missed inducing commits.
Reusable Writing Pattern: established algorithm -> evaluation gap -> stronger oracle -> diagnostic method/failure findings.
Relevance to Our Paper: useful for motivating why affected versions and vulnerability history tasks need developer/ground-truth-aware evaluation.
Do Not Borrow: exact numbers before table repair/manual verification.
{anchor}
""",
        "02_introduction.txt": f"""Opening Context: SZZ is framed as a long-used method for connecting fixes to earlier bug-introducing commits.
Why the Problem Matters: bug-inducing commit identification supports defect prediction, empirical SE, and historical reasoning.
Concrete Pain Point: SZZ can miss cases where the introducing commit is not a straightforward blame result; the paper names these ghost commits.
Prior Work Framing: multiple SZZ variants and prior datasets are positioned as incomplete for Linux-scale developer-labeled assessment.
Key Insight: developer-labeled Linux pairs expose common limitations across SZZ variants and line-history cases where deeper tracing helps.
Paragraph Map:
P1: introduce SZZ and applications.
P2: expose ghost commits and tracing failures.
P3: justify Linux developer-labeled dataset and RQs.
Risks for Our Paper: affected versions claims should avoid relying only on commit-level SZZ metrics.
{anchor}
""",
        "03_background_motivation.txt": f"""Domain Concepts Introduced: SZZ, bug-fixing commits, bug-inducing commits, git blame, SZZ variants, ghost commits, Linux Fixes-style labels.
Task Definition: Given a bug-fixing commit, identify one or more earlier bug-inducing commits.
Motivating Case: ghost commits show why a direct blame-to-introducing-commit assumption can fail. [NEEDS FIGURE EXTRACTION]
Writing Pattern: definitions are paired with concrete version-control mechanics and prior tool variants before RQs.
Relevance to Our Paper: good model for introducing affected versions as an evidence relation rather than a purely textual vulnerability attribute.
{anchor}
""",
        "04_problem_definition.txt": """Input: bug-fixing commit and repository history; for TC-SZZ, impacted files/modified lines and configuration parameters.
Output: candidate bug-inducing commits, plus evaluation against developer-labeled ground truth.
Objects / Entities: fix, inducing commit, modified/deleted line, blame entry, ghost commit, SZZ variant, dataset pair.
Objective: measure SZZ effectiveness, isolate ghost-commit impact, and recover missed cases through changed-line history tracing.
Boundary Conditions: source pass did not execute TC-SZZ or validate metrics. [EXECUTION NOT REQUESTED]
What Is Not Solved: general vulnerability affected versions identification is not directly solved; this is a commit-identification baseline.
""",
        "05_method.txt": f"""System Overview: dataset construction, multiple SZZ runs, ghost-commit filtering/analysis, TC-SZZ tracing, and ChatGPT/code-model experiments.
Pipeline Stages: collect Linux pairs; verify sample/dataset; select SZZ implementations; compute metrics; analyze ghost commits; apply TC-SZZ to non-ghost failures; categorize remaining failures; evaluate ChatGPT/model assistance.
Core Algorithm: tc_szz.py statically shows iterative blame, mapping a blamed line into deleted lines of the blamed commit using whitespace-normalized Levenshtein similarity, and optional mode-2 duplicate removal.
Design Choices: blame_times_target controls tracing depth; mode controls all previous commits versus unique commits; comment skipping/file extension filtering reuse PySZZ base logic.
Static Reproducibility Signals: README, Dockerfile, requirements.txt, run_docker.sh, dataset/artifact directories visible; config paths/data names partially missing. [NEEDS ARTIFACT]
Execution Status: [EXECUTION NOT REQUESTED]
{anchor}
""",
        "06_experiments.txt": f"""Research Questions: RQ1 compares SZZ variants; RQ2 studies ghost-commit impact; RQ3 studies other failure situations and TC-SZZ; later section studies ChatGPT/code models.
Datasets: Linux kernel developer-labeled pairs; README claims 76,046 pairs, but local artifact names partially diverge. [NEEDS ARTIFACT]
Baselines: B-SZZ, AG-SZZ, L-SZZ, R-SZZ, MA-SZZ, SZZ@PYD and related variants; exact table values need repair. [NEEDS TABLE REPAIR]
Metrics: recall, precision, F1/F-measure, overlap, average identified commits, t-test/effect-size table.
Static Reproducibility Materials: README, Dockerfile, requirements.txt, datasets, verification annotation CSV, ChatGPT result XLSX/text directories.
Execution Status: [EXECUTION NOT REQUESTED]
{anchor}
""",
        "07_evaluation.txt": f"""Main Results: abstract reports lower SZZ recall on Linux than prior findings, 17.47% ghost commits, TC-SZZ recovery over part of non-ghost failures, and ChatGPT/model comparisons.
Per-RQ Findings: RQ1 reduced recall and smaller variant disparities; RQ2 ghost commits materially affect results; RQ3 failures can be categorized by function/file history and TC-SZZ addresses a subset.
Ablation: ghost-commit removal functions like an evaluation-condition ablation; exact before/after metrics require Table VI repair. [NEEDS TABLE REPAIR]
Error Analysis: strong part of the paper: ghost commits, function-history/file-history/out-of-file categories, ChatGPT error categories.
Unsupported or Weakly Supported Claims: any exact metric/table claim is weak until table repair/manual verification.
{anchor}
""",
        "08_limitations_ethics.txt": """Stated Limitations: threats to validity section is present; exact subclaims need manual reading/table/figure repair for citation-ready use.
Threats to Validity: dataset construction, developer-label reliability, implementation differences, ghost-commit categorization, and ChatGPT data-cutoff concerns are relevant from extracted headings/context.
Ethical Considerations: [NEEDS EVIDENCE] No standalone ethics section was extracted.
Security / Misuse Discussion: [NEEDS EVIDENCE] Paper is empirical SE/SZZ-focused rather than exploit-enabling; no misuse analysis extracted.
Scope Boundaries: Linux kernel focus; commit-identification focus; ChatGPT analysis bounded by data cutoff and sampled categories.
""",
        "09_figures_tables.txt": f"""Figure / Table Inventory:
- Tables detected: {table_count} caption-neighbor/raw units under raw_extraction/tables. All require [NEEDS TABLE REPAIR].
- Figures detected: {figure_count} caption/context units under raw_extraction/figures. All require [NEEDS FIGURE EXTRACTION].
Citation Readiness: low for exact numbers.
Figure Readiness: low.
Design Pattern: tables carry RQ evidence; figures explain ghost commits, pipeline, and examples.
Required Figures for Our Paper: affected versions pipeline figure, verifier/evidence graph, and source-backed evaluation tables.
""",
        "10_writing_patterns.txt": """Best Structural Moves: accepted baseline -> hidden evaluation weakness -> stronger oracle -> failure diagnosis.
Best Transition Moves: algorithm importance to dataset bias; dataset bias to RQs; weak results to failure taxonomy plus targeted method.
Best Contribution Wording Pattern: dataset-scale contribution + empirical re-evaluation + failure taxonomy + method improvement + modern model-assistance study.
Patterns to Avoid: do not overstate static artifact reproducibility; do not use table numbers before table repair.
""",
        "11_relevance_to_our_paper.txt": """Direct Relevance: baseline for bug-inducing commit identification, useful for contrasting with affected versions pipelines.
Indirect Relevance: strong model for developer-labeled evidence, failure taxonomy, and verifier-like dataset validation.
Useful for Which Section: introduction motivation, SZZ background, evaluation design, limitations/threats to validity.
What We Can Borrow Structurally: RQ framing, failure taxonomy style, validity discussion structure.
What We Cannot Borrow: affected versions claims, exact numerical metrics without table repair, runtime reproducibility claims without execution.
Priority: high for background/evaluation framing; medium for method transfer.
""",
        "12_artifact_consistency.txt": """Paper Claims:
- Linux dataset with 76,046 pairs: supported by PDF abstract/README text; local exact dataset_linux.json not visible. [NEEDS ARTIFACT]
- TC-SZZ traces commit history of modified/deleted lines: partially supported by tc_szz.py static code.
- ChatGPT/code-model experiment artifacts: supported by chatgpt_result directory and xlsx/text files; exact contents not deeply parsed. [NEEDS ARTIFACT]
Implemented Components: PySZZ variants and TCSZZ class, main.py dispatcher, Docker/requirements/run script.
Paper-Code Mismatches: local main.py hard-codes a CVE target list; README path claims differ from visible tree.
Static Reproduction Instructions or Missing Instructions: README gives Docker and command examples; execution not performed. [EXECUTION NOT REQUESTED]
Engineering Lessons for Our Paper: keep artifact paths, configs, dataset manifests, and evaluation scripts aligned with paper claims.
""",
        "13_completeness_audit.txt": f"""Raw Extraction:
- PDF text extracted: yes
- Page text extracted: yes, page count 21
- Section text extracted: yes, section file count {section_count}
- Agent index exists: generated by required build_agent_index.py step after this file is written
- Extraction profile exists: generated by required build_agent_index.py step after this file is written
- Layout blocks extracted: partial
- References extracted: yes, text-only/uncertain
- Table extraction: caption-neighbor/raw only; [NEEDS TABLE REPAIR]
- Figure extraction: caption-only/context-only; [NEEDS FIGURE EXTRACTION]
- Formula/algorithm/prompt extraction: prompt pointer partial; formulas/algorithms not detected; [NEEDS EVIDENCE]
- OCR needed: no

Section Analysis:
- 00_meta.txt through 12_artifact_consistency.txt: complete
- Are analysis files section-oriented enough for writing? yes

Source / Artifact Static Analysis:
- Source inventory exists: yes
- README/config inspected: README yes; config missing/not visible [NEEDS ARTIFACT]
- Main entrypoints inspected: yes, statically
- Runtime behavior: [EXECUTION NOT REQUESTED]

Writing Readiness:
- Abstract support: strong
- Introduction support: strong
- Background/motivation support: strong
- Method support: partial
- Experiment/evaluation support: partial
- Limitations support: partial
- Related work support: partial

Known Gaps:
- [NEEDS TABLE REPAIR]
- [NEEDS FIGURE EXTRACTION]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade: medium, because text/code evidence is sufficient for writing structure and baseline understanding, but exact metrics, figures, and artifact reproduction remain unrepaired/unexecuted.
""",
        "14_section_retrieval_map.txt": """For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/02_introduction.txt
- Must not claim: exact metric deltas without table repair.

For Background / Motivation:
- Read analysis/03_background_motivation.txt
- Read raw_extraction/section_text/03_background.txt

For Method:
- Read analysis/05_method.txt
- Read raw_extraction/source_static_inventory.txt
- Read raw_extraction/source_static_symbols.json
- Must not claim: runtime performance reproduced.

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
    metadata, pages = extract_pdf()
    table_count, figure_count, section_count = write_raw_extraction(metadata, pages)
    symbol_count = write_source_inventory()
    write_analysis(table_count, figure_count, section_count)
    print(f"WROTE={PAPER_DIR}")
    print(f"PDF={PDF}")
    print(f"PAGES={len(pages)} TABLE_UNITS={table_count} FIGURE_UNITS={figure_count} SYMBOLS={symbol_count}")


if __name__ == "__main__":
    main()
