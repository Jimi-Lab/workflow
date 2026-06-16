from __future__ import annotations

import ast
import json
import re
from datetime import date
from pathlib import Path

from pypdf import PdfReader


PAPER_ID = "p12_enhancing_security_third_party_library_reuse_2025"
ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference") / PAPER_ID
RAW = ROOT / "raw_extraction"
ANALYSIS = ROOT / "analysis"
PDF_COPY = RAW / "source_pdf.pdf"
ORIGINAL_PDF = (
    r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)"
    r"\Direct_Comparison_Papers(Baseline_Paper+Code)\VULTURE"
    r"\Enhancing Security in Third-Party Library Reuse-Comprehensive Detection of 1-day Vulnerability through Code Pa.pdf"
)
ORIGINAL_PDF_SHORT = r"E:\AI\Agent\workflow\Replication\BASELI~1\DIRECT~1\VULTURE\ENHANC~1.PDF"
SOURCE = Path(
    r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)"
    r"\Direct_Comparison_Papers(Baseline_Paper+Code)\VULTURE\VULTURE"
)
TITLE = "Enhancing Security in Third-Party Library Reuse - Comprehensive Detection of 1-day Vulnerability through Code Patch Analysis"
AUTHORS = ["Shangzhi Xu", "Jialiang Dong", "Weiting Cai", "Juanru Li", "Arash Shaghaghi", "Nan Sun", "Siqi Ma"]
VENUE = "Network and Distributed System Security (NDSS) Symposium 2025"
YEAR = "2025"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def extract_pdf() -> tuple[list[str], list[int]]:
    for sub in ["page_text", "section_text", "tables", "figures", "formulas", "algorithms", "prompts", "layout_blocks"]:
        (RAW / sub).mkdir(parents=True, exist_ok=True)
    reader = PdfReader(str(PDF_COPY))
    pages: list[str] = []
    empty_pages: list[int] = []
    for i, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        pages.append(text)
        if not text.strip():
            empty_pages.append(i)
        write(RAW / "page_text" / f"page_{i:03d}.txt", text)
    full = "\n\n".join(f"===== PAGE {i:03d} =====\n{text}" for i, text in enumerate(pages, start=1))
    write(RAW / "full_text.txt", full)
    return pages, empty_pages


def split_sections(full: str) -> int:
    heading_re = re.compile(r"(?m)^([IVX]+\.\s+[A-Z][A-Z /:,0-9-]+|[A-Z]\.\s+[A-Za-z][^\n]{2,90}|REFERENCES|[A-Z]\. Appendix [A-Z])$")
    headings: list[tuple[str, int]] = []
    for m in heading_re.finditer(full):
        heading = re.sub(r"\s+", " ", m.group(1).strip())
        if heading not in [h for h, _ in headings]:
            headings.append((heading, m.start()))
    wanted = [
        ("01_abstract.txt", "Abstract"),
        ("02_introduction.txt", "I. I NTRODUCTION"),
        ("03_background.txt", "II. B ACKGROUND"),
        ("04_overview.txt", "III. O VERVIEW"),
        ("05_method.txt", "IV. V ULTURE"),
        ("06_experiment.txt", "V. E XPERIMENT"),
        ("07_related_work.txt", "VI. R ELATED WORK"),
        ("08_conclusion.txt", "VII. C ONCLUSION"),
        ("09_references.txt", "REFERENCES"),
        ("10_appendix_a.txt", "A. Appendix A"),
        ("11_appendix_b.txt", "B. Appendix B"),
    ]
    positions: list[tuple[str, str, int]] = []
    abstract_match = re.search(r"(?m)^Abstract—", full)
    if abstract_match:
        positions.append(("01_abstract.txt", "Abstract", abstract_match.start()))
    for filename, heading in wanted[1:]:
        match = re.search(r"(?m)^" + re.escape(heading) + r"$", full)
        if match:
            positions.append((filename, heading, match.start()))
    positions.sort(key=lambda item: item[2])
    lines = ["Detected Section Headings:", ""]
    lines += [f"- {heading}" for heading, _ in headings]
    lines += ["", "Section Files:"]
    for idx, (filename, heading, start) in enumerate(positions):
        end = positions[idx + 1][2] if idx + 1 < len(positions) else len(full)
        write(RAW / "section_text" / filename, full[start:end].strip() + "\n")
        lines.append(f"- {filename}: {heading}")
    lines += ["", "Notes: conservative split from PDF text layer; IEEE/NDSS two-column ordering, formulas, and code examples may be imperfect. [NEEDS LAYOUT BLOCK EXTRACTION]"]
    write(RAW / "sections.txt", "\n".join(lines) + "\n")
    return len(positions)


def extract_captions(full: str) -> tuple[int, int]:
    counts: dict[str, int] = {}
    for kind in ["table", "figure"]:
        label = "Table" if kind == "table" else "Fig\\."
        pattern = re.compile(rf"(?im)^{label}\s+[IVX\d]+[.:][^\n]*(?:\n(?![IVX]+\.\s|Fig\.\s|Table\s|REFERENCES).{{0,180}}){{0,2}}")
        directory = RAW / ("tables" if kind == "table" else "figures")
        index: list[str] = []
        for n, match in enumerate(pattern.finditer(full), start=1):
            prefix = f"{kind}_{n:03d}"
            caption = match.group(0).strip()
            page_marks = list(re.finditer(r"===== PAGE (\d{3}) =====", full[: match.start()]))
            page = int(page_marks[-1].group(1)) if page_marks else None
            context = full[max(0, match.start() - 900) : min(len(full), match.end() + 900)]
            if kind == "table":
                write(directory / f"{prefix}_caption.txt", caption + "\n\n[NEEDS TABLE REPAIR]\n")
                write(directory / f"{prefix}_raw.txt", caption + "\n\n[NEEDS TABLE REPAIR] Structured cells were not recovered from text extraction.\n")
            else:
                write(directory / f"{prefix}_caption.txt", caption + "\n\n[NEEDS FIGURE EXTRACTION]\n")
                write(directory / f"{prefix}_agent_summary.txt", "Caption/context-only figure evidence. Image crop was not extracted. [NEEDS FIGURE EXTRACTION]\n")
            write(directory / f"{prefix}_context.txt", context)
            index.append(f"{prefix}: page={page or 'unknown'}; caption/context only; repair_needed=yes")
        write(directory / f"{kind}_index.txt", "\n".join(index) + ("\n" if index else f"No {kind} captions detected in plain text extraction.\n"))
        counts[kind] = len(index)
    return counts["table"], counts["figure"]


def source_inventory() -> tuple[int, int, int]:
    py_files = [p for p in sorted(SOURCE.rglob("*.py")) if "__pycache__" not in p.parts]
    all_files = [p for p in sorted(SOURCE.rglob("*")) if p.is_file()]
    artifact_exts = {".xlsx", ".png", ".pdf", ".txt", ".yml", ".sh"}
    artifacts = [p for p in all_files if p.suffix.lower() in artifact_exts or p.name in {"CommitBenckmark", "fp_eliminationLiteOS", "modified_resultLiteOS", "modified_result_without_funcLiteOS"}]
    dirs = [p for p in sorted(SOURCE.iterdir()) if p.is_dir()]
    lines = [
        f"Source Path: {SOURCE}",
        "Analysis Mode: static-only",
        "Runtime behavior: [EXECUTION NOT REQUESTED]",
        "Artifact Type: Type A (paper + source code + local benchmark/data-like artifacts).",
        "",
        "Repository / File Layout Observed:",
    ]
    for directory in dirs:
        lines.append(f"- {directory.name}/")
    lines += [
        f"- Python source files inspected statically: {len(py_files)}",
        f"- Total files observed: {len(all_files)}",
        f"- Local artifact/data-like files observed: {len(artifacts)}",
        "",
        "Primary Files and Artifacts:",
    ]
    for rel in [
        "README.md", "requirements.txt", "setup_pyenv.sh", "CommitBenckmark", "VulnerabilityBenckmark.xlsx",
        "iotList.txt", "vulture.png", "OneDayDetector/VersionBasedDetection.py",
        "OneDayDetector/ChunkExtraction.py", "OneDayDetector/DBConstruction.py",
        "TPLReuseDetector/Detector.py", "TPLReuseDetector/fp_eliminator.py",
        "TPLselection/src/preprocessor/Preprocessor.py", "TPLselection/src/patchcollector/collect_patch.py",
        "TPLselection/src/patchcollector/utils.py", "TPLselection/src/patchcollector/README.md",
    ]:
        path = SOURCE / rel
        lines.append(f"- {rel}: present={path.exists()}, bytes={path.stat().st_size if path.exists() else 'missing'}")
    lines += ["", "Static Python Symbol Inventory:"]
    for path in py_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(text)
        except Exception as exc:
            lines.append(f"- {path.relative_to(SOURCE)}: parse_error={exc}")
            continue
        imports, funcs, classes = [], [], []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                try:
                    imports.append(ast.unparse(node))
                except Exception:
                    imports.append(type(node).__name__)
            if isinstance(node, ast.FunctionDef):
                funcs.append(node.name)
            if isinstance(node, ast.ClassDef):
                classes.append(node.name)
                funcs += [f"{node.name}.{m.name}" for m in node.body if isinstance(m, ast.FunctionDef)]
        lines += [
            f"- {path.relative_to(SOURCE)}",
            f"  imports: {'; '.join(imports[:10]) if imports else 'none'}",
            f"  classes: {', '.join(classes[:8]) if classes else 'none'}",
            f"  functions: {', '.join(funcs[:28]) if funcs else 'none'}",
        ]
    lines += [
        "",
        "Key Static Evidence:",
        "- README states VULTURE detects 1-day vulnerabilities arising from vulnerable third-party library reuse and is composed of TPLFILTER construction, TPL reuse identification, and 1-day vulnerability detection.",
        "- README points to an external Zenodo dataset; local artifacts include benchmarks and preprocessor outputs, but the complete dataset state is not verified. [NEEDS ARTIFACT]",
        "- OneDayDetector contains version-based detection, chunk extraction, database construction, path diff, and item split code using tlsh, libclang, subprocess, and JSON artifacts.",
        "- TPLReuseDetector contains hashing-based Detector.py plus fp_eliminator.py and local result-like artifacts for LiteOS.",
        "- TPLselection contains OSS collection, patch collection, preprocessing, componentDB, funcDate, initialSigs, metaInfos, and verIDX artifacts for several projects.",
        "- patchcollector README requires GitHub, NVD, and OpenAI API keys; requirements include OpenAI/LangChain packages. No API/network calls were executed. [EXECUTION NOT REQUESTED]",
        "- setup_pyenv.sh installs system packages and Python versions; it was not executed. [EXECUTION NOT REQUESTED]",
        "",
        "Static Consistency Notes:",
        "- Paper claims about TPLFILTER, TPL reuse identification, version-based detection, and chunk-based analysis are reflected by README and source layout at a static level.",
        "- Local code and artifact tree is richer than paper-only, but complete reproduction remains unverified because external dataset/API-dependent collection and environment setup were not run. [EXECUTION NOT REQUESTED]",
        "- Exact reported counts and benchmark metrics need table repair and artifact verification before citation-ready use. [NEEDS TABLE REPAIR]",
        "",
        "Observed Local Output / Data Artifacts:",
    ]
    for path in artifacts[:80]:
        lines.append(f"- {path.relative_to(SOURCE)}: bytes={path.stat().st_size}")
    if len(artifacts) > 80:
        lines.append(f"- ... {len(artifacts) - 80} additional artifact-like files omitted from this inventory summary.")
    lines += [
        "",
        "Missing Data / Missing Entrypoints:",
        "- External Zenodo dataset referenced by README was not downloaded or verified. [NEEDS ARTIFACT]",
        "- API keys and live GitHub/NVD/OpenAI collection path were not used. [EXECUTION NOT REQUESTED]",
        "- No scripts, setup, detectors, preprocessors, or notebooks were executed. [EXECUTION NOT REQUESTED]",
    ]
    write(RAW / "source_static_inventory.txt", "\n".join(lines) + "\n")
    return len(py_files), len(all_files), len(artifacts)


def write_raw_metadata(pages: list[str], empty_pages: list[int]) -> None:
    full = (RAW / "full_text.txt").read_text(encoding="utf-8", errors="replace")
    ref_match = re.search(r"(?ms)^REFERENCES\s*(.*)$", full)
    refs = ref_match.group(1).strip() if ref_match else "[NEEDS CITATION VERIFICATION] References section not isolated."
    write(RAW / "references.txt", refs + "\n\n[NEEDS CITATION VERIFICATION] Metadata not verified against official bibliography.\n")
    write(RAW / "appendix.txt", "Appendix A/B text is partially extracted in section_text when detected. Appendix layout remains partial. [NEEDS LAYOUT BLOCK EXTRACTION]\n")
    metadata = {
        "paper_id": PAPER_ID,
        "title": TITLE,
        "authors": AUTHORS,
        "venue": VENUE,
        "year": YEAR,
        "doi": "10.14722/ndss.2025.240576",
        "arxiv": "",
        "pdf_path": ORIGINAL_PDF,
        "local_pdf_copy": "raw_extraction/source_pdf.pdf",
        "artifact_type": "Type A",
        "page_count": len(pages),
        "citation_status": "unverified",
    }
    write(RAW / "metadata.json", json.dumps(metadata, indent=2, ensure_ascii=False) + "\n")
    write(RAW / "00_source_manifest.txt", f"""Paper ID: {PAPER_ID}
Original PDF Path: {ORIGINAL_PDF}
Original PDF Short Path Used For Copy: {ORIGINAL_PDF_SHORT}
Local PDF Copy For Extraction: raw_extraction/source_pdf.pdf
Original Text Path:
Source Code Path or URL: {SOURCE}
Artifact/Data Path or URL: local benchmark/data-like artifacts under source tree; external Zenodo dataset referenced by README [NEEDS ARTIFACT]
Extraction Date: {date.today().isoformat()}
Extraction Tools: pypdf text extraction; Python ast/static file inspection
Artifact Type: Type A
Notes: Source/artifacts inspected statically only. No setup, API, detector, collector, preprocessing, or experiments were executed. [EXECUTION NOT REQUESTED]
""")
    write(RAW / "extraction_log.txt", f"""Status: partial-complete raw extraction
Tools Used: pypdf; Python static AST/file inspection
Successful Outputs: full_text.txt; page_text/page_001..page_{len(pages):03d}.txt; sections.txt; section_text; references.txt; caption/context-level table and figure files; source_static_inventory.txt
Failed Outputs: layout block coordinates; structured table cells/CSV; figure crops; formula/algorithm/prompt repair
Pages With Empty Text: {empty_pages if empty_pages else 'none'}
OCR Needed: no
Tables Extracted: caption/context/raw only; [NEEDS TABLE REPAIR]
Figures/Captions Extracted: caption/context only; [NEEDS FIGURE EXTRACTION]
References Extracted: yes, text-layer only; [NEEDS CITATION VERIFICATION]
Known Losses: two-column ordering, equations/formulas, appendix layout, and figure/table structure may be imperfect.
PDF Text Complete: yes
PDF Layout Partial: yes
Citation-Ready Tables: no
Figure-Ready: no
Agent Index: pending rebuild by build_agent_index.py
Next Repair Step: run build_agent_index.py; repair tables/figures and formula/appendix layout before exact claims.
""")
    write(RAW / "extraction_profile.txt", """Primary Consumer: agent
PDF Text Layer: complete
Layout Block Layer: missing/not attempted
Table Layer: caption-only
Figure Layer: caption-only
Formula Layer: not detected/not attempted
Algorithm Layer: not detected/not attempted
Prompt Layer: partial/not repaired
Known Ordering Losses: two-column reading order and appendix details may be wrong because layout blocks were not extracted.
Known Layout Losses: table cells, figure crops, formulas, algorithm/prompt blocks, and appendix layout are not repaired.
Agent Retrieval Usability: high
Citation Readiness: low
Next Repair Step: [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]; [NEEDS LAYOUT BLOCK EXTRACTION]; [NEEDS CITATION VERIFICATION]
""")


def write_analysis(page_count: int, section_count: int) -> None:
    files = {
        "00_meta.txt": f"""Paper ID: {PAPER_ID}
Title: {TITLE}
Venue / Year: {VENUE} / {YEAR}
Authors: {', '.join(AUTHORS)}
Artifact Type: Type A
Input Files: original PDF; local VULTURE source tree; README/config/scripts/data-like artifacts inspected statically
Source / Artifact Path: {SOURCE}
Analysis Status: section-level analysis complete with extraction caveats
Agent Index Status: pending post-generation rebuild at time of writing this file
Main Topic: detecting 1-day vulnerabilities in third-party library reuse through platform-specific TPL database construction, reuse identification, version-based analysis, and chunk-based patch analysis.
Why This Paper Is Relevant: VULTURE is a direct baseline/reference for affected third-party library reuse and 1-day vulnerability detection, with explicit version and patch analysis.
Citation Metadata Status: [NEEDS CITATION VERIFICATION]
Missing Evidence: [NEEDS ARTIFACT] external Zenodo dataset/API-dependent collection not verified; [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]; [EXECUTION NOT REQUESTED]
""",
        "01_abstract.txt": """Problem: third-party library reuse accelerates development but can introduce 1-day vulnerabilities when vulnerable TPL versions remain in use.
Gap: exact reuse and simple custom reuse detection do not fully address flexible TPL reuse, custom fixes, and complicated code dependencies.
Core Idea: VULTURE builds a platform-targeted TPL database, identifies reused TPLs/versions, and combines version-based comparison with chunk-based patch analysis.
Method: TPLFILTER uses LLM-assisted patch/commit processing and hashing-based component representation; VULTURE detects reuse and analyzes exact/custom reuse through version and chunk evidence.
Evaluation Setup: paper reports 10 real-world projects; local source includes benchmarks/data-like artifacts, but full external dataset and execution are unverified. [NEEDS ARTIFACT]
Main Results: abstract reports 175 vulnerabilities from 178 reused TPLs; exact citation requires table verification. [NEEDS TABLE REPAIR]
Reusable Writing Pattern: security risk from reuse -> insufficiency of exact matching -> platform-specific database -> dual exact/custom analysis.
Relevance to Our Paper: high for affected versions and patch-aware vulnerability-state analysis.
Do Not Borrow: do not use reported counts or benchmark claims without repaired tables and citation verification.
""",
        "02_introduction.txt": """Opening Context: software complexity increases reliance on OSS/TPL reuse.
Why the Problem Matters: reused TPLs can carry known 1-day vulnerabilities into downstream software.
Concrete Pain Point: exact TPL reuse is only a subset; custom reuse and custom fixes complicate both reuse and vulnerability detection.
Prior Work Framing: existing similarity-based or custom-reuse tools are framed as handling only exact or simple custom reuse.
Technical Challenges: platform-specific TPL selection, dependency tracking, version identification, custom patch recognition, and semantic chunk comparison.
Key Insight: combine platform-specific TPL database construction with version-based and chunk-based vulnerability analysis.
System / Method Preview: TPLFILTER construction, TPL reuse identification, version-based analysis, and chunk-based analysis.
Contribution List: [NEEDS LAYOUT BLOCK EXTRACTION] exact bullet contribution wording should be verified.
Claim-Evidence Structure: problem examples and prior-work gaps lead into architecture and experiment sections.
Reusable Moves: explicitly split exact reuse from custom reuse, then map each reuse mode to a different analysis path.
Risks for Our Paper: preserve distinction between TPL vulnerability detection and affected versions inference.
""",
        "03_background_motivation.txt": """Domain Concepts Introduced: third-party library reuse, 1-day vulnerability, CVE, commit analysis, exact reuse, custom reuse, TPL database, vulnerable/patched functions.
Task Definition: detect 1-day vulnerabilities introduced by reused TPLs in target software.
Threat Model / Assumptions: focuses on known vulnerable TPLs and target software that reuses them exactly or with modifications.
Motivating Case: paper text uses TPL reuse and patch analysis to motivate why version-only or exact similarity is insufficient. [NEEDS EVIDENCE] for exact examples.
Definitions Needed by Readers: TPL, CVE, patch commit, component segment, vulnerability segment, version-based analysis, chunk-based analysis.
How Background Leads to Method: background establishes that reuse identification and vulnerability-state checking must be combined.
Writing Pattern: define ecosystem objects before method stages.
Relevance to Our Paper: supports framing of version-aware and patch-aware affectedness analysis.
Agent Evidence Anchors: raw_extraction/section_text/03_background.txt; raw_extraction/source_static_inventory.txt.
""",
        "04_problem_definition.txt": """Input: target software, platform-specific TPL candidates, TPL version/function database, CVE/patch metadata, vulnerable and patched code evidence.
Output: vulnerable CVEs and patched CVEs affecting the target software, with exact/modified and version-detection categories.
Objects / Entities: TPL, target project, version, function hash, component segment, vulnerability segment, patch commit, chunk, CVE.
Formal Definitions: exact formulas and thresholds need layout/formula repair. [NEEDS EVIDENCE]
Objective: identify 1-day vulnerabilities in exact and custom TPL reuse efficiently.
Constraints: requires collected TPL database, patch collection, libclang/ctags/TLSH-style hashing, API-backed patch collection, and prepared artifacts.
Evaluation Target: database quality, benchmark vulnerability detection, wild TPL reuse/vulnerability detection, and time cost.
Boundary Conditions: local code and artifacts were not executed. [EXECUTION NOT REQUESTED]
What Is Not Solved: exact reproducibility against the reported dataset is not established from static inspection. [NEEDS ARTIFACT]
Reusable Formalization Pattern: split reuse identification from vulnerability-state verification.
""",
        "05_method.txt": """System Overview: VULTURE consists of TPLFILTER database construction, TPL reuse identification, version-based analysis, and chunk-based analysis.
Pipeline Stages: TPL selection; component segment construction; vulnerability segment construction; candidate library detection; identification optimization; version-based analysis; chunk-based analysis.
Core Algorithm: source layout suggests hashing/TLSH for reuse/version detection, libclang-based chunk extraction, path/diff analysis, LLM-assisted patch collection, and false-positive elimination.
Data Structures: componentDB, funcDate, initialSigs, metaInfos, verIDX, CommitBenckmark, VulnerabilityBenckmark.xlsx, iotList.txt, patchcollector outputs, TPLReuseDetector result files.
Model / Agent Components: LLM/OpenAI/LangChain components appear in patchcollector for CVE/commit analysis by static import and README.
Design Choices: platform-specific filtering reduces irrelevant TPLs; version-based analysis handles exact reuse; chunk-based analysis handles custom reuse and patch state.
Why Each Choice Is Needed: exact matching alone misses custom reuse; chunk evidence preserves fine-grained semantic patch information.
Failure Handling: source has subprocess/API/parser dependencies; runtime failures were not exercised. [EXECUTION NOT REQUESTED]
Complexity / Cost Discussion: paper has time-cost evaluation; exact numbers require table repair. [NEEDS TABLE REPAIR]
Pseudocode or Algorithm Blocks: [NEEDS ALGORITHM REPAIR]
Static Reproducibility Signals: README, requirements, setup script, source modules, benchmark files, and local database-like artifacts are visible.
Agent Evidence Anchors: raw_extraction/section_text/05_method.txt; raw_extraction/source_static_inventory.txt.
Writing Pattern: method section can be decomposed by database construction, reuse detection, and vulnerability detection.
""",
        "06_experiments.txt": """Research Questions: recovered headings cover experiment setup, database evaluation, benchmark vulnerability detection, wild reuse/vulnerability detection, and limitations.
Datasets: local artifact includes benchmarks and database-like files; README points to Zenodo. Complete dataset verification is pending. [NEEDS ARTIFACT]
Baselines: V1SCAN and MVP are mentioned in introduction text; full baseline set and table values require evaluation table repair. [NEEDS TABLE REPAIR]
Metrics: detected vulnerabilities, reused TPLs, database quality, time cost, and detection categories are visible at text level.
Experimental Protocol: paper uses 10 real-world projects and benchmark/wild evaluations; execution not performed locally. [EXECUTION NOT REQUESTED]
Implementation Details: source uses Python, TLSH, libclang, OpenAI/LangChain, requests, scikit-learn/numpy, shell setup, ctags/clang-format dependencies.
Hyperparameters / Settings: [NEEDS EVIDENCE] from repaired method/evaluation text.
Hardware / Environment: [NEEDS EVIDENCE]
Static Reproducibility Materials: partial local artifacts plus source; external dataset/API paths remain unverified.
Execution Status: [EXECUTION NOT REQUESTED]
What Is Measured: database construction quality, vulnerability detection, reuse detection, and time cost.
What Is Not Measured: local reproduction or regenerated results.
Agent Evidence Anchors: raw_extraction/section_text/06_experiment.txt; raw_extraction/source_static_inventory.txt; raw_extraction/tables/.
""",
        "07_evaluation.txt": """Main Results: abstract reports 175 vulnerabilities from 178 reused TPLs; exact use requires table repair. [NEEDS TABLE REPAIR]
Per-RQ Findings: database evaluation, benchmark vulnerability detection, wild reuse/vulnerability detection, and time cost are present by headings.
Ablation: efficacy of platform database and chunk/version analysis may be inferable, but exact ablation claims need evidence. [NEEDS EVIDENCE]
Sensitivity Analysis: [NEEDS EVIDENCE]
Case Study: wild projects and examples appear in experiment text; exact cases require section verification. [NEEDS EVIDENCE]
Efficiency: time cost subsection exists; exact values require table repair. [NEEDS TABLE REPAIR]
Error Analysis: limitations subsection exists; details need direct extraction verification. [NEEDS EVIDENCE]
How Claims Are Supported: paper uses database evaluation, benchmark detection, wild detection, and time-cost evaluation.
Unsupported or Weakly Supported Claims: exact numeric values, baseline superiority, and per-project results until table/figure repair.
Agent Evidence Anchors: raw_extraction/section_text/06_experiment.txt; raw_extraction/tables/table_index.txt; raw_extraction/figures/figure_index.txt.
Writing Pattern: pair benchmark evaluation with in-the-wild evaluation and time cost.
""",
        "08_limitations_ethics.txt": """Stated Limitations: experiment section includes E. Limitation; exact limitation text should be read in section_text/06_experiment.txt. [NEEDS EVIDENCE]
Threats to Validity: [NEEDS EVIDENCE]
Ethical Considerations: patch collection and vulnerability detection are dual-use; paper-specific ethics statements are not isolated. [NEEDS EVIDENCE]
Security / Misuse Discussion: [NEEDS EVIDENCE]
Responsible Disclosure: [NEEDS EVIDENCE]
Scope Boundaries: static source/artifact analysis only; API paths and detectors were not run. [EXECUTION NOT REQUESTED]
Writing Pattern: limitations should separate dataset coverage, API/LLM dependence, and custom patch recognition limits.
Relevance to Our Paper: useful for making affectedness claims conditional on available patch/version evidence.
""",
        "09_figures_tables.txt": """Figure / Table Inventory: see raw_extraction/tables/table_index.txt and raw_extraction/figures/figure_index.txt.
For each figure/table:
  ID: generated table_### or figure_### evidence units after build_agent_index.py
  Agent Evidence Unit ID: generated from caption/context files
  Purpose: [NEEDS EVIDENCE] per item until captions are manually reviewed
  Evidence Shown: caption/context-only
  Placement in Argument: inferred from nearby context; [NEEDS LAYOUT BLOCK EXTRACTION]
  Extraction Confidence: partial
  Repair Needed: yes
  Citation Readiness: low; [NEEDS TABLE REPAIR]
  Figure Readiness: low; [NEEDS FIGURE EXTRACTION]
  Could Inspire Our Paper? yes, structurally, after repair.
Required Figures for Our Paper: TPL database construction pipeline, reuse-to-vulnerability detection flow, version/chunk split, and benchmark result tables.
""",
        "10_writing_patterns.txt": """Best Structural Moves: split problem into exact/custom TPL reuse; build platform-specific database; combine version and chunk analysis; validate with benchmark and wild projects.
Best Transition Moves: TPL reuse risk -> exact/custom reuse gap -> TPLFILTER database -> version-based and chunk-based vulnerability detection.
Best Contribution Wording Pattern: tool detects 1-day vulnerabilities from vulnerable TPL reuse through code patch analysis.
Best Method Overview Pattern: database construction first, reuse identification second, vulnerability-state analysis third.
Best Experiment Framing Pattern: database evaluation, benchmark detection, wild detection, time cost, limitations.
Useful Phrases to Paraphrase Structurally: platform-targeted TPL database; version-based comparison; chunk-based analysis; code patch analysis.
Patterns to Avoid: claiming complete reproduction; using abstract counts without table repair; treating TPL reuse detection as identical to affected versions.
""",
        "11_relevance_to_our_paper.txt": """Direct Relevance: high for affected versions, 1-day vulnerability detection, TPL reuse, patch-aware vulnerability-state analysis, and baseline comparison.
Indirect Relevance: useful as a design reference for combining version evidence and code-level patch evidence.
Useful for Which Section: related work, motivation, method contrast, evaluation design, limitations.
Comparable Task Elements: target software, reused component/library, vulnerable version, patch evidence, exact vs modified code state.
Comparable Method Elements: database construction, hashing, version detection, chunk/path analysis, LLM-assisted patch collection.
Comparable Evaluation Elements: benchmark detection, in-the-wild projects, time cost, database quality.
What We Can Borrow Structurally: exact/custom split and version/chunk dual analysis.
What We Cannot Borrow: VULTURE's counts, dataset, and artifact behavior as facts about our system.
Evidence Needed Before Use: repaired result tables, citation metadata, and artifact verification.
Priority: high
""",
        "12_artifact_consistency.txt": """Paper Claims: VULTURE detects 1-day vulnerabilities in TPL reuse using TPLFILTER, reuse identification, version-based analysis, and chunk-based analysis.
Artifact Evidence: README names the same modules; local source tree contains TPLselection, TPLReuseDetector, and OneDayDetector.
Source Evidence: static AST inventory finds patch collection, preprocessing, TLSH/hash detection, version-based detection, chunk extraction, and false-positive elimination code.
Consistency: supported at static-layout level; runtime behavior and reported results unverified. [EXECUTION NOT REQUESTED]
Analysis Mode: static-only
Notes: local artifacts exist, but external Zenodo dataset/API-dependent collection and environment setup were not verified. [NEEDS ARTIFACT]
Use in Our Paper: yes, as reference/baseline analysis with caution.

Claim: LLM-assisted patch collection exists.
Artifact Evidence: TPLselection/src/patchcollector/README.md and utils.py mention OpenAI/LangChain parsing.
Consistency: supported at static-source level; not executed.

Claim: VULTURE results are reproduced by local package.
Artifact Evidence: result-like files and benchmark artifacts exist, but no execution was requested.
Consistency: unclear/unsupported for reproduction. [EXECUTION NOT REQUESTED]
""",
        "13_completeness_audit.txt": f"""Raw Extraction:
- PDF text extracted: yes
- Page text extracted: yes, page count {page_count}
- Section text extracted: yes, section file count {section_count}
- Agent index exists: pending rebuild by build_agent_index.py
- Extraction profile exists: yes
- Layout blocks extracted: missing/not attempted
- References extracted: yes/uncertain, text layer only
- Table extraction: caption-only/raw context; [NEEDS TABLE REPAIR]
- Figure extraction: caption-only/context; [NEEDS FIGURE EXTRACTION]
- Formula/algorithm/prompt extraction: partial/not repaired; [NEEDS EVIDENCE]
- OCR needed: no

Section Analysis:
- 00_meta.txt through 12_artifact_consistency.txt: complete
- Are analysis files section-oriented enough for writing? yes

Source / Artifact Static Analysis:
- Source inventory exists: yes
- README/config inspected: yes
- Main entrypoints inspected: yes
- Runtime behavior: [EXECUTION NOT REQUESTED]

Writing Readiness:
- Abstract support: strong
- Introduction support: strong
- Background/motivation support: strong
- Method support: strong
- Experiment/evaluation support: partial
- Limitations support: partial
- Related work support: partial

Known Gaps:
- [NEEDS TABLE REPAIR]
- [NEEDS FIGURE EXTRACTION]
- [NEEDS LAYOUT BLOCK EXTRACTION]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade: medium-high - the text and static artifact tree are strong for method and related-work framing, but exact evaluation claims remain gated by table/figure repair and artifact verification.
""",
        "14_section_retrieval_map.txt": """For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/02_introduction.txt
- Must not claim exact counts without table repair.

For Background / Motivation:
- Read analysis/03_background_motivation.txt
- Read raw_extraction/section_text/03_background.txt

For Method:
- Read analysis/05_method.txt
- Read raw_extraction/section_text/05_method.txt
- Read raw_extraction/source_static_inventory.txt

For Experiments / Evaluation:
- Read analysis/06_experiments.txt and 07_evaluation.txt
- Read raw_extraction/section_text/06_experiment.txt
- Read raw_extraction/tables/
- Must not claim exact results until [NEEDS TABLE REPAIR] is resolved.

For Limitations:
- Read analysis/08_limitations_ethics.txt and raw_extraction/section_text/06_experiment.txt

For Related Work:
- Read raw_extraction/references.txt and analysis/11_relevance_to_our_paper.txt
- Must not claim verified bibliography until [NEEDS CITATION VERIFICATION] is resolved.
""",
    }
    for filename, text in files.items():
        write(ANALYSIS / filename, text)


def main() -> None:
    pages, empty_pages = extract_pdf()
    full = (RAW / "full_text.txt").read_text(encoding="utf-8", errors="replace")
    section_count = split_sections(full)
    table_count, figure_count = extract_captions(full)
    py_count, file_count, artifact_count = source_inventory()
    write_raw_metadata(pages, empty_pages)
    write_analysis(len(pages), section_count)
    print(json.dumps({
        "paper_id": PAPER_ID,
        "pages": len(pages),
        "sections": section_count,
        "tables_caption_context": table_count,
        "figures_caption_context": figure_count,
        "python_files_static": py_count,
        "source_files_total": file_count,
        "artifact_like_files": artifact_count,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
