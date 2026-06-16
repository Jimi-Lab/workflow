from __future__ import annotations

import ast
import json
import re
from datetime import date
from pathlib import Path

from pypdf import PdfReader


PAPER_ID = "p05_movery_precise_modified_vulnerable_code_clone_discovery_2022"
ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference") / PAPER_ID
RAW = ROOT / "raw_extraction"
ANALYSIS = ROOT / "analysis"
PDF_COPY = RAW / "source_pdf.pdf"
ORIGINAL_PDF = (
    r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)"
    r"\Direct_Comparison_Papers(Baseline_Paper+Code)\MOVERY"
    r"\Movery：A Precise Approach for Modified Vulnerable Code Clone Discovery from Modified Open-Source Software Compo.pdf"
)
ORIGINAL_PDF_SHORT = r"E:\AI\Agent\workflow\Replication\BASELI~1\DIRECT~1\MOVERY\MOVERY~1.PDF"
SOURCE = Path(
    r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)"
    r"\Direct_Comparison_Papers(Baseline_Paper+Code)\MOVERY\MOVERY"
)
TITLE = "Movery: A Precise Approach for Modified Vulnerable Code Clone Discovery from Modified Open-Source Software Components"
AUTHORS = ["Seunghoon Woo", "Hyunji Hong", "Eunjin Choi", "Heejo Lee"]
VENUE = "31st USENIX Security Symposium (USENIX Security 2022)"
YEAR = "2022"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def extract_pdf() -> tuple[list[str], list[int]]:
    for sub in ["page_text", "section_text", "tables", "figures", "formulas", "algorithms", "prompts", "layout_blocks"]:
        (RAW / sub).mkdir(parents=True, exist_ok=True)
    reader = PdfReader(str(PDF_COPY))
    pages: list[str] = []
    empty: list[int] = []
    for i, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        pages.append(text)
        if not text.strip():
            empty.append(i)
        write(RAW / "page_text" / f"page_{i:03d}.txt", text)
    full = "\n\n".join(f"===== PAGE {i:03d} =====\n{text}" for i, text in enumerate(pages, start=1))
    write(RAW / "full_text.txt", full)
    return pages, empty


def split_sections(full: str) -> int:
    heading_re = re.compile(r"(?m)^(Abstract|\d+(?:\.\d+)*\s+[A-Za-z][A-Za-z /()\-:,]{2,100}|References)$")
    headings: list[tuple[str, int]] = []
    for m in heading_re.finditer(full):
        heading = re.sub(r"\s+", " ", m.group(1).strip())
        if heading not in [h for h, _ in headings]:
            headings.append((heading, m.start()))

    wanted = [
        ("01_abstract.txt", "Abstract"),
        ("02_introduction.txt", "1 Introduction"),
        ("03_motivation.txt", "2 Motivation"),
        ("04_methodology.txt", "3 Methodology of M OVERY"),
        ("05_implementation.txt", "4 Implementation of M OVERY"),
        ("06_evaluation.txt", "5 Evaluation"),
        ("07_discussion.txt", "6 Discussion"),
        ("08_related_work.txt", "7 Related Work"),
        ("09_conclusion.txt", "8 Conclusion"),
        ("10_references.txt", "References"),
    ]
    positions = []
    for filename, heading in wanted:
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
    lines += ["", "Notes: conservative split from PDF text layer; code examples and multi-column ordering may be imperfect. [NEEDS LAYOUT BLOCK EXTRACTION]"]
    write(RAW / "sections.txt", "\n".join(lines) + "\n")
    return len(positions)


def extract_captions(full: str) -> tuple[int, int]:
    counts: dict[str, int] = {}
    for kind in ["table", "figure"]:
        pattern = re.compile(rf"(?im)^{kind.capitalize()}\s+\d+[:.][^\n]*(?:\n(?!\d+\s|Figure\s|Table\s|References).{{0,180}}){{0,2}}")
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


def source_inventory() -> tuple[int, int]:
    py_files = [p for p in sorted(SOURCE.rglob("*.py")) if "__pycache__" not in p.parts]
    all_files = [p for p in sorted(SOURCE.rglob("*")) if p.is_file()]
    dirs = [p for p in sorted(SOURCE.iterdir()) if p.is_dir()]
    lines = [
        f"Source Path: {SOURCE}",
        "Analysis Mode: static-only",
        "Runtime behavior: [EXECUTION NOT REQUESTED]",
        "Artifact Type: Type B (paper + source code only; required dataset/config binaries are not present locally).",
        "",
        "Repository / File Layout Observed:",
    ]
    for directory in dirs:
        lines.append(f"- {directory.name}/")
    lines += [
        f"- Python source files inspected statically: {len(py_files)}",
        f"- Total files observed: {len(all_files)}",
        "- README: missing. [NEEDS ARTIFACT]",
        "",
        "Primary Files:",
    ]
    for rel in ["Detector.py", "Preprocessing.py", "movery_auto.py", "config/movery_config.py"]:
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
        imports, funcs, assigns = [], [], []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                try:
                    imports.append(ast.unparse(node))
                except Exception:
                    imports.append(type(node).__name__)
            if isinstance(node, ast.FunctionDef):
                funcs.append(node.name)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigns.append(target.id)
        lines += [
            f"- {path.relative_to(SOURCE)}",
            f"  imports: {'; '.join(imports[:10]) if imports else 'none'}",
            f"  functions: {', '.join(funcs[:30]) if funcs else 'none'}",
            f"  top_level_assignments: {', '.join(assigns[:30]) if assigns else 'none'}",
        ]
    lines += [
        "",
        "Key Static Evidence:",
        "- Detector.py defines normalization/comment-removal helpers, dataset readers, search-space reduction, and detector(tar).",
        "- Detector.py hardcodes dataset paths under dataset/vulESSLines, vulDEPLines, noOldESSLines, patESSLines, vulBodySet, vulHashes, tarFuncs, oss_idx.txt, and idx2cve.txt.",
        "- Detector.py uses theta = 0.5 and a spaceReduction step that intersects target function hashes with vulnerability hashes and OSS index metadata.",
        "- Preprocessing.py extracts C/C++ functions from a target path using ctags, normalizes/abstracts functions, hashes raw bodies, and writes target function/hash artifacts under dataset/tarFuncs.",
        "- Preprocessing.py hardcodes pathToCtags = /home/cxy/MOVERY/config/ctags, which is not present in the local tree. [NEEDS ARTIFACT]",
        "- movery_auto.py is a wrapper around Preprocessing.py and Detector.py over vuln_repo_input and MOVERY_output; it was not executed. [EXECUTION NOT REQUESTED]",
        "- config/movery_config.py points to D:/NEWRESEARCH/vulFuncs and D:/NEWRESEARCH/oldestFuncs; these paths are external to the provided target tree. [NEEDS ARTIFACT]",
        "",
        "Static Consistency Notes:",
        "- Paper claims about vulnerable/patch signatures and OSS-reuse-based search-space reduction are partially reflected by Detector.py and Preprocessing.py names, paths, and functions.",
        "- Dataset construction, vulnerability metadata, target software corpus, and evaluation artifacts are absent locally, so evaluation claims cannot be checked from this artifact alone. [NEEDS ARTIFACT]",
        "- Runtime behavior, parser behavior, generated outputs, precision/recall, and scalability were not checked. [EXECUTION NOT REQUESTED]",
        "",
        "Observed Local Output / Data Artifacts:",
        "- No local dataset/ directory was observed under the MOVERY source path.",
        "- No README, requirements file, environment file, or bundled ctags binary was observed.",
        "",
        "Missing Data / Missing Entrypoints:",
        "- dataset/* directories required by Detector.py and Preprocessing.py. [NEEDS ARTIFACT]",
        "- config/ctags binary expected by Preprocessing.py. [NEEDS ARTIFACT]",
        "- vuln_repo_input and MOVERY_output paths used by movery_auto.py. [NEEDS ARTIFACT]",
        "- Published vulnerability dataset and target software artifacts for reproducing reported evaluation. [NEEDS ARTIFACT]",
    ]
    write(RAW / "source_static_inventory.txt", "\n".join(lines) + "\n")
    return len(py_files), len(all_files)


def write_raw_metadata(pages: list[str], empty_pages: list[int]) -> None:
    full = (RAW / "full_text.txt").read_text(encoding="utf-8", errors="replace")
    ref_match = re.search(r"(?ms)^References\s*(.*)$", full)
    refs = ref_match.group(1).strip() if ref_match else "[NEEDS CITATION VERIFICATION] References section not isolated."
    write(RAW / "references.txt", refs + "\n\n[NEEDS CITATION VERIFICATION] Metadata not verified against official bibliography.\n")
    write(RAW / "appendix.txt", "No separate appendix was reliably isolated from the text layer. [NEEDS EVIDENCE]\n")
    metadata = {
        "paper_id": PAPER_ID,
        "title": TITLE,
        "authors": AUTHORS,
        "venue": VENUE,
        "year": YEAR,
        "doi": "",
        "arxiv": "",
        "pdf_path": ORIGINAL_PDF,
        "local_pdf_copy": "raw_extraction/source_pdf.pdf",
        "artifact_type": "Type B",
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
Artifact/Data Path or URL: [NEEDS ARTIFACT] local MOVERY tree lacks dataset/, ctags, target corpus, README, and reproduction instructions.
Extraction Date: {date.today().isoformat()}
Extraction Tools: pypdf text extraction; Python ast/static file inspection
Artifact Type: Type B
Notes: Source code inspected statically only. No target code, scripts, dependency install, ctags invocation, or experiments were executed. [EXECUTION NOT REQUESTED]
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
Known Losses: multi-column ordering and code-example layout may be imperfect; table cells and figure images are not citation-ready.
PDF Text Complete: yes
PDF Layout Partial: yes
Citation-Ready Tables: no
Figure-Ready: no
Agent Index: pending rebuild by build_agent_index.py
Next Repair Step: run build_agent_index.py; repair tables/figures from PDF if exact numeric or visual claims are needed.
""")
    write(RAW / "extraction_profile.txt", """Primary Consumer: agent
PDF Text Layer: complete
Layout Block Layer: missing/not attempted
Table Layer: caption-only
Figure Layer: caption-only
Formula Layer: not detected/not attempted
Algorithm Layer: not detected/not attempted
Prompt Layer: not detected/not attempted
Known Ordering Losses: multi-column reading order and code examples may be wrong because layout blocks were not extracted.
Known Layout Losses: table cells, figure crops, formulas, and algorithms are not repaired.
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
Artifact Type: Type B
Input Files: original PDF; local MOVERY source tree; config/script files inspected statically
Source / Artifact Path: {SOURCE}
Analysis Status: section-level analysis complete with extraction caveats
Agent Index Status: pending post-generation rebuild at time of writing this file
Main Topic: vulnerable code clone discovery from modified OSS components
Why This Paper Is Relevant: MOVERY is a direct recurring-vulnerability/VCC baseline that handles internal and external OSS modifications with vulnerability and patch signatures plus search-space reduction.
Citation Metadata Status: [NEEDS CITATION VERIFICATION]
Missing Evidence: [NEEDS ARTIFACT] dataset/ctags/target corpora absent; [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]; [EXECUTION NOT REQUESTED]
""",
        "01_abstract.txt": """Problem: third-party OSS reuse can propagate vulnerable code, and modified OSS components make clone discovery harder.
Gap: existing techniques are framed as weak under internal OSS updates and external reuse-time code changes.
Core Idea: MOVERY generates vulnerability and patch signatures from the oldest vulnerable function and core changed lines, then checks target functions against vulnerability evidence while distinguishing patch evidence.
Method: search-space reduction over borrowed OSS code, vulnerability/patch signature generation, and VCC decision logic.
Evaluation Setup: ten popular software systems are reported in the paper; local reproduction artifacts are missing. [NEEDS ARTIFACT]
Main Results: abstract reports 415 VCCs with 96% precision and 96% recall; citation-ready use requires table repair and metadata verification. [NEEDS TABLE REPAIR]
Contribution Wording: problem is framed around modified OSS syntax diversity, then method is presented as signature design plus scalability filter.
Limitations or Scope Boundaries: source runtime and reported metrics were not checked. [EXECUTION NOT REQUESTED]
Reusable Writing Pattern: introduce two modification sources, show why prior matching fails, then define a signature construction that covers both.
Relevance to Our Paper: useful for related work and evaluation framing around baseline limits under code evolution/modification.
Do Not Borrow: do not transfer MOVERY's VCC metrics or dataset claims to our affected versions work without direct citation and verification.
""",
        "02_introduction.txt": """Opening Context: OSS reuse increases security dependence on third-party components.
Why the Problem Matters: vulnerabilities inherited from OSS can compromise downstream software even when components are modified.
Concrete Pain Point: updated or reused OSS changes vulnerable code syntax, making exact or shallow clone detection unreliable.
Motivating Example: paper includes code-level examples of internal and external modification; extraction is text-only and figure/code layout needs repair. [NEEDS LAYOUT BLOCK EXTRACTION]
Prior Work Framing: VCC discovery and SCA are introduced as relevant but insufficient under modified OSS.
Why Prior Work Is Insufficient: prior tools are framed as missing oldest-vulnerable variants, patch distinction, or modified syntax coverage.
Technical Challenges: syntax diversity, version evolution, reused-code modification, search-space scale, and patch/vulnerability distinction.
Key Insight: use oldest vulnerable function plus core vulnerable/patch lines to create signatures robust to modification.
System / Method Preview: MOVERY has signature generation and vulnerable code clone discovery phases.
Contribution List: exact contribution wording should be verified against PDF layout. [NEEDS LAYOUT BLOCK EXTRACTION]
Claim-Evidence Structure: introduction motivates with modification taxonomy and then supports with method/evaluation sections.
Paragraph Map:
P1: Function: OSS reuse security context; Main Claim: inherited vulnerabilities threaten software; Evidence Type: citations.
P2+: Function: modified OSS challenge; Main Claim: internal/external changes impair existing VCC discovery; Evidence Type: examples and prior-work contrast.
Reusable Moves: define concrete failure modes before presenting a method-specific signature.
Risks for Our Paper: keep MOVERY as VCC/reuse baseline, not an affected versions solver.
""",
        "03_background_motivation.txt": """Domain Concepts Introduced: OSS reuse, vulnerable code clone, internal modification, external modification, vulnerable function, patch function, oldest vulnerable function.
Task Definition: discover VCCs in modified OSS components by comparing target functions with vulnerability and patch signatures.
Threat Model / Assumptions: paper focuses on code-level propagation through OSS reuse; exact threat model details need section-level verification. [NEEDS EVIDENCE]
Motivating Case: examples show code syntax can differ between disclosed vulnerable function and propagated vulnerable code.
Definitions Needed by Readers: VCC, internal/external OSS modification, vulnerability signature, patch signature, search-space reduction.
How Background Leads to Method: modification taxonomy motivates oldest-vulnerable evidence and patch-aware decision logic.
Writing Pattern: name two concrete sources of distribution shift, then use examples to show each one.
Relevance to Our Paper: useful for explaining why version/reuse analysis needs evolution-aware evidence rather than exact matching.
Agent Evidence Anchors: raw_extraction/section_text/03_motivation.txt; raw_extraction/source_static_inventory.txt.
""",
        "04_problem_definition.txt": """Input: vulnerable and patched OSS functions/signatures plus target software functions extracted from reused OSS components.
Output: functions classified as vulnerable code clones.
Objects / Entities: target function, vulnerable function, oldest vulnerable function, patch function, essential lines, dependent lines, hashes, OSS index, CVE/version mapping.
Formal Definitions: exact formal notation is [NEEDS EVIDENCE] unless layout/formula extraction is repaired.
Objective: identify modified VCCs precisely while reducing target search space.
Constraints: requires prepared datasets, ctags-based preprocessing, OSS index metadata, vulnerability body/signature files, and target function hashes.
Evaluation Target: accuracy, comparison with MVP/Centris, speed/scalability, search-space reduction, and case study according to recovered headings.
Boundary Conditions: local execution and reproduction are not checked. [EXECUTION NOT REQUESTED]
What Is Not Solved: local artifact does not include dataset/ctags/target corpus, so evaluation cannot be reproduced from this tree. [NEEDS ARTIFACT]
Reusable Formalization Pattern: separate candidate search-space reduction from final vulnerability/patch signature decision.
""",
        "05_method.txt": """System Overview: MOVERY has signature generation and vulnerable code clone discovery phases.
Pipeline Stages: paper headings recover P1 signature generation and P2 vulnerable code clone discovery; source exposes Preprocessing.py and Detector.py.
Core Algorithm: static code suggests preprocessing extracts/abstracts C/C++ functions and hashes them, while detector reads vulnerability/patch signature datasets, reduces target search space by OSS/hash indices, and applies signature matching.
Data Structures: dataset/vulESSLines, vulDEPLines, noOldESSLines, patESSLines, patDEPLines, vulBodySet, vulHashes, tarFuncs, oss_idx.txt, idx2cve.txt.
Model / Agent Components: no model/agent component detected in local source.
Design Choices: vulnerability signature plus patch signature is used to avoid confusing vulnerable and patched variants; search-space reduction focuses on borrowed OSS code.
Why Each Choice Is Needed: modification-aware signatures address syntax diversity; search-space reduction addresses scale.
Failure Handling: source has parser-error handling and missing-file exits, but runtime behavior is unverified. [EXECUTION NOT REQUESTED]
Complexity / Cost Discussion: speed/scalability is evaluated in paper; exact numbers require table repair. [NEEDS TABLE REPAIR]
Pseudocode or Algorithm Blocks: no reliable algorithm block extracted. [NEEDS EVIDENCE]
Static Reproducibility Signals: Python scripts and config file exist; README, dataset, ctags, and target corpus are missing. [NEEDS ARTIFACT]
Agent Evidence Anchors: raw_extraction/section_text/04_methodology.txt; raw_extraction/section_text/05_implementation.txt; raw_extraction/source_static_inventory.txt.
Writing Pattern: split method into signature generation and detection, then tie each phase to one challenge.
""",
        "06_experiments.txt": """Research Questions: paper evaluation headings cover accuracy, comparisons with MVP and Centris, speed/scalability, search-space reduction efficacy, and a Git case study.
Datasets: abstract and evaluation mention ten popular software; local dataset artifacts are absent. [NEEDS ARTIFACT]
Baselines: MVP and Centris are explicit section headings; additional baselines require repaired table/text verification. [NEEDS TABLE REPAIR]
Metrics: precision, recall, VCC count, speed/scalability, and search-space reduction are visible at paper-text level.
Experimental Protocol: reported protocol cannot be reproduced locally without dataset and target corpus. [NEEDS ARTIFACT]
Implementation Details: source has Detector.py, Preprocessing.py, movery_auto.py, and config/movery_config.py; no environment file or README present.
Hyperparameters / Settings: Detector.py uses theta = 0.5 by static inspection; whether this exactly matches paper experiments needs verification. [NEEDS EVIDENCE]
Hardware / Environment: [NEEDS EVIDENCE]
Static Reproducibility Materials: partial source only.
Execution Status: [EXECUTION NOT REQUESTED]
What Is Measured: accuracy, baseline comparison, scalability, search-space reduction, and case-study effectiveness.
What Is Not Measured: local run success or reproduced results.
Agent Evidence Anchors: raw_extraction/section_text/06_evaluation.txt; raw_extraction/source_static_inventory.txt; raw_extraction/tables/.
""",
        "07_evaluation.txt": """Main Results: abstract reports 415 VCCs with 96% precision and 96% recall; exact use requires table repair. [NEEDS TABLE REPAIR]
Per-RQ Findings: recovered headings include accuracy, MVP comparison, Centris comparison, speed/scalability, search-space reduction, and Git case study.
Ablation: search-space reduction efficacy is a component-style evaluation.
Sensitivity Analysis: [NEEDS EVIDENCE]
Case Study: Git case study is present by heading; detailed claims need section verification. [NEEDS EVIDENCE]
Efficiency: speed/scalability section exists; exact values need table repair. [NEEDS TABLE REPAIR]
Error Analysis: [NEEDS EVIDENCE]
Statistical / Validity Notes: [NEEDS EVIDENCE]
How Claims Are Supported: paper appears to use RQ-style subsections, comparative baselines, tables/figures, and case study.
Unsupported or Weakly Supported Claims: exact numeric results, baseline rankings, and per-system claims until tables/figures/citations are repaired.
Agent Evidence Anchors: raw_extraction/section_text/06_evaluation.txt; raw_extraction/tables/table_index.txt; raw_extraction/figures/figure_index.txt.
Writing Pattern: combine accuracy comparison with scalability and reduction ablation to support both precision and practicality.
""",
        "08_limitations_ethics.txt": """Stated Limitations: discussion section should be used for exact limitations; no dedicated limitations/ethics section was isolated. [NEEDS EVIDENCE]
Threats to Validity: [NEEDS EVIDENCE]
Ethical Considerations: [NEEDS EVIDENCE]
Security / Misuse Discussion: VCC discovery is dual-use, but this analysis does not infer claims absent from text. [NEEDS EVIDENCE]
Responsible Disclosure: [NEEDS EVIDENCE]
Scope Boundaries: static source analysis only; MOVERY code was not run. [EXECUTION NOT REQUESTED]
Writing Pattern: use discussion to bound dataset coverage and artifact availability; avoid overclaiming reproducibility.
Relevance to Our Paper: highlights the need to separate detection claim, dataset claim, and artifact claim.
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
Required Figures for Our Paper: modification taxonomy, signature-generation flow, search-space reduction, and baseline comparison tables.
""",
        "10_writing_patterns.txt": """Best Structural Moves: define two modification classes; use code examples; separate signature generation from detection; evaluate accuracy and scalability separately.
Best Transition Moves: OSS reuse risk -> modified syntax challenge -> oldest-vulnerable/patch-aware signatures -> scalable search-space reduction.
Best Contribution Wording Pattern: method addresses both internal and external OSS modifications.
Best Method Overview Pattern: P1 signature generation, P2 vulnerable code clone discovery.
Best Experiment Framing Pattern: accuracy first, baseline comparisons second, speed/scalability and reduction ablation after.
Useful Phrases to Paraphrase Structurally: modified OSS components; vulnerability and patch signatures; search-space reduction.
Patterns to Avoid: claiming affected versions inference; claiming reproducibility from partial source; using exact metrics without table repair.
""",
        "11_relevance_to_our_paper.txt": """Direct Relevance: MOVERY is a baseline/reference for modified vulnerable code clone discovery and recurring vulnerability detection.
Indirect Relevance: useful for framing why code evolution/modification breaks shallow matching.
Useful for Which Section: related work, motivation, baseline discussion, evaluation framing, limitation discussion.
Comparable Task Elements: vulnerability propagation, modified code, vulnerable/patch evidence, target-code scanning.
Comparable Method Elements: signature construction, patch distinction, search-space reduction.
Comparable Evaluation Elements: precision/recall, baseline comparison, speed/scalability, component efficacy.
What We Can Borrow Structurally: modification taxonomy, signature-vs-patch framing, and multi-part evaluation structure.
What We Cannot Borrow: MOVERY's VCC task definition, datasets, and empirical numbers as claims about affected versions.
Evidence Needed Before Use: repaired tables/figures and citation metadata; careful bridge from VCC detection to affected versions.
Priority: high
""",
        "12_artifact_consistency.txt": """Paper Claims: MOVERY discovers modified vulnerable code clones using vulnerability/patch signatures and search-space reduction.
Artifact Evidence: local source has Preprocessing.py, Detector.py, movery_auto.py, and config/movery_config.py.
Source Evidence: static inspection finds preprocessing, normalization, hashing, dataset readers, spaceReduction, and detector(tar).
Consistency: partially supported by static source layout; runtime behavior and evaluation claims unverified. [EXECUTION NOT REQUESTED]
Analysis Mode: static-only
Notes: missing dataset/ctags/target corpus prevents reproduction assessment. [NEEDS ARTIFACT]
Use in Our Paper: yes, as related work/baseline analysis with caution.

Claim: source implements preprocessing and detection phases.
Artifact Evidence: Preprocessing.py and Detector.py exist.
Source Evidence: preprocessor(target), abstract(), spaceReduction(), detector(tar).
Consistency: supported at static-symbol level.

Claim: reported precision/recall can be reproduced locally.
Artifact Evidence: no dataset/ctags/target corpus.
Consistency: unsupported from local artifact. [NEEDS ARTIFACT]
Notes: [EXECUTION NOT REQUESTED]
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
- Formula/algorithm/prompt extraction: not detected/not attempted
- OCR needed: no

Section Analysis:
- 00_meta.txt through 12_artifact_consistency.txt: complete
- Are analysis files section-oriented enough for writing? yes

Source / Artifact Static Analysis:
- Source inventory exists: yes
- README/config inspected: config yes, README missing [NEEDS ARTIFACT]
- Main entrypoints inspected: yes
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
- [NEEDS LAYOUT BLOCK EXTRACTION]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade: medium - paper text and partial source are useful for related-work and method framing, but missing datasets/tools and unrepaired tables block citation-ready metrics and reproduction claims.
""",
        "14_section_retrieval_map.txt": """For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/02_introduction.txt
- Must not claim: MOVERY metrics without repaired tables

For Background / Motivation:
- Read analysis/03_background_motivation.txt
- Read raw_extraction/section_text/03_motivation.txt
- Useful claims: internal/external OSS modification framing

For Method:
- Read analysis/05_method.txt
- Read raw_extraction/section_text/04_methodology.txt and 05_implementation.txt
- Read raw_extraction/source_static_inventory.txt
- Must not claim: runtime correctness or complete implementation

For Experiments / Evaluation:
- Read analysis/06_experiments.txt and 07_evaluation.txt
- Read raw_extraction/section_text/06_evaluation.txt
- Must not claim: exact results until [NEEDS TABLE REPAIR] is resolved

For Limitations:
- Read analysis/08_limitations_ethics.txt and raw_extraction/section_text/07_discussion.txt
- Must not claim: ethics/disclosure details without direct evidence

For Related Work:
- Read raw_extraction/references.txt and analysis/11_relevance_to_our_paper.txt
- Must not claim: verified bibliography until [NEEDS CITATION VERIFICATION] is resolved
""",
    }
    for filename, text in files.items():
        write(ANALYSIS / filename, text)


def main() -> None:
    pages, empty = extract_pdf()
    full = (RAW / "full_text.txt").read_text(encoding="utf-8", errors="replace")
    section_count = split_sections(full)
    table_count, figure_count = extract_captions(full)
    py_count, file_count = source_inventory()
    write_raw_metadata(pages, empty)
    write_analysis(len(pages), section_count)
    print(json.dumps({
        "paper_id": PAPER_ID,
        "pages": len(pages),
        "sections": section_count,
        "tables_caption_context": table_count,
        "figures_caption_context": figure_count,
        "python_files_static": py_count,
        "source_files_total": file_count,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
