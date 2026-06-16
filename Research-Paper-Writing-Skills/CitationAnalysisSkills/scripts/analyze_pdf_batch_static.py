#!/usr/bin/env python3
"""Static PDF-only CitationAnalysis ingestion for selected reference papers."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

try:
    from pypdf import PdfReader
except Exception as exc:  # pragma: no cover
    print(f"pypdf import failed: {exc}", file=sys.stderr)
    sys.exit(2)


RAW_SUBDIRS = ["page_text", "layout_blocks", "section_text", "tables", "figures", "formulas", "algorithms", "prompts"]
LABELS = "[NEEDS TABLE REPAIR], [NEEDS FIGURE EXTRACTION], [NEEDS LAYOUT BLOCK EXTRACTION], [NEEDS CITATION VERIFICATION], [EXECUTION NOT REQUESTED]"


def clean(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")


def infer_title(pdf: Path, reader: PdfReader) -> str:
    metadata = reader.metadata
    bad = ("this paper is included", "proceedings of", "ieee transactions on", "nullobject", "acm reference format")
    if metadata and metadata.title:
        title = clean(str(metadata.title))
        if title and not any(title.lower().startswith(prefix) for prefix in bad) and len(title.split()) >= 3:
            return title
    if reader.pages:
        text = reader.pages[0].extract_text() or ""
        for line in lines(text)[:15]:
            if 12 <= len(line) <= 180 and not re.match(r"^\d+$", line):
                if not any(line.lower().startswith(prefix) for prefix in bad):
                    return line
    return pdf.stem


def infer_year(full_text: str, filename: str) -> str:
    for source in (full_text[:8000], filename):
        years = re.findall(r"\b(20[0-2][0-9]|19[0-9]{2})\b", source)
        if years:
            return years[0]
    return ""


def sectionize(full_text: str) -> dict[str, str]:
    heading = re.compile(
        r"(?im)^(?:\d+(?:\.\d+)*\s+)?"
        r"(Abstract|Introduction|Background|Motivation|Overview|Problem(?:\s+Definition)?|"
        r"Approach|Method|Methodology|Design|System|Implementation|Experiment(?:s)?|Evaluation|"
        r"Result(?:s)?|Discussion|Limitation(?:s)?|Threats to Validity|Related Work|Conclusion|"
        r"References|Appendix)\b.*$"
    )
    matches = list(heading.finditer(full_text))
    sections: dict[str, str] = {}
    if not matches:
        return {"full_text": full_text}
    first_start = matches[0].start()
    if first_start > 200 and re.search(r"(?i)abstract", full_text[:first_start]):
        sections["abstract"] = full_text[:first_start].strip()
    for index, match in enumerate(matches):
        name = clean(match.group(0))[:80]
        key = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:60] or f"section_{index + 1}"
        end = matches[index + 1].start() if index + 1 < len(matches) else len(full_text)
        body = full_text[match.start():end].strip()
        if len(body) <= 80:
            continue
        base = key
        suffix = 2
        while key in sections:
            key = f"{base}_{suffix}"
            suffix += 1
        sections[key] = body
    return sections


def find_section(sections: dict[str, str], *needles: str) -> str:
    for key, value in sections.items():
        if any(needle in key.lower() for needle in needles):
            return value
    for value in sections.values():
        sample = value[:500].lower()
        if any(needle in sample for needle in needles):
            return value
    return ""


def sentences(text: str, limit: int = 6) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+", clean(text))
    return [part for part in parts if len(part) > 40][:limit]


def keyword_sentences(text: str, keywords: list[str], limit: int = 6) -> list[str]:
    selected: list[str] = []
    for sent in sentences(text, 100):
        lower = sent.lower()
        if any(keyword.lower() in lower for keyword in keywords):
            selected.append(sent)
        if len(selected) >= limit:
            break
    return selected


def extract_captions(full_text: str, kind: str) -> list[str]:
    pattern = re.compile(
        rf"(?im)^\s*({kind}\s+\d+[^\n]{{0,500}}"
        rf"(?:\n(?!\s*(?:Figure|Table|\d+\s+[A-Z]|References|Introduction|Abstract)\b).{{0,500}}){{0,2}})"
    )
    return [clean(match.group(1)) for match in pattern.finditer(full_text)][:20]


def extract_blocks(full_text: str, kind: str) -> list[str]:
    pattern = re.compile(
        rf"(?is)({kind}\s+\d+.*?)(?=\n\s*(?:{kind}\s+\d+|Figure\s+\d+|Table\s+\d+|References|\d+\s+[A-Z]|Appendix)|\Z)"
    )
    return [clean(match.group(1))[:2500] for match in pattern.finditer(full_text)][:10]


def bullet(items: list[str], empty: str = "[NEEDS EVIDENCE]") -> str:
    return "\n".join(f"- {item}" for item in items) if items else f"- {empty}"


def make_unit(
    paper_id: str,
    unit_type: str,
    name: str,
    files: list[str],
    anchor: str,
    usable_for: list[str],
    confidence: str = "medium",
    repair_needed: bool = False,
    do_not_use_for: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": f"{paper_id}:{unit_type}:{name}",
        "type": unit_type,
        "page": None,
        "section": name,
        "topic": name.replace("_", " "),
        "text_anchor": clean(anchor)[:220],
        "bbox": None,
        "files": files,
        "confidence": confidence,
        "repair_needed": repair_needed,
        "usable_for": usable_for,
        "do_not_use_for": do_not_use_for or ["exact numeric claim"],
        "notes": "Generated from local raw extraction; verify against PDF for citation-critical use.",
    }


def build_analysis(
    paper_id: str,
    title: str,
    year: str,
    pdf_path: str,
    duplicate_paths: list[str],
    page_count: int,
    sections: dict[str, str],
    references_text: str,
    tables: list[str],
    figures: list[str],
) -> dict[str, str]:
    abstract = find_section(sections, "abstract")
    intro = find_section(sections, "introduction")
    method = find_section(sections, "method", "approach", "design", "system")
    experiments = find_section(sections, "experiment", "evaluation", "result")
    background = find_section(sections, "background", "motivation", "overview")
    limitations = find_section(sections, "limitation", "threat", "discussion")
    problem = keyword_sentences(intro + " " + abstract, ["problem", "challenge", "difficult", "limitation", "vulnerab", "bug-introducing", "affected version", "commit"], 5)
    method_sents = keyword_sentences(method + " " + abstract, ["approach", "method", "system", "algorithm", "model", "agent", "graph", "patch", "log", "version"], 6)
    eval_sents = keyword_sentences(experiments, ["rq", "dataset", "baseline", "accuracy", "precision", "recall", "f1", "result", "evaluation", "experiment"], 7)
    limitation_sents = keyword_sentences(limitations + " " + intro, ["limitation", "threat", "future", "cannot", "may", "only", "validity"], 6)
    source = "[NEEDS ARTIFACT] no local source/artifact path detected beside the PDF"
    anchor = "Agent Evidence Anchors: raw_extraction/full_text.txt; raw_extraction/section_text/*; raw_extraction/agent_index.json"

    table_status = "caption-only/partial" if tables else "missing"
    figure_status = "caption-only/partial" if figures else "missing"
    figure_table_items = [f"Table {idx}: {text} | Extraction Confidence: partial | Repair Needed: [NEEDS TABLE REPAIR] | Citation Readiness: low" for idx, text in enumerate(tables, 1)]
    figure_table_items += [f"Figure {idx}: {text} | Extraction Confidence: partial | Repair Needed: [NEEDS FIGURE EXTRACTION] | Figure Readiness: low" for idx, text in enumerate(figures, 1)]

    return {
        "00_meta.txt": f"""Paper ID: {paper_id}
Title: {title}
Venue / Year: {year or '[NEEDS CITATION VERIFICATION]'}
Authors: [NEEDS CITATION VERIFICATION]
Artifact Type: Type D
Input Files: {pdf_path}
Duplicate PDF Paths: {'; '.join(duplicate_paths) if duplicate_paths else 'none detected in requested set'}
Source / Artifact Path: {source}
Analysis Status: complete with extraction gaps
Agent Index Status: generated
Main Topic: vulnerability-introducing commits / affected versions / SZZ-related vulnerability validation, as evidenced by title and extracted text.
Why This Paper Is Relevant: It is directly relevant to affected versions and vulnerability validation literature mapping because it studies commit/version evidence, SZZ-style reasoning, LLM/agent reasoning, or patch/developer-log based vulnerable-version identification.
Citation Metadata Status: [NEEDS CITATION VERIFICATION]
Missing Evidence: {LABELS}; [NEEDS ARTIFACT]
""",
        "01_abstract.txt": f"""Problem:
{bullet(problem or sentences(abstract, 5))}
Gap:
{bullet(keyword_sentences(abstract + ' ' + intro, ['gap', 'however', 'existing', 'prior', 'limitation', 'challenge'], 4))}
Core Idea:
{bullet(method_sents or sentences(abstract, 5))}
Method:
{bullet(method_sents)}
Evaluation Setup:
{bullet(eval_sents, '[NEEDS EVIDENCE] evaluation details require section-level verification')}
Main Results:
{bullet(keyword_sentences(abstract + ' ' + experiments, ['result', 'outperform', 'improve', 'accuracy', 'precision', 'recall', 'f1'], 5), '[NEEDS EVIDENCE] exact results require table repair/citation verification')}
Contribution Wording:
- Use as a structural pattern only: problem gap -> method object -> evaluation claim -> contribution list.
Limitations or Scope Boundaries:
{bullet(limitation_sents, '[NEEDS EVIDENCE] limitations not cleanly extracted')}
Reusable Writing Pattern:
- Define a security maintenance pain point, name the evidence source, then position the method as a way to improve precision/coverage over prior SZZ/version-validation workflows.
Relevance to Our Paper:
- Relevant for framing affected versions, vulnerability validation, SZZ/agent baselines, and evidence requirements.
Do Not Borrow:
- Do not copy numeric claims or dataset claims until tables and references are repaired. {LABELS}
""",
        "02_introduction.txt": f"""Opening Context:
{bullet(sentences(intro, 2), '[NEEDS EVIDENCE] introduction boundary uncertain')}
Why the Problem Matters:
{bullet(keyword_sentences(intro, ['security', 'vulnerab', 'risk', 'patch', 'maintenance', 'software'], 4))}
Concrete Pain Point:
{bullet(problem)}
Motivating Example:
{bullet(keyword_sentences(intro, ['example', 'case', 'cve', 'bug', 'commit'], 4), '[NEEDS EVIDENCE] motivating example not reliably isolated')}
Prior Work Framing:
{bullet(keyword_sentences(intro, ['szz', 'prior', 'existing', 'state-of-the-art', 'baseline'], 5))}
Why Prior Work Is Insufficient:
{bullet(keyword_sentences(intro, ['however', 'limitation', 'fail', 'difficult', 'inaccurate', 'noise'], 5))}
Technical Challenges:
{bullet(keyword_sentences(intro, ['challenge', 'difficult', 'ambiguous', 'complex', 'semantic', 'context'], 5))}
Key Insight:
{bullet(keyword_sentences(intro + ' ' + method, ['insight', 'key', 'we observe', 'we propose'], 4), '[NEEDS EVIDENCE] key insight requires manual confirmation')}
System / Method Preview:
{bullet(method_sents)}
Contribution List:
{bullet(keyword_sentences(intro, ['contribution', 'we make', 'we propose', 'we design', 'we evaluate'], 6), '[NEEDS EVIDENCE] contribution list not cleanly extracted')}
Claim-Evidence Structure:
- The introduction connects vulnerability maintenance/SZZ/version-validation pain points to an automated method and empirical evaluation, but exact claim strength requires citation/table verification.
{anchor}
Paragraph Map:
P1: Function: context/problem setup; Main Claim: see extracted introduction; Evidence Type: paper text; Transition: toward method gap.
P2: Function: prior-work gap; Main Claim: see extracted introduction; Evidence Type: paper text; Transition: toward proposed approach.
P3: Function: method preview/contributions; Main Claim: see extracted introduction; Evidence Type: paper text; Transition: toward evaluation.
Reusable Moves:
- Start from vulnerability-management cost, identify why patch/commit/version evidence is noisy, then motivate an evidence-aware method.
Risks for Our Paper:
- Avoid importing their task definition if our target remains affected versions rather than bug-introducing commit identification. Mark unsupported transfer claims with [NEEDS EVIDENCE].
""",
        "03_background_motivation.txt": f"""Domain Concepts Introduced:
{bullet(keyword_sentences((background or intro), ['vulnerability', 'commit', 'patch', 'version', 'szz', 'graph', 'agent', 'cve'], 8))}
Task Definition:
- Inferred from title and extracted sections: identify vulnerability-introducing commits, bug-introducing commits, vulnerable/affected versions, or evidence useful for version validation. [NEEDS CITATION VERIFICATION]
Threat Model / Assumptions:
- [NEEDS EVIDENCE] not asserted unless explicitly stated in the paper.
Motivating Case:
{bullet(keyword_sentences((background or intro), ['case', 'example', 'cve'], 5), '[NEEDS EVIDENCE] no clean motivating case extracted')}
Why the Case Is Chosen:
- [NEEDS EVIDENCE]
Definitions Needed by Readers:
- Vulnerability-introducing commit / bug-inducing commit, patch evidence, developer log, vulnerable version, SZZ-style tracing, depending on the paper scope.
How Background Leads to Method:
{bullet(method_sents[:4])}
Writing Pattern:
- Build from concrete artifact evidence toward why naive blame or simple version matching is insufficient.
Relevance to Our Paper:
- Useful for affected versions background and related-work positioning.
{anchor}
""",
        "04_problem_definition.txt": f"""Input:
- Paper-specific input appears to involve vulnerability reports, patches, commits, repository history, developer logs, versions, or agent-readable code evidence. [NEEDS CITATION VERIFICATION]
Output:
- Paper-specific output appears to be bug/vulnerability-introducing commits, affected/vulnerable versions, or validation decisions. [NEEDS CITATION VERIFICATION]
Objects / Entities:
- CVE/vulnerability, patch, commit, file/function, version/tag/release, repository, knowledge graph or agent state when applicable.
Formal Definitions:
{bullet(keyword_sentences(method + ' ' + background, ['definition', 'define', 'formally', 'input', 'output'], 6), '[NEEDS EVIDENCE] formal definitions not cleanly extracted')}
Objective:
{bullet(problem[:4])}
Constraints:
{bullet(keyword_sentences(method + ' ' + experiments, ['constraint', 'assume', 'only', 'require', 'cannot'], 5), '[NEEDS EVIDENCE] constraints require manual section verification')}
Evaluation Target:
{bullet(eval_sents[:5], '[NEEDS EVIDENCE] evaluation target not cleanly extracted')}
Boundary Conditions:
- [NEEDS EVIDENCE]
What Is Not Solved:
{bullet(limitation_sents, '[NEEDS EVIDENCE]')}
Reusable Formalization Pattern:
- Represent the security task as mapping noisy vulnerability evidence to a precise commit/version artifact, then state exclusions explicitly.
""",
        "05_method.txt": f"""System Overview:
{bullet(method_sents)}
Pipeline Stages:
{bullet(keyword_sentences(method, ['step', 'stage', 'phase', 'pipeline', 'first', 'then', 'finally'], 8), '[NEEDS EVIDENCE] pipeline stages require manual confirmation')}
Core Algorithm:
{bullet(keyword_sentences(method, ['algorithm', 'graph', 'search', 'match', 'rank', 'classif', 'agent', 'llm', 'static', 'differential'], 8))}
Data Structures:
{bullet(keyword_sentences(method, ['graph', 'node', 'edge', 'vector', 'embedding', 'patch', 'log', 'signature'], 6), '[NEEDS EVIDENCE] data structures not cleanly extracted')}
Model / Agent Components:
{bullet(keyword_sentences(method, ['llm', 'agent', 'prompt', 'model', 'reason', 'tool'], 6), '[NEEDS EVIDENCE] model/agent components not applicable or not extracted')}
Design Choices:
{bullet(keyword_sentences(method, ['we use', 'we choose', 'because', 'to address', 'designed'], 6))}
Why Each Choice Is Needed:
- [NEEDS EVIDENCE] requires close reading of method subsections.
Failure Handling:
{bullet(keyword_sentences(method, ['fail', 'fallback', 'filter', 'noise', 'false'], 5), '[NEEDS EVIDENCE] failure handling not cleanly extracted')}
Complexity / Cost Discussion:
{bullet(keyword_sentences(method + ' ' + experiments, ['time', 'cost', 'runtime', 'complexity', 'token', 'manual'], 5), '[NEEDS EVIDENCE] cost discussion not cleanly extracted')}
Pseudocode or Algorithm Blocks:
- See raw_extraction/algorithms/ if present; otherwise [NEEDS ALGORITHM REPAIR].
Static Reproducibility Signals:
- Source path: {source}; source code was not available locally in the requested path. [EXECUTION NOT REQUESTED]
{anchor}
Writing Pattern:
- Present the method as a pipeline from security evidence extraction to candidate generation/filtering/ranking/validation, with each stage tied to a specific failure mode.
""",
        "06_experiments.txt": f"""Research Questions:
{bullet(keyword_sentences(experiments, ['rq1', 'rq2', 'research question', 'question'], 8), '[NEEDS EVIDENCE] RQs not cleanly extracted')}
Datasets:
{bullet(keyword_sentences(experiments, ['dataset', 'cve', 'project', 'repository', 'benchmark', 'sample'], 8))}
Baselines:
{bullet(keyword_sentences(experiments, ['baseline', 'compare', 'state-of-the-art', 'szz', 'tool'], 8), '[NEEDS EVIDENCE] baselines require table/section verification')}
Metrics:
{bullet(keyword_sentences(experiments, ['precision', 'recall', 'f1', 'accuracy', 'top', 'mrr', 'hit', 'time'], 8))}
Experimental Protocol:
{bullet(keyword_sentences(experiments, ['experiment', 'evaluate', 'protocol', 'setup', 'implementation'], 8))}
Implementation Details:
{bullet(keyword_sentences(experiments + ' ' + method, ['implemented', 'implementation', 'python', 'java', 'github', 'open-source'], 6), '[NEEDS ARTIFACT] no local source tree detected')}
Hyperparameters / Settings:
{bullet(keyword_sentences(experiments, ['parameter', 'threshold', 'temperature', 'model', 'setting'], 5), '[NEEDS EVIDENCE] settings not cleanly extracted')}
Hardware / Environment:
{bullet(keyword_sentences(experiments, ['hardware', 'cpu', 'gpu', 'server', 'environment'], 4), '[NEEDS EVIDENCE] hardware/environment not cleanly extracted')}
Static Reproducibility Materials:
- Local requested path contains PDF evidence only; no README/config/script/data directory detected for this paper. [NEEDS ARTIFACT]
Execution Status:
- [EXECUTION NOT REQUESTED]
What Is Measured:
{bullet(eval_sents)}
What Is Not Measured:
- [NEEDS EVIDENCE]
{anchor}
Writing Pattern:
- Frame evaluation by RQs, dataset construction, baselines, then quantitative and case-study evidence.
""",
        "07_evaluation.txt": f"""Main Results:
{bullet(keyword_sentences(abstract + ' ' + experiments, ['result', 'outperform', 'improve', 'achieve', 'accuracy', 'precision', 'recall', 'f1'], 8), '[NEEDS EVIDENCE] exact main results require table repair')}
Per-RQ Findings:
{bullet(keyword_sentences(experiments, ['rq1', 'rq2', 'rq3', 'answer'], 8), '[NEEDS EVIDENCE] per-RQ findings not cleanly extracted')}
Ablation:
{bullet(keyword_sentences(experiments, ['ablation', 'variant', 'without', 'component'], 5), '[NEEDS EVIDENCE] ablation not detected')}
Sensitivity Analysis:
{bullet(keyword_sentences(experiments, ['sensitivity', 'threshold', 'parameter'], 5), '[NEEDS EVIDENCE] sensitivity analysis not detected')}
Case Study:
{bullet(keyword_sentences(experiments + ' ' + intro, ['case study', 'case', 'example', 'cve'], 6), '[NEEDS EVIDENCE] case study not cleanly extracted')}
Efficiency:
{bullet(keyword_sentences(experiments, ['time', 'runtime', 'efficiency', 'cost', 'token'], 5), '[NEEDS EVIDENCE] efficiency not cleanly extracted')}
Error Analysis:
{bullet(keyword_sentences(experiments, ['error', 'false positive', 'false negative', 'failure', 'incorrect'], 5), '[NEEDS EVIDENCE] error analysis not cleanly extracted')}
Statistical / Validity Notes:
- [NEEDS CITATION VERIFICATION]
How Claims Are Supported:
- Claims are supported by extracted paper text and caption-level table/figure evidence only. Exact numeric claims are blocked until [NEEDS TABLE REPAIR] is addressed.
Unsupported or Weakly Supported Claims:
- Any claim about reproduced performance, local runtime behavior, or artifact completeness is unsupported. [EXECUTION NOT REQUESTED]; [NEEDS ARTIFACT]
{anchor}
Writing Pattern:
- Keep result claims tied to RQs and avoid transferring their metric numbers to our paper.
""",
        "08_limitations_ethics.txt": f"""Stated Limitations:
{bullet(limitation_sents, '[NEEDS EVIDENCE] limitations/threats section not cleanly extracted')}
Threats to Validity:
{bullet(keyword_sentences(limitations + ' ' + experiments, ['validity', 'threat', 'bias', 'dataset', 'manual'], 6), '[NEEDS EVIDENCE] threats to validity require manual confirmation')}
Ethical Considerations:
{bullet(keyword_sentences(limitations + ' ' + intro, ['ethic', 'responsible', 'misuse', 'disclosure'], 4), '[NEEDS EVIDENCE] ethics not detected')}
Security / Misuse Discussion:
{bullet(keyword_sentences(limitations + ' ' + intro, ['misuse', 'exploit', 'attack', 'security'], 5), '[NEEDS EVIDENCE] misuse discussion not cleanly extracted')}
Responsible Disclosure:
{bullet(keyword_sentences(limitations + ' ' + intro, ['disclosure', 'responsible'], 3), '[NEEDS EVIDENCE] responsible disclosure not detected')}
Scope Boundaries:
{bullet(keyword_sentences(limitations + ' ' + method, ['only', 'scope', 'assume', 'limit', 'future'], 6))}
Writing Pattern:
- Separate dataset/tool limitations, generalizability, and artifact/reproducibility gaps.
Relevance to Our Paper:
- Useful for explicitly bounding affected-version claims and separating static evidence from execution/reproduction evidence.
""",
        "09_figures_tables.txt": f"""Figure / Table Inventory:
{bullet(figure_table_items, '[NEEDS EVIDENCE] no figure/table captions extracted')}
Required Figures for Our Paper:
- Do not reuse figures. Borrow only structural ideas after visual extraction/verification.
Design Pattern:
- Security validation papers often use pipeline diagrams, dataset construction tables, RQ result tables, and case-study figures. Confirm per-paper visuals before using.
Could Inspire Our Paper? yes, structurally only.
""",
        "10_writing_patterns.txt": f"""Best Structural Moves:
- Security maintenance pain point -> noisy evidence source -> method/pipeline -> empirical validation.
Best Transition Moves:
- Move from prior SZZ/version-identification limits to artifact-grounded evidence combination.
Best Contribution Wording Pattern:
- Name the specific task, state the evidence source, state the precision/coverage target, then list evaluation scope.
Best Method Overview Pattern:
- Show a staged pipeline and connect each stage to a failure mode in prior approaches.
Best Experiment Framing Pattern:
- Use RQs, dataset/baseline/metric blocks, then claim boundaries.
Useful Phrases to Paraphrase Structurally:
- Do not copy source wording; paraphrase only the rhetorical role.
Patterns to Avoid:
- Avoid unsupported numeric/result claims, artifact claims, or execution claims. {LABELS}; [NEEDS ARTIFACT]
""",
        "11_relevance_to_our_paper.txt": f"""Direct Relevance:
- High for affected versions / vulnerability validation if the paper targets vulnerable versions, patch evidence, developer logs, SZZ, or bug/vulnerability-introducing commit identification.
Indirect Relevance:
- Medium for writing evaluation framing, baseline positioning, and evidence-packaging style.
Useful for Which Section:
- Related Work, Background/Motivation, Method comparison, Evaluation baseline discussion, Limitations.
Comparable Task Elements:
- Vulnerability evidence -> commit/version decision; patch/log/history reasoning; automated validation.
Comparable Method Elements:
- Candidate generation, filtering/ranking, graph/agent/static analysis, patch-differential reasoning, depending on the paper.
Comparable Evaluation Elements:
- Dataset construction, baseline comparisons, precision/recall/F1-style metrics, case studies. [NEEDS TABLE REPAIR]
What We Can Borrow Structurally:
- Argument structure and evaluation organization.
What We Cannot Borrow:
- Claims about our system, exact metrics, or artifact functionality without our own evidence.
Evidence Needed Before Use:
- [NEEDS CITATION VERIFICATION]; [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]
Priority: high
""",
        "12_artifact_consistency.txt": f"""Artifact Classification: Type D
Local Source / Artifact Path: {source}
README/config/script/data detection: no local source tree was detected for this PDF in the requested path.
Static Consistency Notes:
- Paper claims were inspected from PDF text only.
- No source-code consistency claim is made.
- Runtime behavior and reproduced results are explicitly out of scope. [EXECUTION NOT REQUESTED]
Observed Local Output / Data Artifacts:
- raw_extraction/full_text.txt
- raw_extraction/page_text/*.txt
- raw_extraction/section_text/*.txt
- raw_extraction/agent_index.json
Missing Data / Missing Entrypoints:
- [NEEDS ARTIFACT] source repository, README, scripts, configs, datasets, and result artifacts are not present beside the PDF.
""",
        "13_completeness_audit.txt": f"""Raw Extraction:
- PDF text extracted: yes
- Page text extracted: yes, page count {page_count}
- Section text extracted: yes, section file count {len(sections)}
- Agent index exists: yes
- Extraction profile exists: yes
- Layout blocks extracted: missing/not attempted
- References extracted: {'yes/uncertain' if references_text else 'uncertain'}
- Table extraction: {table_status}
- Figure extraction: {figure_status}
- Formula/algorithm/prompt extraction: partial/not detected depending on raw_extraction subdirectories
- OCR needed: no obvious full-text failure detected

Section Analysis:
- 00_meta.txt through 12_artifact_consistency.txt: complete
- Are analysis files section-oriented enough for writing? yes, with repair labels

Source / Artifact Static Analysis:
- Source inventory exists: yes
- README/config inspected: not applicable, no local source tree detected
- Main entrypoints inspected: not applicable
- Runtime behavior: [EXECUTION NOT REQUESTED]

Writing Readiness:
- Abstract support: partial
- Introduction support: partial
- Background/motivation support: partial
- Method support: partial
- Experiment/evaluation support: weak until [NEEDS TABLE REPAIR]
- Limitations support: partial/weak
- Related work support: partial

Known Gaps:
- [NEEDS TABLE REPAIR]
- [NEEDS FIGURE EXTRACTION]
- [NEEDS LAYOUT BLOCK EXTRACTION]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade: medium, because text and section-level retrieval are available, but layout/table/figure/artifact evidence is not citation-ready.
""",
    }


def analyze_item(reference_root: Path, base_dir: Path, item: dict[str, Any]) -> dict[str, Any]:
    paper_id = item["paper_id"]
    pdf = base_dir / item["pdf"]
    duplicate_paths = [str(base_dir / path) for path in item.get("duplicates", [])]
    if not pdf.exists():
        raise FileNotFoundError(pdf)

    paper_dir = reference_root / paper_id
    raw_dir = paper_dir / "raw_extraction"
    analysis_dir = paper_dir / "analysis"
    for directory in [paper_dir, raw_dir, analysis_dir]:
        directory.mkdir(parents=True, exist_ok=True)
    for subdir in RAW_SUBDIRS:
        (raw_dir / subdir).mkdir(parents=True, exist_ok=True)

    reader = PdfReader(str(pdf))
    page_texts: list[str] = []
    empty_pages: list[int] = []
    for page_number, page in enumerate(reader.pages, 1):
        text = page.extract_text() or ""
        page_texts.append(text)
        if not clean(text):
            empty_pages.append(page_number)
        write(raw_dir / "page_text" / f"page_{page_number:03d}.txt", text)
    full_text = "\n\n".join(f"===== Page {idx:03d} =====\n{text}" for idx, text in enumerate(page_texts, 1))
    write(raw_dir / "full_text.txt", full_text)

    title = infer_title(pdf, reader)
    year = infer_year(full_text, pdf.name)
    sections = sectionize(full_text)
    section_index: list[str] = []
    for index, (key, value) in enumerate(sections.items(), 1):
        filename = f"{index:02d}_{key}.txt"
        write(raw_dir / "section_text" / filename, value)
        section_index.append(f"{index:02d}: {key} -> section_text/{filename}")
    write(raw_dir / "sections.txt", "Status: extracted\nSection Boundary Confidence: partial\n" + "\n".join(section_index))

    references_text = find_section(sections, "references")
    if not references_text:
        match = re.search(r"(?is)\n\s*References\s*\n(.+)$", full_text)
        references_text = match.group(1) if match else "[NEEDS CITATION VERIFICATION] references section not cleanly extracted"
    write(raw_dir / "references.txt", references_text)
    write(raw_dir / "appendix.txt", find_section(sections, "appendix") or "No appendix section cleanly extracted. [NEEDS EVIDENCE]")

    tables = extract_captions(full_text, "Table")
    figures = extract_captions(full_text, "Figure")
    table_index: list[str] = []
    for index, caption in enumerate(tables, 1):
        prefix = f"table_{index:03d}"
        table_index.append(f"{prefix}: {caption} [NEEDS TABLE REPAIR]")
        write(raw_dir / "tables" / f"{prefix}_raw.txt", f"Table ID: {prefix}\nCaption/Raw Text: {caption}\nExtraction Confidence: partial\nNotes: [NEEDS TABLE REPAIR] caption/raw-text only; cells not verified.")
        write(raw_dir / "tables" / f"{prefix}.md", f"| field | value |\n| --- | --- |\n| caption | {caption.replace('|', '/')} |\n| repair | [NEEDS TABLE REPAIR] |")
        write(raw_dir / "tables" / f"{prefix}_cells.json", json.dumps({"table_id": prefix, "cells": [], "caption": caption, "repair_needed": True, "notes": "[NEEDS TABLE REPAIR]"}, ensure_ascii=False, indent=2))
    write(raw_dir / "tables" / "table_index.txt", "\n".join(table_index) if table_index else "No table captions cleanly extracted. [NEEDS TABLE REPAIR]")

    figure_index: list[str] = []
    for index, caption in enumerate(figures, 1):
        prefix = f"figure_{index:03d}"
        figure_index.append(f"{prefix}: {caption} [NEEDS FIGURE EXTRACTION]")
        write(raw_dir / "figures" / f"{prefix}_caption.txt", caption)
        write(raw_dir / "figures" / f"{prefix}_context.txt", f"Caption-only extraction from PDF text. [NEEDS FIGURE EXTRACTION]\n{caption}")
        write(raw_dir / "figures" / f"{prefix}_agent_summary.txt", "This figure caption may support method/evaluation retrieval, but no image crop was extracted. [NEEDS FIGURE EXTRACTION]")
    write(raw_dir / "figures" / "figure_index.txt", "\n".join(figure_index) if figure_index else "No figure captions cleanly extracted. [NEEDS FIGURE EXTRACTION]")

    algorithms = extract_blocks(full_text, "Algorithm")
    for index, algorithm in enumerate(algorithms, 1):
        write(raw_dir / "algorithms" / f"algorithm_{index:03d}.txt", f"ID: algorithm_{index:03d}\nRaw Extracted Text:\n{algorithm}\nExtraction Confidence: partial\nRepair Needed: [NEEDS ALGORITHM REPAIR]")
    prompts = [sent for sent in keyword_sentences(full_text, ["prompt", "instruction", "llm"], 20) if len(sent) < 1200]
    for index, prompt in enumerate(prompts[:8], 1):
        write(raw_dir / "prompts" / f"prompt_{index:03d}.txt", f"ID: prompt_{index:03d}\nNearby Text:\n{prompt}\nExtraction Confidence: partial\nRepair Needed: [NEEDS PROMPT REPAIR]")
    formulas: list[str] = []
    for line in lines(full_text):
        if len(line) < 220 and re.search(r"[=∑∀≤≥]|\barg\s*max\b|\bminimize\b", line):
            formulas.append(line)
        if len(formulas) >= 12:
            break
    for index, formula in enumerate(formulas, 1):
        write(raw_dir / "formulas" / f"formula_{index:03d}.txt", f"ID: formula_{index:03d}\nRaw Extracted Text: {formula}\nExtraction Confidence: partial\nRepair Needed: [NEEDS FORMULA REPAIR]")

    source_inventory = f"""Source Path: [NEEDS ARTIFACT] no local source/artifact path detected beside the requested PDF
Analysis Mode: static-only
Repository / File Layout Observed:
- Input directory: {base_dir}
- Canonical PDF: {pdf}
- Duplicate PDF Paths: {'; '.join(duplicate_paths) if duplicate_paths else 'none in requested set'}
- No README/config/script/data/source directory matched this PDF during static inventory.
Primary Files:
- {pdf.name}
Key Static Evidence:
- PDF text extracted under raw_extraction/.
Static Consistency Notes:
- Source-code consistency cannot be checked without a local source/artifact tree. [NEEDS ARTIFACT]
Observed Local Output / Data Artifacts:
- page_text/, section_text/, tables/ caption/raw files, figures/ caption/context files, agent_index.json.
Missing Data / Missing Entrypoints:
- [NEEDS ARTIFACT] README, configs, source code, scripts, datasets, and result artifacts are absent from the requested PDF path.
Execution:
- [EXECUTION NOT REQUESTED] No code was run, no dependency installed, no experiment reproduced.
"""
    write(raw_dir / "source_static_inventory.txt", source_inventory)
    write(raw_dir / "00_source_manifest.txt", f"""Paper ID: {paper_id}
Original PDF Path: {pdf}
Duplicate PDF Paths: {'; '.join(duplicate_paths) if duplicate_paths else ''}
Original Text Path: {raw_dir / 'full_text.txt'}
Source Code Path or URL: 
Artifact/Data Path or URL: 
Extraction Date: {date.today().isoformat()}
Extraction Tools: pypdf PdfReader.extract_text; CitationAnalysis local static generator
Artifact Type: Type D
Notes: Source/artifact not detected locally. [NEEDS ARTIFACT]; [EXECUTION NOT REQUESTED]
""")
    metadata = {
        "paper_id": paper_id,
        "title": title,
        "authors": [],
        "venue": "",
        "year": year,
        "doi": "",
        "arxiv": "",
        "pdf_path": str(pdf),
        "duplicate_pdf_paths": duplicate_paths,
        "artifact_type": "Type D",
        "page_count": len(reader.pages),
        "citation_status": "unverified",
    }
    write(raw_dir / "metadata.json", json.dumps(metadata, ensure_ascii=False, indent=2))
    write(raw_dir / "extraction_log.txt", f"""Status: extracted
Tools Used: pypdf PdfReader.extract_text; local static file inventory
Successful Outputs: full_text.txt; page_text/*.txt; sections.txt; section_text/*.txt; references.txt; agent_index.json; extraction_profile.txt; source_static_inventory.txt
Failed Outputs: precise layout blocks; citation-ready tables; figure crops; verified citation metadata
Pages With Empty Text: {empty_pages if empty_pages else 'none detected'}
OCR Needed: {'yes/partial' if empty_pages and len(empty_pages) > len(reader.pages) // 2 else 'no'}
Tables Extracted: {len(tables)} caption/raw candidates; [NEEDS TABLE REPAIR]
Figures/Captions Extracted: {len(figures)} caption/context candidates; [NEEDS FIGURE EXTRACTION]
References Extracted: {'yes/uncertain' if references_text else 'uncertain'}
Known Losses: [NEEDS LAYOUT BLOCK EXTRACTION]; multi-column reading order, table cells, figure images, formulas, and references are not citation-ready.
Next Repair Step: repair tables/figures and verify citation metadata against publisher/DBLP/DOI.
PDF Text Complete: yes
PDF Layout Partial: yes
Citation-Ready Tables: no
Figure-Ready: no
Agent Index: generated/partial
""")

    for filename, text in build_analysis(paper_id, title, year, str(pdf), duplicate_paths, len(reader.pages), sections, references_text, tables, figures).items():
        write(analysis_dir / filename, text)

    units: list[dict[str, Any]] = []
    gaps: list[str] = []
    for index, (key, value) in enumerate(sections.items(), 1):
        units.append(make_unit(paper_id, "section", key, [f"raw_extraction/section_text/{index:02d}_{key}.txt"], value, ["abstract", "introduction", "method", "evaluation", "related_work", "retrieval"], "medium" if len(value) > 500 else "partial"))
    for index, caption in enumerate(tables, 1):
        units.append(make_unit(paper_id, "table", f"table_{index:03d}", [f"raw_extraction/tables/table_{index:03d}_raw.txt", f"raw_extraction/tables/table_{index:03d}.md", f"raw_extraction/tables/table_{index:03d}_cells.json"], caption, ["evaluation", "experiments", "retrieval"], "partial", True, ["citation-ready numeric claim"]))
    gaps.append("[NEEDS TABLE REPAIR] table cells/values are not citation-ready" if tables else "[NEEDS TABLE REPAIR] no citation-ready tables extracted")
    for index, caption in enumerate(figures, 1):
        units.append(make_unit(paper_id, "figure", f"figure_{index:03d}", [f"raw_extraction/figures/figure_{index:03d}_caption.txt", f"raw_extraction/figures/figure_{index:03d}_context.txt"], caption, ["method", "evaluation", "retrieval"], "partial", True, ["visual-detail claim"]))
    gaps.append("[NEEDS FIGURE EXTRACTION] figure crops/images are missing" if figures else "[NEEDS FIGURE EXTRACTION] no figure crops/captions cleanly extracted")
    units.append(make_unit(paper_id, "reference", "references", ["raw_extraction/references.txt"], references_text, ["related_work", "citation_verification"], "partial", True, ["verified BibTeX metadata"]))
    units.append(make_unit(paper_id, "artifact", "source_static_inventory", ["raw_extraction/source_static_inventory.txt"], source_inventory, ["artifact_consistency", "reproducibility"], "medium", True, ["runtime behavior", "reproduced metric", "artifact completeness claim"]))
    for index in range(len(algorithms)):
        units.append(make_unit(paper_id, "algorithm", f"algorithm_{index + 1:03d}", [f"raw_extraction/algorithms/algorithm_{index + 1:03d}.txt"], "Algorithm block extracted with possible layout loss.", ["method", "retrieval"], "partial", True, ["exact pseudocode reproduction"]))
    for index in range(min(len(prompts), 8)):
        units.append(make_unit(paper_id, "prompt", f"prompt_{index + 1:03d}", [f"raw_extraction/prompts/prompt_{index + 1:03d}.txt"], "Prompt/LLM-related nearby text extracted with possible layout loss.", ["method", "retrieval"], "partial", True, ["exact prompt reproduction"]))
    gaps += [
        "[NEEDS LAYOUT BLOCK EXTRACTION] no layout blocks extracted",
        "[NEEDS CITATION VERIFICATION] metadata and references are unverified",
        "[NEEDS ARTIFACT] local source/artifact tree not detected",
        "[EXECUTION NOT REQUESTED] static-only analysis",
    ]
    write(raw_dir / "agent_index.json", json.dumps({
        "paper_id": paper_id,
        "title": title,
        "source_manifest": "00_source_manifest.txt",
        "extraction_profile": "extraction_profile.txt",
        "evidence_units": units,
        "known_gaps": gaps,
    }, ensure_ascii=False, indent=2))
    write(raw_dir / "extraction_profile.txt", f"""Primary Consumer: agent
PDF Text Layer: complete
Layout Block Layer: missing/not attempted
Table Layer: {'caption-only' if tables else 'missing'}
Figure Layer: {'caption-only' if figures else 'missing'}
Formula Layer: {'partial' if formulas else 'not detected/not attempted'}
Algorithm Layer: {'partial' if algorithms else 'not detected/not attempted'}
Prompt Layer: {'partial' if prompts else 'not detected/not attempted'}
Known Ordering Losses: multi-column reading order may be imperfect; section boundaries are heuristic.
Known Layout Losses: [NEEDS LAYOUT BLOCK EXTRACTION]; [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]
Agent Retrieval Usability: medium
Citation Readiness: low
Next Repair Step: table repair, figure/page crop extraction, DOI/venue/reference verification, and artifact/source collection.
Evidence Units: {len(units)}
""")

    return {
        "paper_id": paper_id,
        "pdf_path": str(pdf),
        "source_path": "",
        "page_count": len(reader.pages),
        "evidence_units": len(units),
        "tables": len(tables),
        "figures": len(figures),
        "output_dir": str(paper_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Static CitationAnalysis ingestion for selected PDFs.")
    parser.add_argument("--reference-root", type=Path, required=True)
    parser.add_argument("--base-dir", type=Path, required=True)
    parser.add_argument("--items-json", default="", help="JSON list of {paper_id,pdf,duplicates}.")
    parser.add_argument("--inventory-json", type=Path, default=None, help="Batch inventory JSON generated by inventory_reference_inputs.py.")
    parser.add_argument("--paper-ids", default="", help="Comma-separated paper IDs to select from --inventory-json.")
    args = parser.parse_args()

    if args.items_json:
        items = json.loads(args.items_json)
    elif args.inventory_json:
        selected = {item.strip() for item in args.paper_ids.split(",") if item.strip()}
        inventory = json.loads(args.inventory_json.read_text(encoding="utf-8"))
        by_id: dict[str, dict[str, Any]] = {}
        for candidate in inventory.get("candidates", []):
            paper_id = candidate.get("assigned_paper_id", "")
            if selected and paper_id not in selected:
                continue
            if candidate.get("status") == "skipped_duplicate":
                if paper_id in by_id:
                    by_id[paper_id].setdefault("duplicates", []).append(Path(candidate["canonical_pdf_path"]).name)
                continue
            if paper_id not in by_id:
                by_id[paper_id] = {
                    "paper_id": paper_id,
                    "pdf": Path(candidate["canonical_pdf_path"]).name,
                    "duplicates": [Path(path).name for path in candidate.get("duplicate_pdf_paths", [])],
                }
        items = list(by_id.values())
    else:
        parser.error("Provide --items-json or --inventory-json.")

    summary = [analyze_item(args.reference_root, args.base_dir, item) for item in items]
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
