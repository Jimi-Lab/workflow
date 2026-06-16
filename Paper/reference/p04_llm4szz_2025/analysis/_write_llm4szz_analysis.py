from pathlib import Path

ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference\p04_llm4szz_2025")
AN = ROOT / "analysis"
PAPER_ID = "p04_llm4szz_2025"
PDF = r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\LLM4SZZ\LLM4SZZ：Enhancing SZZ Algorithm with Context-Enhanced Assessment on Large Language Models.pdf"
SRC = r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\LLM4SZZ\LLM4SZZ"


def w(name: str, text: str) -> None:
    (AN / name).write_text(text.strip() + "\n", encoding="utf-8", newline="\n")


w("00_meta.txt", f"""
Paper ID: p04_llm4szz_2025
Title: LLM4SZZ: Enhancing SZZ Algorithm with Context-Enhanced Assessment on Large Language Models
Venue / Year: Proc. ACM Softw. Eng., ISSTA / 2025
Authors: Lingxiao Tang; Jiakun Liu; Zhongxin Liu; Xiaohu Yang; Lingfeng Bao
Artifact Type: Type A
Input Files:
- PDF: {PDF}
- Source/artifact directory: {SRC}
Source / Artifact Path: {SRC}
Analysis Status: complete for PDF text-layer and static-source pass; no runtime reproduction.
Agent Index Status: partial, with section/table/figure/prompt/artifact evidence units.
Main Topic: LLM-enhanced SZZ for identifying bug-inducing commits.
Why This Paper Is Relevant: It is an adjacent baseline for commit-level bug-inducing commit discovery, which can feed or constrain affected versions analysis but does not by itself solve version-level verification.
Citation Metadata Status: extracted from PDF metadata but still [NEEDS CITATION VERIFICATION].
Missing Evidence: [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]; [NEEDS LAYOUT BLOCK EXTRACTION]; [NEEDS PROMPT REPAIR]; [NEEDS ARTIFACT]; [EXECUTION NOT REQUESTED]
""")

w("01_abstract.txt", """
Problem: Existing SZZ variants identify bug-inducing commits but are limited by static heuristics, deleted-line assumptions, and incomplete use of patch/commit context.
Gap: Static and heuristic SZZ variants are easy to implement but have limited improvement; neural variants require complex preprocessing, can be language-limited, and may trade recall for precision.
Core Idea: Use LLM assessment with additional context to identify bug-inducing commits under different bug-fixing commit patterns.
Method: The paper presents two paths: rank-based identification and context-enhanced identification.
Evaluation Setup: The abstract states evaluation across three datasets and comparisons with baselines; exact numeric use requires table repair.
Main Results: Text layer states F1 improvement of 6.9% to 16.0% and additional bug-inducing commits found; these numbers should be table/citation-verified before paper reuse.
Contribution Wording: The abstract frames LLM4SZZ as using LLM comprehension of bugs plus context-rich candidate selection.
Limitations or Scope Boundaries: It targets bug-inducing commit identification, not complete affected versions reconstruction.
Reusable Writing Pattern: State weaknesses of prior algorithm families, then introduce a hybrid design that dispatches cases to different strategies.
Relevance to Our Paper: Useful as a candidate-commit generation baseline and as a contrast for why affected versions require downstream version/tag verification.
Do Not Borrow: Do not present LLM4SZZ's commit-level F1 as affected versions accuracy.
""")

w("02_introduction.txt", """
Opening Context: SZZ is introduced as a dominant technique for identifying bug-inducing commits and supporting downstream software engineering studies.
Why the Problem Matters: Better bug-inducing commit identification improves defect prediction, static analysis, maintenance studies, and empirical software engineering tasks.
Concrete Pain Point: Prior SZZ variants miss semantic/contextual information and are often constrained to bug-fixing commits with deleted lines.
Motivating Example: The paper includes motivating examples showing refactoring/noise and large patch context; figure extraction is needed before visual reuse.
Prior Work Framing: The introduction groups earlier work into original/heuristic/static/neural SZZ and positions LLM4SZZ as using LLM reasoning over code/context.
Why Prior Work Is Insufficient: The text layer states that many variants rely on static techniques or heuristic assumptions, while deep-learning approaches can be language-limited and recall-sensitive.
Technical Challenges: Bug-fixing commits may not contain deletions, bug-relevant lines may be sparse, patch context can be large, and LLMs may struggle with long/noisy context.
Key Insight: Different commit types should be handled by different strategies, and LLMs can assess root-cause relevance when provided with suitable context.
System / Method Preview: Preparation, context-enhanced assessment, and commit identification structure the method.
Contribution List: [NEEDS CITATION VERIFICATION] Exact bullet wording should be verified from the PDF layout.
Claim-Evidence Structure: The paper moves from SZZ limitations -> LLM opportunity -> two-strategy method -> multi-dataset evaluation.
Agent Evidence Anchors: raw_extraction/section_text/02_introduction.txt; raw_extraction/figures/figure_index.txt
Paragraph Map:
P1: Function: define SZZ importance. Main Claim: SZZ underpins many studies. Evidence Type: prior work framing. Transition: variants and limitations.
P2: Function: summarize existing variants. Main Claim: existing improvements are bounded by assumptions. Evidence Type: literature contrast. Transition: LLM opportunity.
P3+: Function: introduce LLM4SZZ. Main Claim: rank/context enhanced LLM assessment can improve bug-inducing commit identification. Evidence Type: method preview and reported results.
Reusable Moves: Separate "why the task matters" from "why prior technical assumptions fail."
Risks for Our Paper: Keep affected versions terminology separate from bug-inducing commit identification.
""")

w("03_background_motivation.txt", """
Domain Concepts Introduced: SZZ algorithm; bug-fixing commit; bug-inducing commit; buggy statements; commit message; patch context; LLM assessment.
Task Definition: Given a bug-fixing commit, identify one or more bug-inducing commits.
Threat Model / Assumptions: This is a software history mining task, not a vulnerability exploitability model.
Motivating Case: Figures discuss noisy changes/refactoring and large commit contexts; captions are available but images need extraction.
Why the Case Is Chosen: It demonstrates why line deletion alone and local static heuristics are insufficient for some fixing commits.
Definitions Needed by Readers: BFC, BIC, deleted-line cases, no-deleted-line cases, candidate commits, buggy statements, rank-based identification, context-enhanced identification.
How Background Leads to Method: Background motivates a dispatch between rank-based and context-enhanced paths depending on LLM comprehension and commit type.
Writing Pattern: Use concrete patch examples before introducing abstract pipeline stages.
Relevance to Our Paper: Good model for explaining why commit-level seeds are uncertain and need verification before affected versions inference.
Agent Evidence Anchors: raw_extraction/section_text/03_background.txt
""")

w("04_problem_definition.txt", """
Input: Bug-fixing commits and related source history; local artifact includes dataset/FFmpeg_dataset_fa.json and scripts, but full benchmark data is not verified.
Output: Bug-inducing commit predictions.
Objects / Entities: bug-fixing commit, bug-inducing commit, buggy statement, patch hunk, candidate commit, dataset, baseline method, LLM model.
Formal Definitions: [NEEDS EVIDENCE] Exact formal definitions should be checked in the PDF text before citation.
Objective: Improve precision/F1 of bug-inducing commit identification while preserving recall relative to baselines.
Constraints: Large/noisy patch contexts; different commit structures; reliance on LLM judgment; benchmark artifact completeness not verified.
Evaluation Target: Precision, recall, and F1-score over bug-inducing commit identification datasets.
Boundary Conditions: The paper does not directly define affected versions as the target output; affected-version scripts in the local artifact are post-processing/adjacent evidence.
What Is Not Solved: Full affected versions verification, model-output reproducibility without precomputed artifacts, and runtime reproduction in this pass. [EXECUTION NOT REQUESTED]
Reusable Formalization Pattern: Treat candidate generation and final version/range verification as separate stages.
""")

w("05_method.txt", """
System Overview: LLM4SZZ combines SZZ-style history tracing with LLM-guided assessment of buggy statements, patch context, and candidate commits.
Pipeline Stages:
1. Preparation of bug-fixing commit context.
2. Determine whether to use rank-based identification or context-enhanced identification.
3. Rank/select buggy statements or candidate commits using LLM judgment.
4. Trace/identify bug-inducing commits.
5. Evaluate predictions against datasets and baselines.
Core Algorithm: The paper describes rank-based and context-enhanced identification; exact prompt/algorithm formatting needs repair. [NEEDS PROMPT REPAIR]
Data Structures: Local static code shows patch parsing classes, CFG/control-flow utilities, tree-sitter parsing, SZZ core classes, and version-range helper scripts.
Model / Agent Components: LLM calls are paper-level method components; local runtime/API behavior was not executed. [EXECUTION NOT REQUESTED]
Design Choices: Use different strategies for deleted-line and non-deleted-line cases; enrich context instead of relying only on static local hunks.
Why Each Choice Is Needed: Deleted-line cases can use buggy statement ranking, while non-deleted-line or large-context cases need candidate-context assessment.
Failure Handling: Discussion section covers failures from wrong candidate selection and LLM misunderstanding; exact counts require table repair.
Complexity / Cost Discussion: [NEEDS EVIDENCE] Extracted discussion mentions scalability, but exact cost claims need verification.
Pseudocode or Algorithm Blocks: Not cleanly extracted. [NEEDS ALGORITHM REPAIR]
Static Reproducibility Signals: visible scripts include gen_results_for_dels_llm.py, gen_results_for_no_dels_llm.py, core/vszz.py, CFG.py, util.py, parse_patch.py, 3_gen_vuln_version.py, version_range_evidence.py.
Agent Evidence Anchors: raw_extraction/section_text/04_method.txt; raw_extraction/source_static_inventory.txt
Writing Pattern: Present a branch-specific pipeline when a task has structurally different input cases.
""")

w("06_experiments.txt", """
Research Questions: Effectiveness of LLM4SZZ, effectiveness of key components, effectiveness across LLMs, and discussion/failure analyses.
Datasets: The paper states DS_LINUX, DS_GITHUB, and DS_APACHE in extracted tables; local artifact only visibly contains dataset/FFmpeg_dataset_fa.json in this pass. [NEEDS ARTIFACT]
Baselines: B-SZZ, AG-SZZ, MA-SZZ, R-SZZ, L-SZZ, plus V-SZZ-related local scripts. Exact baseline setup requires artifact verification.
Metrics: Precision, recall, F1-score for bug-inducing commit identification.
Experimental Protocol: Static PDF extraction shows dataset/model/baseline comparisons; no code execution or metric regeneration was performed.
Implementation Details: Local requirements.txt and README exist; imports include tree_sitter, GitPython/git, Levenshtein, networkx, matplotlib, pydriller, subprocess, and custom SZZ/CFG utilities.
Hyperparameters / Settings: [NEEDS EVIDENCE]
Hardware / Environment: PDF text mentions Ubuntu/CPU context near experiment setup, but exact environment needs citation verification.
Static Reproducibility Materials: README, requirements, dataset folder, result parsing scripts, baseline scripts, LLM scripts, core SZZ files.
Execution Status: [EXECUTION NOT REQUESTED]
What Is Measured: commit-level bug-inducing commit identification performance.
What Is Not Measured: affected versions accuracy, exact vulnerable tag sets, end-to-end reproduction in this pass.
Agent Evidence Anchors: raw_extraction/section_text/05_experiments.txt; raw_extraction/tables/table_index.txt; raw_extraction/source_static_inventory.txt
Writing Pattern: Split evaluation by RQ and include ablation/model-sensitivity analyses.
""")

w("07_evaluation.txt", """
Main Results: The text layer and table captions indicate LLM4SZZ is compared against SZZ baselines and different LLMs using precision/recall/F1. Exact numeric claims require table repair.
Per-RQ Findings:
- RQ1: effectiveness against baselines.
- RQ2: contribution of key components/ablation.
- RQ3: comparison across LLMs.
Ablation: Table context indicates ablation study exists, but structured values are not citation-ready. [NEEDS TABLE REPAIR]
Sensitivity Analysis: Different language models are compared; exact conclusions need table repair.
Case Study: Discussion and failure analysis contain examples of missed or extra bug-inducing commits.
Efficiency: Scalability is discussed, but exact cost/time claims need verification. [NEEDS EVIDENCE]
Error Analysis: Discussion mentions failure cases from incorrect candidate choice and bugs not understood by LLMs.
Statistical / Validity Notes: [NEEDS EVIDENCE]
How Claims Are Supported: Main claims rely on tables and figures; current extraction is caption/context-only.
Unsupported or Weakly Supported Claims: Any exact improvement percentage, per-dataset score, or ablation conclusion remains weak until [NEEDS TABLE REPAIR].
Agent Evidence Anchors: raw_extraction/section_text/06_evaluation.txt; raw_extraction/tables/table_index.txt
Writing Pattern: Evaluate both overall method effectiveness and the specific mechanism that justifies the design.
""")

w("08_limitations_ethics.txt", """
Stated Limitations: Discussion includes failure analysis, data leakage, scalability, LLM misunderstanding, extra BICs, and threats to validity.
Threats to Validity: The extracted section contains a dedicated threats subsection inside Discussion.
Ethical Considerations: [NEEDS EVIDENCE]
Security / Misuse Discussion: Not confirmed in the static extraction. [NEEDS EVIDENCE]
Responsible Disclosure: [NEEDS EVIDENCE]
Scope Boundaries: The method identifies bug-inducing commits; downstream affected versions inference needs separate validation.
Writing Pattern: Include both algorithmic failure modes and data/model validity risks.
Relevance to Our Paper: Useful for arguing that LLM/SZZ candidate generation must be verifier-gated before affected versions claims.
""")

w("09_figures_tables.txt", """
Figure / Table Inventory:
ID: figure_001 to figure_003
Agent Evidence Unit IDs: p04_llm4szz_2025:figure:figure_001 ... figure_003
Purpose: motivation and workflow/context illustrations.
Evidence Shown: caption/context only.
Placement in Argument: motivates noisy/refactoring cases and context-enhanced identification.
Extraction Confidence: partial
Repair Needed: [NEEDS FIGURE EXTRACTION]
Citation Readiness: low
Figure Readiness: no
Design Pattern: use patch-level visual examples to motivate algorithm branches.
Could Inspire Our Paper? yes, structurally.

ID: table_001
Agent Evidence Unit ID: p04_llm4szz_2025:table:table_001
Purpose: compare methods on bug-inducing commit identification.
Evidence Shown: caption/context and partially extracted values.
Placement in Argument: main RQ1 evidence.
Extraction Confidence: partial
Repair Needed: [NEEDS TABLE REPAIR]
Citation Readiness: low
Figure Readiness: not applicable
Design Pattern: baseline table with precision/recall/F1 by dataset.
Could Inspire Our Paper? yes, but adapt to affected versions metrics.

ID: table_002
Agent Evidence Unit ID: p04_llm4szz_2025:table:table_002
Purpose: compare LLM choices.
Evidence Shown: caption/context and partially extracted values.
Placement in Argument: RQ3/model-sensitivity evidence.
Extraction Confidence: partial
Repair Needed: [NEEDS TABLE REPAIR]
Citation Readiness: low
Figure Readiness: not applicable
Design Pattern: model comparison across datasets.
Could Inspire Our Paper? yes, if we compare agent/model variants.

Required Figures for Our Paper: candidate-generation vs affected versions verification boundary; affected versions evaluation table; failure taxonomy connecting candidate commits, propagation, and tag verification. [NEEDS EVIDENCE from our project]
""")

w("10_writing_patterns.txt", """
Best Structural Moves:
- Separate prior algorithm families and their assumptions.
- Use motivating patch examples before a complex pipeline.
- Dispatch method branches according to input-case structure.
- Evaluate overall performance, ablation, model choice, and failures separately.

Best Transition Moves:
- From SZZ's importance to limitations of line/deletion heuristics.
- From LLM capability to LLM context limitations.
- From candidate-commit prediction to failure analysis and validity threats.

Best Contribution Wording Pattern:
- "We improve X by combining Y with Z, and evaluate across datasets using precision/recall/F1."

Best Method Overview Pattern:
- Preparation -> branch selection -> LLM assessment -> candidate commit identification -> evaluation.

Best Experiment Framing Pattern:
- RQ1 effectiveness; RQ2 component ablation; RQ3 model sensitivity; discussion/failures.

Useful Phrases to Paraphrase Structurally:
- "context-enhanced assessment" as a pattern, not as copied terminology for our system unless defined.
- "rank-based identification" as an example of branch-specific strategy naming.

Patterns to Avoid:
- Do not collapse commit-level BIC identification into affected versions analysis.
- Do not claim source artifact reproduces results without execution.
- Do not use exact table values until table repair.
""")

w("11_relevance_to_our_paper.txt", """
Direct Relevance: High as a baseline/reference for LLM-assisted SZZ and bug-inducing commit candidate generation.
Indirect Relevance: Useful for designing agentic candidate filtering, prompt/context boundaries, and failure taxonomies.
Useful for Which Section: Related Work, Background, Method motivation, Evaluation baselines, Limitations.
Comparable Task Elements: bug-fixing commits, buggy statement anchors, candidate inducing commits, blame/history tracing, LLM context assessment.
Comparable Method Elements: rank-based statement selection, context-enhanced candidate selection, CFG/tree-sitter/static analysis utilities.
Comparable Evaluation Elements: precision/recall/F1 over bug-inducing commits; ablation and model comparison tables.
What We Can Borrow Structurally: branch-specific pipeline, RQ organization, ablation framing, model sensitivity framing.
What We Cannot Borrow: commit-level metrics as affected versions metrics; paper result numbers without table repair; runtime artifact behavior without execution.
Evidence Needed Before Use: table repair, figure extraction, citation verification, artifact completeness check, and explicit mapping from BIC candidate generation to affected versions verification.
Priority: high
""")

w("12_artifact_consistency.txt", """
Paper Claims: LLM4SZZ uses LLM-based rank/context assessment to improve bug-inducing commit identification across datasets.
Implemented Components: Static source shows LLM-named scripts, baseline scripts, V-SZZ comparison scripts, CFG/tree-sitter utilities, SZZ core files, patch parsing, result parsing, version-range helper scripts, README, requirements, and a small dataset file.
Unimplemented or Stubbed Components: Full benchmark datasets, model outputs, save_logs, result directories, and complete reproduction artifacts were not verified. [NEEDS ARTIFACT]
Dataset Availability: dataset/FFmpeg_dataset_fa.json is visible; README claims dataset files for multiple datasets, but only this visible dataset file was confirmed in this pass.
Benchmark / Evaluation Scripts Visible by Static Inspection: gen_results_for_dels_llm.py, gen_results_for_no_dels_llm.py, gen_baseline_results_for_*.py, ablation.py, 5_parse_result.py.
Static Reproduction Instructions or Missing Instructions: README provides high-level commands and requirements, but it refers to a different paper title and directory structure than fully visible locally.
Config Files: constant.py and requirements.txt are present.
Environment Constraints: requirements and imports indicate tree-sitter, GitPython/git, Levenshtein, pydriller, networkx/matplotlib, and external tools; exact setup was not tested. [EXECUTION NOT REQUESTED]
Paper-Code Mismatches: README title refers to "Enhancing Bug-Inducing Commit Identification: A Fine-Grained Semantic Analysis Approach" / SEMA-SZZ rather than the PDF title LLM4SZZ; README lists dataset/result/DelBaselines/NoDelBaselines directories, but the local visible layout contains core, dataset, and top-level scripts instead. This is a static documentation/artifact mismatch.
Engineering Lessons for Our Paper: Keep artifact README synchronized with the paper title, directory layout, data availability, and execution boundaries.

Consistency Check:
Claim: LLM4SZZ uses LLM-assisted assessment with SZZ/history tracing.
Paper Location: Abstract and Approach sections.
Artifact Evidence: gen_results_for_dels_llm.py, gen_results_for_no_dels_llm.py, core/vszz.py, CFG.py, util.py.
Source Evidence: AST inventory in raw_extraction/source_static_inventory.txt.
Consistency: partially supported
Analysis Mode: static-only
Notes: Source structure aligns with the claim, but precomputed model outputs and runtime behavior were not checked.
Use in Our Paper: yes, with caution.

Consistency Check:
Claim: artifact fully supports paper evaluation.
Paper Location: Evaluation sections.
Artifact Evidence: README/requirements/scripts/dataset file.
Source Evidence: missing visible result directories and incomplete dataset visibility.
Consistency: unclear
Analysis Mode: static-only
Notes: [NEEDS ARTIFACT]; [EXECUTION NOT REQUESTED]
Use in Our Paper: no, until artifact completeness is checked.
""")

w("13_completeness_audit.txt", """
Raw Extraction:
- PDF text extracted: yes
- Page text extracted: yes, page count 23
- Section text extracted: yes, section file count 10, heuristic boundaries
- Agent index exists: yes
- Extraction profile exists: yes
- Layout blocks extracted: missing/not attempted
- References extracted: yes, text-layer only
- Table extraction: caption/context-only
- Figure extraction: caption-only
- Formula/algorithm/prompt extraction: algorithm partial/not confidently extracted; prompt context partial; formula not attempted
- OCR needed: no

Section Analysis:
- 00_meta.txt through 12_artifact_consistency.txt: complete
- Are analysis files section-oriented enough for writing? yes, with repair labels

Source / Artifact Static Analysis:
- Source inventory exists: yes
- README/config inspected: yes
- Main entrypoints inspected: yes by static AST/file layout
- Runtime behavior: [EXECUTION NOT REQUESTED]

Writing Readiness:
- Abstract support: strong
- Introduction support: strong
- Background/motivation support: strong
- Method support: partial
- Experiment/evaluation support: partial
- Limitations support: partial
- Related work support: strong

Known Gaps:
- [NEEDS TABLE REPAIR]
- [NEEDS FIGURE EXTRACTION]
- [NEEDS LAYOUT BLOCK EXTRACTION]
- [NEEDS PROMPT REPAIR]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade: medium-high, because paper text and static code structure are strong for related-work/method framing, but quantitative results and artifact completeness are not citation-ready.
""")

w("14_section_retrieval_map.txt", """
For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/02_introduction.txt
- Useful claims: SZZ importance; limitations of static/heuristic variants.
- Must not claim: affected versions accuracy.

For Background / Motivation:
- Read analysis/03_background_motivation.txt
- Read raw_extraction/section_text/03_background.txt
- Useful claims: deleted-line/no-deleted-line and context limits.
- Must not claim: exact visual details until figure extraction.

For Method:
- Read analysis/05_method.txt
- Read raw_extraction/section_text/04_method.txt
- Read raw_extraction/source_static_inventory.txt
- Useful claims: rank-based and context-enhanced branch structure.
- Must not claim: runtime model behavior in the local artifact.

For Experiments / Evaluation:
- Read analysis/06_experiments.txt and analysis/07_evaluation.txt
- Read raw_extraction/section_text/05_experiments.txt and section_text/06_evaluation.txt
- Read raw_extraction/tables/table_index.txt
- Useful claims: evaluation organization and metric families.
- Must not claim: exact scores until [NEEDS TABLE REPAIR] is resolved.

For Limitations:
- Read analysis/08_limitations_ethics.txt
- Read raw_extraction/section_text/08_limitations.txt
- Useful claims: failure modes, data leakage, scalability, LLM misunderstanding.
- Must not claim: ethics/responsible disclosure details without evidence.

For Related Work:
- Read analysis/11_relevance_to_our_paper.txt and raw_extraction/section_text/07_related_work.txt
- Useful claims: SZZ/LLM adjacent work positioning.
- Must not claim: verified BibTeX or official citation metadata.
""")

print("analysis written")
