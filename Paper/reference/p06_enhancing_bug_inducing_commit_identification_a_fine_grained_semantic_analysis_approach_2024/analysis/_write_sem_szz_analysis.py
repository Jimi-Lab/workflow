from pathlib import Path

PAPER_ID = "p06_enhancing_bug_inducing_commit_identification_a_fine_grained_semantic_analysis_approach_2024"
PAPER_DIR = Path(r"E:\AI\Agent\workflow\Paper\reference") / PAPER_ID
ANALYSIS = PAPER_DIR / "analysis"

PDF_PATH = r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\SEM-SZZ\Enhancing Bug-Inducing Commit Identification：A Fine-Grained Semantic Analysis Approach.pdf"
SOURCE_PATH = r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\SEM-SZZ\SEM-SZZ"

common = f"""Paper ID: {PAPER_ID}
Title: Enhancing Bug-Inducing Commit Identification: A Fine-Grained Semantic Analysis Approach
PDF Path: {PDF_PATH}
Source Path: {SOURCE_PATH}
Analysis Mode: PDF evidence + static source/artifact inspection only
Runtime Status: [EXECUTION NOT REQUESTED]

"""

files = {
"00_meta.txt": common + """Venue / Year: IEEE Transactions on Software Engineering, Vol. 50, No. 11, November 2024
Authors: Lingxiao Tang; Chao Ni; Qiao Huang; Lingfeng Bao
Artifact Type: Type B, local source code is present; README mentions datasets/results directories, but those directories are not present in the observed local source root. [NEEDS ARTIFACT]
Input Files:
- PDF: original local PDF path above
- Source: local SEM-SZZ directory above
- Raw extraction: raw_extraction/full_text.txt, page_text/, section_text/, tables/, figures/
Analysis Status: completed with known table/figure/layout/citation gaps
Agent Index Status: pending/updated by build_agent_index.py after analysis
Main Topic: bug-inducing commit identification using a fine-grained semantic-analysis SZZ variant.
Why This Paper Is Relevant: It is a direct affected-version / SZZ-family baseline source for understanding how bug-introducing commits are identified from bug-fixing commits, including no-deletion and deletion scenarios.
Citation Metadata Status: paper title/authors/venue/year extracted from PDF text; DOI/BibTeX not verified. [NEEDS CITATION VERIFICATION]
Missing Evidence: precise table repair, precise figure extraction, official citation metadata, local dataset/result directories advertised by README, executed reproducibility.
""",
"01_abstract.txt": common + """Problem: Existing SZZ variants identify bug-inducing commits from bug-fixing commits, but struggle when a bug-fixing commit has no deleted lines.
Gap: Prior approaches that trace all lines in a block around added lines are framed as too coarse-grained and low precision.
Core Idea: SEM-SZZ narrows the search by using fine-grained semantic analysis near added lines.
Method: The abstract states a pipeline of program slicing, state comparison between previous/current versions, data-flow/control-flow difference analysis, buggy-statement extraction, and tracing those statements to bug-inducing commits.
Evaluation Setup: The abstract claims experiments compare SEM-SZZ with state-of-the-art methods for both no-deletion and deletion bug-fixing commits; exact table values require table repair before citation-ready use. [NEEDS TABLE REPAIR]
Main Results: The abstract says SEM-SZZ outperforms state-of-the-art methods; exact numeric claims must be verified against repaired tables. [NEEDS TABLE REPAIR]
Contribution Wording: The paper positions the contribution as a semantic refinement of SZZ, not as a new vulnerability-version system.
Limitations or Scope Boundaries: The abstract does not disclose detailed limitations; discussion section later describes failure cases.
Reusable Writing Pattern: Start from a concrete blind spot in prior algorithms, introduce an observation, then justify a more precise semantic analysis layer.
Relevance to Our Paper: Useful as a baseline-analysis model for affected versions work, especially when explaining why commit-level origin tracing is not equivalent to complete affected-version recovery.
Do Not Borrow: Do not copy the outperformance claim for our system without our own evidence; use only as related-work/baseline context.
Agent Evidence Anchors: raw_extraction/section_text/01_abstract.txt; raw_extraction/source_static_inventory.txt.
""",
"02_introduction.txt": common + """Opening Context: The introduction begins from modern software evolution as a sequence of commits and the need to identify bug-inducing commits.
Why the Problem Matters: Bug-inducing commit identification supports defect/vulnerability lifecycle analysis, but false positives in SZZ-style tracing weaken downstream conclusions.
Concrete Pain Point: The paper highlights bug-fixing commits that only add lines; deletion-based blame cannot directly identify candidate bug-inducing lines.
Motivating Example: The introduction previews that nearby unmodified lines around additions often expose bug-inducing commits, but whole-block tracing is too coarse.
Prior Work Framing: It references SZZ and variants, then separates previous added-line handling from the proposed finer semantic comparison.
Why Prior Work Is Insufficient: The paper argues block-level tracing around additions improves recall but introduces noise, motivating data-flow/control-flow comparison.
Technical Challenges: The method must decide which surrounding statements actually contribute to the bug and must avoid broad search scopes that add irrelevant statements.
Key Insight: The closest useful evidence is not necessarily the added line itself, but statements whose program states differ when comparing fixed and previous versions.
System / Method Preview: Program slicing isolates nearby relevant basic blocks; state collection records variable data flow and path constraints; state comparison finds changed semantic evidence; line tracing locates bug-inducing commits.
Contribution List: The introduction states a new approach for pointing out bug-related statements and claims experimental outperformance. Numeric contribution claims require table repair. [NEEDS TABLE REPAIR]
Claim-Evidence Structure: Motivation observation -> semantic method -> experiments over added-line/deleted-line datasets -> discussion and failure analysis.
Agent Evidence Anchors: raw_extraction/section_text/02_introduction.txt; raw_extraction/figures/figure_001_caption.txt; raw_extraction/tables/table_index.txt.
Paragraph Map:
P1-P2: software evolution and SZZ context; evidence type is related-work framing.
P3-P5: added-line no-deletion pain point; evidence type is problem framing.
P6-P9: observations around nearby unmodified lines and SEM-SZZ preview; evidence type is method motivation.
P10-P12: RQs/evaluation claims; evidence type is table-backed but not citation-ready. [NEEDS TABLE REPAIR]
Reusable Moves: Define a narrow algorithmic failure mode before presenting the new method; convert observations into method stages.
Risks for Our Paper: Do not imply SEM-SZZ solves affected-version identification end-to-end; it targets bug-inducing commit identification.
""",
"03_background_motivation.txt": common + """Domain Concepts Introduced: SZZ algorithm, bug-fixing commit, bug-inducing commit, added/deleted lines, unmodified neighboring lines, basic blocks, program slicing.
Task Definition: Given bug-fixing commit evidence, identify commits that introduced the bug; the paper handles cases with only added lines and extends to deleted-line cases.
Threat Model / Assumptions: Not a security threat model; the paper assumes source-code history, fix commits, and line-level/semantic code evidence are available.
Motivating Case: Figure 1 is used as a motivation example, but figure precision requires figure extraction. [NEEDS FIGURE EXTRACTION]
Why the Case Is Chosen: The paper uses it to show that the added line itself is not always traceable, while nearby unmodified statements can reveal the origin.
Definitions Needed by Readers: Commit categories, bug-inducing vs bug-fixing relationship, slicing criterion, path constraints, variable data flow.
How Background Leads to Method: The motivation derives three observations: nearby unmodified lines help, whole-block tracing is noisy, and semantic comparison should narrow candidates.
Writing Pattern: Use a concrete code example to justify method granularity; then state observations that directly become pipeline stages.
Relevance to Our Paper: Useful for explaining limitations of naive affected-version propagation from fixes and why semantic provenance matters.
Agent Evidence Anchors: raw_extraction/section_text/03_motivation.txt; raw_extraction/figures/figure_001_caption.txt.
""",
"04_problem_definition.txt": common + """Input: A bug-fixing commit and repository history; for source implementation, README and scripts imply datasets and generated result files are expected but local dataset/result directories are absent. [NEEDS ARTIFACT]
Output: Bug-inducing commit candidates, based on traced buggy statements.
Objects / Entities: bug-fixing commit, added lines, deleted lines, unmodified neighboring lines, basic block, control flow graph, execution path, variable data flow, path constraints, buggy statement, bug-inducing commit.
Formal Definitions: The paper gives formula-style metric definitions for precision/recall/F1 in the experiment setting; formula layout is not repaired. [NEEDS FORMULA REPAIR]
Objective: Improve precision/F1 of bug-inducing commit identification while preserving useful recall in added-line and deleted-line settings.
Constraints: Requires source history and static code parsing; README mentions tree-sitter and Joern environment requirements, but execution was not requested. [EXECUTION NOT REQUESTED]
Evaluation Target: Performance against SZZ variants/baselines on DATASET-A, DATASET-FA, and DATASET-D as stated by the paper/README; local datasets not verified. [NEEDS ARTIFACT]
Boundary Conditions: The discussion states failures where line similarity misjudges semantics or buggy statements are not correctly identified.
What Is Not Solved: It does not claim to identify affected versions directly; it does not solve cases where the fix changes only non-function regions or where tracing changed functions still cannot find the origin. [PAPER-ONLY]
Reusable Formalization Pattern: Define the code-history task through input/output and then isolate the narrow class of commits the method can handle.
""",
"05_method.txt": common + """System Overview: SEM-SZZ is presented as a semantic-analysis SZZ pipeline that uses local slicing around added lines, state collection, state comparison, buggy-statement selection, and bug-inducing commit localization.
Pipeline Stages:
1. Extract function/basic blocks around added lines.
2. Build a control-flow graph and perform bounded DFS over N predecessor/successor basic blocks.
3. Collect execution paths and program states.
4. Compare current/fixed and previous/buggy program states, focusing on path constraints and data flow.
5. Select statements contributing to the bug.
6. Trace those statements to earliest commits containing them.
Core Algorithm: Algorithm 1 collects program state by adding branch statements to path constraints and appending expression statements to variable data flow. Algorithm layout is text-extracted but not repaired. [NEEDS ALGORITHM REPAIR]
Data Structures: Program state as path constraints plus variable data-flow lists; CFG/basic blocks; source inventory shows CFG.py contains Basic_block and CFG classes.
Model / Agent Components: No LLM/agent method is described in the paper. Local source has 5_parse_result_llm_conservative.py, but that appears to be local adaptation/processing and is not used to infer paper method behavior. [NEEDS EVIDENCE]
Design Choices: Basic-block slicing is chosen over variable-only slicing to reduce noise and cost; N controls the search radius.
Why Each Choice Is Needed: The paper argues local semantic comparison narrows candidates better than tracing entire blocks.
Failure Handling: Discussion identifies failure modes from line similarity and incorrect buggy-statement selection.
Complexity / Cost Discussion: The paper reports time-efficiency discussion and impact of N; exact values require figure/table repair. [NEEDS FIGURE EXTRACTION]
Pseudocode or Algorithm Blocks: Algorithm 1 is extracted from page text; not citation-ready. [NEEDS ALGORITHM REPAIR]
Static Reproducibility Signals: README maps files to CFG construction, patch parsing, result generation, baseline generation, and utility functions. source_static_symbols.json confirms static function/class surfaces.
Agent Evidence Anchors: raw_extraction/section_text/04_approach.txt; raw_extraction/source_static_inventory.txt; raw_extraction/source_static_symbols.json.
Writing Pattern: Present observations first, then map each observation to a concrete pipeline component.
""",
"06_experiments.txt": common + """Research Questions: RQ1 evaluates added-line/no-deletion bug-fixing commits; RQ2 evaluates deleted-line bug-fixing commits; RQ3 evaluates ablation/design choices; discussion studies failure and parameter sensitivity.
Datasets: The paper names DATASET-A, DATASET-FA, and DATASET-D. README says dataset files should exist in a dataset directory, but the observed local source root does not contain that directory. [NEEDS ARTIFACT]
Baselines: The paper compares added-line variants such as A-SZZ/AB-SZZ/AAG-SZZ/AMA-SZZ/AR-SZZ/AL-SZZ and deletion-line SZZ baselines. Exact baseline table values need repair. [NEEDS TABLE REPAIR]
Metrics: Precision, recall, F1-score; formula text extracted but layout may be damaged. [NEEDS FORMULA REPAIR]
Experimental Protocol: Paper states multiple datasets and baselines; README gives scripts for pre-calculated results, baseline generation, SEM-SZZ result generation, ablation, and discussion.
Implementation Details: README lists CFG.py, parse_patch.py, util.py, result generation scripts, baseline scripts, and requirements; source inventory confirms these files exist.
Hyperparameters / Settings: Maximum search step N is discussed and varied in discussion; exact curve/values require figure/table repair. [NEEDS FIGURE EXTRACTION]
Hardware / Environment: Paper text mentions experiment setting; README requires packages and Joern. Environment not reproduced. [EXECUTION NOT REQUESTED]
Static Reproducibility Materials: Source files and requirements are present; local datasets/result directories advertised by README are missing under the observed root. [NEEDS ARTIFACT]
Execution Status: [EXECUTION NOT REQUESTED]
What Is Measured: bug-inducing commit identification precision/recall/F1, ablations, time/parameter sensitivity.
What Is Not Measured: affected versions as a full version-range task; runtime reproducibility in this analysis.
Agent Evidence Anchors: raw_extraction/section_text/05_experiment_setting_and_baselines.txt; raw_extraction/section_text/06_experiment.txt; raw_extraction/tables/table_index.txt; raw_extraction/source_static_inventory.txt.
Writing Pattern: Define RQs before tables; use filtered datasets to separate method applicability from noisy cases.
""",
"07_evaluation.txt": common + """Main Results: The paper reports SEM-SZZ improves precision/F1 over baselines for added-line and deletion-line scenarios; exact numbers are visible in raw table text but not citation-ready. [NEEDS TABLE REPAIR]
Per-RQ Findings: RQ1 claims better precision and F1 on DATASET-A/DATASET-FA; RQ2 claims effectiveness for deleted-line commits; RQ3 reports ablation effects from data-flow/control-flow/slicing components.
Ablation: README exposes ablation.py and the paper discusses key designs, but local execution was not requested. [EXECUTION NOT REQUESTED]
Sensitivity Analysis: Discussion varies maximum search step N from 1 to 5 and describes limited time impact with best effectiveness around N=3; exact figure values require extraction. [NEEDS FIGURE EXTRACTION]
Case Study: The paper includes failure examples and program-slicing examples with commit IDs/figures; figures require extraction before visual reuse. [NEEDS FIGURE EXTRACTION]
Efficiency: Introduction/discussion report approximate per-case handling time and N impact; exact timing needs table/figure repair and citation verification. [NEEDS TABLE REPAIR]
Error Analysis: Discussion identifies two major failure classes: line similarity confusing semantically different short statements, and failure to point out correct buggy statements when the added line influences variables not causally tied to the bug.
Statistical / Validity Notes: Threats-to-validity text was not isolated as a separate heading in extraction; related limitations are represented in discussion/conclusion. [NEEDS EVIDENCE]
How Claims Are Supported: Mostly tables/figures/RQ summaries in the paper plus README static artifacts; not supported by local rerun. [EXECUTION NOT REQUESTED]
Unsupported or Weakly Supported Claims: Any exact numeric result, artifact completeness, and reproduced performance claim remain unsupported until table repair and artifact/data verification.
Agent Evidence Anchors: raw_extraction/section_text/06_experiment.txt; raw_extraction/section_text/07_discussion.txt; raw_extraction/tables/; raw_extraction/figures/.
Writing Pattern: Use RQ summaries after detailed table discussion; include failure analysis instead of only positive results.
""",
"08_limitations_ethics.txt": common + """Stated Limitations: The discussion states failures from line-similarity mismatch and incorrect buggy-statement selection. The paper also notes categories of commits outside the method's design scope.
Threats to Validity: A separate threats-to-validity heading was not cleanly extracted; any formal validity taxonomy requires manual verification. [NEEDS EVIDENCE]
Ethical Considerations: No explicit ethics/security misuse section was detected in the extracted text. [NEEDS EVIDENCE]
Security / Misuse Discussion: The paper is software-engineering/SZZ focused rather than exploit-oriented; no misuse discussion was detected. [NEEDS EVIDENCE]
Responsible Disclosure: Not applicable/detected. [NEEDS EVIDENCE]
Scope Boundaries: Not designed for all no-deletion commits; paper says some commits with no function changes or untraceable changed functions cannot be handled by the approach/baselines.
Writing Pattern: The strongest reusable pattern is an engineering failure taxonomy tied back to concrete cases, not a generic limitations paragraph.
Relevance to Our Paper: For affected versions, this paper is a useful warning that line-level provenance can fail even before version-range propagation begins.
""",
"09_figures_tables.txt": common + """Figure / Table Inventory:
- Figures detected: caption/context records plus page crops for some caption pages. They are not precise figure crops. [NEEDS FIGURE EXTRACTION]
- Tables detected: caption-neighbor/plain-text table records with empty structured cell JSON. Not citation-ready. [NEEDS TABLE REPAIR]

For each figure/table:
ID: see raw_extraction/figures/figure_index.txt and raw_extraction/tables/table_index.txt
Agent Evidence Unit ID: generated by build_agent_index.py from raw_extraction/figures and raw_extraction/tables.
Purpose: motivation example, method overview, slicing/state-comparison examples, result tables, parameter/time discussion.
Evidence Shown: qualitative and quantitative evidence as stated by captions/context; exact values need repair.
Placement in Argument: motivation -> method architecture -> RQ evidence -> failure/sensitivity discussion.
Extraction Confidence: partial.
Repair Needed: [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]; [NEEDS LAYOUT BLOCK EXTRACTION]
Citation Readiness: low for tables because cells/CSV are not verified.
Figure Readiness: low/partial because page crops are not precise figure crops.
Design Pattern: Pair an architecture overview with small code examples and RQ result tables.
Could Inspire Our Paper? yes, structurally; no, for copied visuals or numeric claims without repaired evidence.
Required Figures for Our Paper: [NEEDS EVIDENCE] depends on our own verified system/results.
""",
"10_writing_patterns.txt": common + """Best Structural Moves:
- Start from a known algorithm family, isolate a specific failure mode, then build a method around observations.
- Use an example before formal pipeline details.
- Pair each method component with the observation it addresses.
- Include failure analysis and parameter sensitivity after main results.

Best Transition Moves:
- Problem with added-line commits -> observation about nearby unmodified lines -> semantic comparison -> bounded slicing.
- Broad SZZ history -> new baseline variants -> proposed method evaluation.

Best Contribution Wording Pattern:
- "We observe X; based on this observation, we design Y; experiments show Z." Use only as structure, not as copied wording.

Best Method Overview Pattern:
- Overview figure first, then subsections for slicing, state collection, state comparison, locating commits, and extension to deleted-line scenarios.

Best Experiment Framing Pattern:
- RQs map directly to applicability cases: no-deletion, deleted-line, ablation, efficiency/sensitivity.

Useful Phrases to Paraphrase Structurally:
- coarse-grained tracing vs fine-grained semantic analysis
- state comparison between previous and current versions
- bounded search around added lines

Patterns to Avoid:
- Do not overclaim reproduced results without execution.
- Do not import their bug-inducing commit framing as affected-version identification.
- Do not cite exact numbers until tables are repaired and verified.
""",
"11_relevance_to_our_paper.txt": common + """Direct Relevance: High for baseline/context around SZZ-style bug-inducing commit identification, especially when comparing affected-version identification against origin-commit localization.
Indirect Relevance: Method design shows how semantic evidence can improve line/commit provenance, which may inform verifier or evidence-selection components.
Useful for Which Section: Related work, baseline comparison, motivation for semantic evidence, limitations of SZZ-derived affected-version inference.
Comparable Task Elements: Fix commit -> candidate origin evidence; static code history; precision/recall/F1 evaluation.
Comparable Method Elements: slicing, control/data-flow comparison, bounded search, statement-to-commit tracing.
Comparable Evaluation Elements: RQs, datasets by commit type, ablation, failure analysis.
What We Can Borrow Structurally: RQ framing, failure taxonomy style, observation-to-stage method narrative.
What We Cannot Borrow: Exact claims, tables, figures, datasets, implementation behavior, or affected-version conclusions without our own evidence.
Evidence Needed Before Use: repaired tables, verified citations, clear distinction from affected-version task, and our own experimental comparison.
Priority: high
""",
"12_artifact_consistency.txt": common + """Paper Claims:
- SEM-SZZ uses slicing, control/data-flow state comparison, and statement tracing to identify bug-inducing commits.
- Experiments compare against SZZ-family baselines and report improvements.

Implemented Components:
- README maps CFG.py to control-flow graph construction.
- parse_patch.py is documented as extracting added/deleted lines and line numbers.
- util.py is documented as containing data-flow/path-constraint classes plus program slicing, state collection, and commit localization utilities.
- gen_results_for_no_dels.py and gen_results_for_dels.py are documented as SEM-SZZ result-generation scripts.
- gen_baseline_results_for_no_deletes.py and gen_baseline_results_for_dels.py are documented as baseline result-generation scripts.
- source_static_symbols.json statically confirms CFG classes and multiple utility/entrypoint functions.

Unimplemented or Stubbed Components: [NEEDS EVIDENCE] static inventory did not classify stubs exhaustively.
Dataset Availability: README mentions dataset/result/DelBaselines/NoDelBaselines directories, but the observed local source root contains only code-like files, core/, tmp/, requirements, README, and time.txt. [NEEDS ARTIFACT]
Benchmark / Evaluation Scripts Visible by Static Inspection: yes, baseline/result/ablation/discussion scripts are present by filename and README description.
Static Reproduction Instructions or Missing Instructions: README includes commands, but dependency installation, Joern setup, and execution were not performed. [EXECUTION NOT REQUESTED]
Config Files: requirements.txt and constant.py are present; exact environment viability unverified.
Environment Constraints: README requires Joern and Python packages; requirements is a captured environment list.
Paper-Code Mismatches:
- README title/status says submitted to TSE while PDF is published in TSE 2024; this may reflect artifact README staleness.
- README refers to datasets/results directories not present in the observed local source root. [NEEDS ARTIFACT]
- README uses SEMA-SZZ spelling in two file descriptions, while paper title/method uses SEM-SZZ; likely naming inconsistency, not enough evidence for semantic difference. [NEEDS EVIDENCE]
Engineering Lessons for Our Paper: Keep artifact directories, scripts, and paper claims aligned; write static manifest files that make dataset/result availability explicit.

Consistency Check:
Claim: SEM-SZZ uses CFG/program slicing/state comparison.
Paper Location: method section.
Artifact Evidence: CFG.py, util.py, parse_patch.py named in README and symbol inventory.
Source Evidence: raw_extraction/source_static_inventory.txt; raw_extraction/source_static_symbols.json.
Consistency: partially supported by static inspection.
Analysis Mode: static-only.
Use in Our Paper: with caution.

Claim: reported performance improvements.
Paper Location: experiment section/tables.
Artifact Evidence: result scripts visible, but datasets/results not verified.
Source Evidence: README command list.
Consistency: unclear for reproduction.
Analysis Mode: static-only.
Use in Our Paper: no exact numeric reuse until table/artifact verification.
""",
"13_completeness_audit.txt": common + """Raw Extraction:
- PDF text extracted: yes
- Page text extracted: yes, page count 16
- Section text extracted: yes, section file count 10
- Agent index exists: yes after build_agent_index.py; initially regenerated in final gate
- Extraction profile exists: yes after build_agent_index.py
- Layout blocks extracted: missing/not attempted
- References extracted: yes, citation metadata unverified
- Table extraction: caption-neighbor/plain-text only; not citation-ready
- Figure extraction: caption/context plus page crops for detected captions; not precise figure-ready
- Formula/algorithm/prompt extraction: formula/algorithm partial or not repaired; prompt not detected/not applicable
- OCR needed: no

Section Analysis:
- 00_meta.txt through 12_artifact_consistency.txt: complete
- Are analysis files section-oriented enough for writing? yes, with repair labels on weak evidence

Source / Artifact Static Analysis:
- Source inventory exists: yes
- README/config inspected: yes
- Main entrypoints inspected: yes, by filename/README/AST symbol inventory
- Runtime behavior: [EXECUTION NOT REQUESTED]

Writing Readiness:
- Abstract support: strong
- Introduction support: strong
- Background/motivation support: strong
- Method support: strong for paper-level claims; partial for implementation behavior
- Experiment/evaluation support: partial because exact tables/data/results need repair/artifacts
- Limitations support: partial
- Related work support: partial

Known Gaps:
- [NEEDS TABLE REPAIR]
- [NEEDS FIGURE EXTRACTION]
- [NEEDS LAYOUT BLOCK EXTRACTION]
- [NEEDS FORMULA REPAIR]
- [NEEDS ALGORITHM REPAIR]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade: high, because the paper text and static source inventory are sufficient for baseline positioning and method comparison, while quantitative reuse remains gated by table/artifact repair.
""",
"14_section_retrieval_map.txt": common + """For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/02_introduction.txt
- Useful claims: added-line SZZ failure mode; nearby unmodified-line motivation.
- Must not claim: affected-version coverage or our-system results.

For Background / Motivation:
- Read analysis/03_background_motivation.txt
- Read raw_extraction/section_text/03_motivation.txt
- Useful claims: SZZ task entities and motivation example structure.
- Must not claim: visual details from figures until repaired.

For Method:
- Read analysis/05_method.txt
- Read raw_extraction/section_text/04_approach.txt
- Read raw_extraction/source_static_inventory.txt
- Useful claims: slicing/state-comparison pipeline as paper-level baseline mechanism.
- Must not claim: runtime behavior from local code. [EXECUTION NOT REQUESTED]

For Experiments / Evaluation:
- Read analysis/06_experiments.txt and analysis/07_evaluation.txt
- Read raw_extraction/section_text/05_experiment_setting_and_baselines.txt and 06_experiment.txt
- Useful claims: RQ structure, dataset names, metric framing.
- Must not claim: exact numeric values until tables are repaired. [NEEDS TABLE REPAIR]

For Limitations:
- Read analysis/08_limitations_ethics.txt
- Read raw_extraction/section_text/07_discussion.txt
- Useful claims: line-similarity and buggy-statement-selection failure modes.
- Must not claim: formal threats-to-validity taxonomy unless manually verified. [NEEDS EVIDENCE]

For Related Work:
- Read analysis/11_relevance_to_our_paper.txt
- Read raw_extraction/section_text/08_related_work.txt
- Useful claims: SEM-SZZ as SZZ-family baseline context.
- Must not claim: citation metadata without verification. [NEEDS CITATION VERIFICATION]
""",
}

for name, text in files.items():
    (ANALYSIS / name).write_text(text, encoding="utf-8")
