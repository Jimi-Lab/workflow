from pathlib import Path

ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference\p03_how_long_do_vulnerabilities_live_2021")
AN = ROOT / "analysis"
RAW = ROOT / "raw_extraction"
PAPER_ID = "p03_how_long_do_vulnerabilities_live_2021"
PDF = r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\Lifetime\How Long Do Vulnerabilities Live in the Code？A Large-Scale Empirical Measurement Study on FOSS Vulnerability Lifetimes.pdf"
SRC = r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\Lifetime\Lifetime"


def w(name: str, text: str) -> None:
    (AN / name).write_text(text.strip() + "\n", encoding="utf-8", newline="\n")


w("00_meta.txt", f"""
Paper ID: p03_how_long_do_vulnerabilities_live_2021
Title: How Long Do Vulnerabilities Live in the Code? A Large-Scale Empirical Measurement Study on FOSS Vulnerability Lifetimes
Venue / Year: [NEEDS CITATION VERIFICATION] / 2021
Authors: Nikolaos Alexopoulos; Manuel Brack; Jan Philipp Wagner; Tim Grube; Max Mühlhäuser
Artifact Type: Type A
Input Files:
- PDF: {PDF}
- Source/artifact directory: {SRC}
Source / Artifact Path: {SRC}
Analysis Status: complete for text-layer and static-source pass; layout/table/figure repair remains open.
Agent Index Status: partial agent package; build_agent_index.py still must be run as requested.
Main Topic: empirical measurement of vulnerability lifetimes in FOSS repositories.
Why This Paper Is Relevant: It studies when vulnerabilities are introduced and fixed, and it provides a baseline style for reasoning about affected versions and vulnerability lifetime evidence.
Citation Metadata Status: [NEEDS CITATION VERIFICATION]
Missing Evidence: [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]; [NEEDS LAYOUT BLOCK EXTRACTION]; [NEEDS ARTIFACT]; [EXECUTION NOT REQUESTED]
""")

w("01_abstract.txt", """
Problem: The paper asks how long vulnerabilities remain in source repositories before they are fixed.
Gap: Prior work is described as relying mostly on lower-bound estimates or smaller-scale/manual evidence; exact introduction points are hard to identify.
Core Idea: Estimate lifetimes at scale using a heuristic approach rather than requiring perfectly identified introduction commits for every vulnerability.
Method: The abstract frames the method as automatic lifetime estimation over a large sample of FOSS vulnerabilities.
Evaluation Setup: FOSS projects are measured at scale; exact project list and numeric results require table repair before citation-ready reuse.
Main Results: The text layer states an average lifetime around four years, project variation, approximate exponential lifetime distribution, and no significant differences among vulnerability types within projects. Exact values need table repair.
Contribution Wording: The abstract uses a first-large-scale-measurement framing and explicitly contrasts with lower-bound-only approaches.
Limitations or Scope Boundaries: Fuzzer impact is not resolved strongly; the abstract says further research is needed.
Reusable Writing Pattern: Open with a direct measurable research question, explain why exact ground truth is hard, then justify a scalable estimator and summarize empirical findings.
Relevance to Our Paper: Useful for motivating affected versions as an empirical security measurement task and for showing why introduction/fix evidence is hard.
Do Not Borrow: Do not borrow its lifetime results as evidence for our system without citation verification and table repair.
""")

w("02_introduction.txt", """
Opening Context: Vulnerabilities are framed as exploitable software flaws; reducing their number is a primary security goal.
Why the Problem Matters: Vulnerability lifecycle measurements help assess security practices and tooling.
Concrete Pain Point: The introduction point of a vulnerability is hard to determine, which makes lifetime measurement difficult.
Motivating Example: The lifecycle figure separates introduction, finding, disclosure, fix, and host patching phases; the figure itself needs image extraction.
Prior Work Framing: The paper places itself among vulnerability lifecycle and measurement studies, then narrows to repository-level lifetime.
Why Prior Work Is Insufficient: Prior work is treated as not providing adequate depth and scale for source-code vulnerability lifetimes.
Technical Challenges: Linking CVEs to fixing commits, inferring vulnerability-contributing commits, and avoiding overclaiming exact per-vulnerability introduction dates.
Key Insight: A scalable heuristic can estimate average lifetime for a large enough sample even when individual exact introduction points are difficult.
System / Method Preview: Dataset creation, VCC linking, and lifetime estimation are introduced as the core pipeline.
Contribution List: [NEEDS CITATION VERIFICATION] The exact contribution list should be verified against the PDF layout before direct citation.
Claim-Evidence Structure: The introduction moves from lifecycle concept -> missing measurement -> feasibility of heuristic estimation -> large-scale empirical study.
Agent Evidence Anchors: raw_extraction/section_text/02_introduction.txt; raw_extraction/figures/figure_001_caption.txt
Paragraph Map:
P1: Function: define vulnerability/security-bug context. Main Claim: vulnerability reduction is central to security. Evidence Type: general field framing. Transition: moves to measurement studies.
P2: Function: define lifecycle/window of exposure. Main Claim: lifecycle phases contextualize repository lifetime. Evidence Type: figure and prior concept. Transition: focuses on Phase 1.
P3+: Function: motivate repository lifetime measurement. Main Claim: introduction time is difficult but important. Evidence Type: problem statement. Transition: leads to heuristic method.
Reusable Moves: Define lifecycle first, then isolate the phase your paper measures.
Risks for Our Paper: Our paper should not imply that affected versions and vulnerability lifetime are identical; use this paper as adjacent motivation, not task equivalence.
""")

w("03_background_motivation.txt", """
Domain Concepts Introduced: vulnerability lifecycle; window of exposure; vulnerability-contributing commit; fixing commit; CVE-to-commit mapping.
Task Definition: Estimate how long a vulnerability lives in a code repository, from introduction to fix.
Threat Model / Assumptions: The paper measures repository lifetime, not exploitability or complete deployment patch status.
Motivating Case: Fig. 1 lifecycle framing motivates why introduction and fix timestamps matter.
Why the Case Is Chosen: It makes a complex security lifecycle measurable in version-control terms.
Definitions Needed by Readers: t_int, t_f, t_d, t_fix, patched-host time; VCC; fix commit.
How Background Leads to Method: Once lifetime is reduced to repository events, the method can focus on linking CVEs, fixes, and inferred introduction points.
Writing Pattern: Define the lifecycle broadly, then narrow to the part that the dataset can actually observe.
Relevance to Our Paper: Good template for separating observable repository evidence from non-observable deployment/user exposure.
Agent Evidence Anchors: raw_extraction/section_text/03_background.txt
""")

w("04_problem_definition.txt", """
Input: CVE records and linked repository/fixing-commit evidence as stated by the paper; local artifact contains scripts and data files but completeness is not verified.
Output: Vulnerability lifetime estimates and aggregate empirical distributions.
Objects / Entities: CVE, fixing commit, vulnerability-contributing commit, project repository, vulnerability type/category, project release history [NEEDS EVIDENCE for release-specific use].
Formal Definitions: The PDF text defines lifetime conceptually through lifecycle timing; exact formal notation should be verified in the PDF. [NEEDS CITATION VERIFICATION]
Objective: Estimate vulnerability lifetimes at scale and analyze distribution, project differences, trends, code age, vulnerability types, and fuzzing impact.
Constraints: Exact introduction points are hard to know; heuristic estimates are used; ground-truth validation is limited.
Evaluation Target: Agreement with ground-truth samples and aggregate empirical findings across projects.
Boundary Conditions: Repository-level lifetime only; runtime exploitability, deployment exposure, and patch adoption are outside the static artifact pass.
What Is Not Solved: Full per-vulnerability ground truth, causal proof of fuzzer impact, and reproduction of results in this pass. [EXECUTION NOT REQUESTED]
Reusable Formalization Pattern: State observable repository endpoints, then label non-observable lifecycle phases as out of scope.
""")

w("05_method.txt", """
System Overview: The paper pipeline links CVEs to fixes, constructs or uses vulnerability-contributing commit evidence, and estimates lifetime distributions.
Pipeline Stages:
1. Dataset creation and project selection.
2. CVE-to-fixing-commit linkage.
3. Vulnerability-contributing commit inference or validation.
4. Lifetime estimation.
5. Aggregate analyses over distributions, trends, code age, types, and fuzzing.
Core Algorithm: The paper relies on a heuristic lifetime estimator; exact pseudo-code is not layout-extracted. [NEEDS ALGORITHM REPAIR]
Data Structures: Local source artifact shows JSON/text data and Python scripts: continue_added_block_cve_dict.json, bad_case_result.txt, affected_version, tmp, vccs_output.
Model / Agent Components: none in the reference paper.
Design Choices: The major design choice is aggregate heuristic estimation rather than exact manual per-CVE introduction recovery.
Why Each Choice Is Needed: Scalability: exact VCC identification is cumbersome; aggregate estimation can support large-scale measurement.
Failure Handling: Static source shows scripts for bad cases and continued blocks, but runtime failure behavior is not verified. [EXECUTION NOT REQUESTED]
Complexity / Cost Discussion: [NEEDS EVIDENCE] Not verified from extracted section text.
Pseudocode or Algorithm Blocks: [NEEDS ALGORITHM REPAIR]
Static Reproducibility Signals: local Python scripts exist: 1_lifetime.py, get_continue_block.py, 2_gen_vuln_version.py, log_generation.py, vul_lifetime_run.py, _core/abstract_szz.py, _core/comment_parser.py.
Agent Evidence Anchors: raw_extraction/section_text/04_method.txt; raw_extraction/source_static_inventory.txt
Writing Pattern: Method is grounded in dataset construction before estimator details, which helps readers trust later empirical claims.
""")

w("06_experiments.txt", """
Research Questions: The results section studies general lifetimes, distribution fit, time trends, code age, vulnerability types, and a fuzzing case study.
Datasets: FOSS project CVE/fix/VCC data as stated by the paper; exact list and counts need table repair before citation-ready use.
Baselines: Prior lower-bound estimation is the conceptual comparison; exact baseline configuration is [NEEDS EVIDENCE].
Metrics: lifetime in days/years; distribution fit; project-level averages; type-level comparisons; statistical significance statements need citation verification.
Experimental Protocol: Empirical measurement over linked CVE/repository data; source-code execution was not requested.
Implementation Details: Local static code imports GitPython/git, unidiff, subprocess, JSON, and custom SZZ/comment parsing modules.
Hyperparameters / Settings: [NEEDS EVIDENCE]
Hardware / Environment: [NEEDS EVIDENCE]
Static Reproducibility Materials: source scripts and data/output folders are present; README is minimal.
Execution Status: [EXECUTION NOT REQUESTED]
What Is Measured: vulnerability lifetime distributions and related empirical trends.
What Is Not Measured: runtime reproducibility in this pass, deployment patching, exploitability, and exact affected versions for every release.
Agent Evidence Anchors: raw_extraction/section_text/05_experiments.txt; raw_extraction/source_static_inventory.txt
Writing Pattern: Organize evaluation around empirical questions instead of only tool accuracy.
""")

w("07_evaluation.txt", """
Main Results: Text extraction supports claims about multi-year average vulnerability lifetime, project-level variation, approximate exponential distribution, code-age relationship, type-level comparisons, and inconclusive fuzzer effect. Exact values are not citation-ready.
Per-RQ Findings: The section structure suggests separate findings for general lifetime, distribution, temporal trends, code age, types, and fuzzing.
Ablation: [NEEDS EVIDENCE]
Sensitivity Analysis: [NEEDS EVIDENCE]
Case Study: Fuzzing impact is treated as a case-study-style analysis; conclusion is cautious rather than strongly causal.
Efficiency: [NEEDS EVIDENCE]
Error Analysis: Ground-truth and heuristic comparison is visible in figure caption/context; exact details need figure/table repair.
Statistical / Validity Notes: The text layer mentions statistical significance for type differences and distribution comparisons; verify exact tests/values before reuse. [NEEDS TABLE REPAIR]
How Claims Are Supported: Through aggregate tables/figures and discussion sections, but current extraction is not table/figure ready.
Unsupported or Weakly Supported Claims: Any exact numeric claim, table-derived comparison, or figure-derived trend is weak until repair.
Agent Evidence Anchors: raw_extraction/section_text/05_experiments.txt; raw_extraction/section_text/06_evaluation.txt; raw_extraction/tables/table_index.txt; raw_extraction/figures/figure_index.txt
Writing Pattern: Strong empirical papers state the main aggregate result first, then qualify it with project variation, distribution shape, and validity threats.
""")

w("08_limitations_ethics.txt", """
Stated Limitations: Threats to validity are a separate section. The text layer supports concerns around dataset construction, mappings, heuristic estimation, and external validity, but exact wording should be verified.
Threats to Validity: CVE-to-fix mapping, VCC inference, project selection, and measurement assumptions are the likely threat families from the extracted structure.
Ethical Considerations: [NEEDS EVIDENCE]
Security / Misuse Discussion: The paper is measurement-focused; no misuse analysis was confirmed in this pass. [NEEDS EVIDENCE]
Responsible Disclosure: [NEEDS EVIDENCE]
Scope Boundaries: repository lifetime measurement, not deployment exposure or runtime exploitability.
Writing Pattern: The limitations section should explicitly bind empirical claims to observable repository evidence.
Relevance to Our Paper: Useful model for distinguishing affected versions evidence from broader real-world exposure claims.
""")

w("09_figures_tables.txt", """
Figure / Table Inventory:
ID: figure_001
Agent Evidence Unit ID: p03_how_long_do_vulnerabilities_live_2021:figure:figure_001
Purpose: compare heuristic and ground-truth lifetime trend evidence.
Evidence Shown: caption/context only.
Placement in Argument: method validation / empirical trend support.
Extraction Confidence: partial
Repair Needed: [NEEDS FIGURE EXTRACTION]
Citation Readiness: low
Figure Readiness: no
Design Pattern: use a validation figure to justify a heuristic estimator.
Could Inspire Our Paper? yes, structurally.

ID: table_001 through table_004
Agent Evidence Unit IDs: p03_how_long_do_vulnerabilities_live_2021:table:table_001 ... table_004
Purpose: project averages, distribution-fit comparisons, vulnerability category summaries.
Evidence Shown: caption/context only.
Placement in Argument: main empirical evidence.
Extraction Confidence: partial
Repair Needed: [NEEDS TABLE REPAIR]
Citation Readiness: low
Figure Readiness: not applicable
Design Pattern: present aggregate measurement by project/category before deeper interpretation.
Could Inspire Our Paper? yes, but exact numeric reuse requires repair.

Required Figures for Our Paper: affected versions pipeline figure; evidence coverage/verification figure; per-family or per-project affected-version result table. [NEEDS EVIDENCE from our project]
""")

w("10_writing_patterns.txt", """
Best Structural Moves:
- Start from a direct empirical question.
- Separate lifecycle concept from the narrower repository-level measurement.
- Present dataset construction before estimator claims.
- Report headline aggregate result, then project variation and validity limits.

Best Transition Moves:
- From security goal to lifecycle measurement.
- From exact VCC difficulty to scalable heuristic estimation.
- From aggregate lifetime results to implications and threats.

Best Contribution Wording Pattern:
- "We provide a large-scale empirical measurement of X using Y evidence, while explicitly qualifying Z uncertainty."

Best Method Overview Pattern:
- Dataset creation -> evidence linking -> estimator -> validation/check -> empirical analyses.

Best Experiment Framing Pattern:
- Use research-question-like subsections: general result, distribution, trend, code age, type, case study.

Useful Phrases to Paraphrase Structurally:
- Direct question headline.
- "Going beyond lower bounds" as a contrast pattern.
- "Further research is needed" as a cautious causal boundary.

Patterns to Avoid:
- Do not overstate heuristic estimates as exact per-case ground truth.
- Do not reuse numeric results without table repair and citation verification.
""")

w("11_relevance_to_our_paper.txt", """
Direct Relevance: Adjacent to affected versions because both need repository history, fix evidence, and reasoning about when vulnerable code exists.
Indirect Relevance: Strong model for empirical measurement framing and validity threats.
Useful for Which Section: Introduction, Background, Evaluation, Limitations.
Comparable Task Elements: CVE/fix linking; historical code reasoning; VCC/lifetime estimation; project-level aggregation.
Comparable Method Elements: heuristic estimation and static repository evidence; local artifact scripts suggest SZZ-like tracing and version generation.
Comparable Evaluation Elements: project-level summaries, distribution/trend analysis, category analysis.
What We Can Borrow Structurally: question-driven introduction; lifecycle framing; table design for per-project results; cautious validity section.
What We Cannot Borrow: lifetime numeric results as our system evidence; causal fuzzer conclusions; implementation claims not verified by static source.
Evidence Needed Before Use: citation metadata, table repair, figure extraction, and mapping from this paper's lifetime task to our affected versions task.
Priority: high
""")

w("12_artifact_consistency.txt", """
Paper Claims: Large-scale vulnerability lifetime measurement over FOSS projects using CVE/fix/VCC-style evidence.
Implemented Components: Static source shows scripts for lifetime tracing, continued-block analysis, affected-version generation, logging, and SZZ/comment parsing support.
Unimplemented or Stubbed Components: [NEEDS EVIDENCE] Static inspection did not prove completeness of every paper stage.
Dataset Availability: Local JSON/text artifacts and directories exist, but complete dataset coverage is not verified. [NEEDS ARTIFACT]
Benchmark / Evaluation Scripts Visible by Static Inspection: Python scripts are visible, including vul_lifetime_run.py and 1_lifetime.py; no execution was performed.
Static Reproduction Instructions or Missing Instructions: README.md is minimal; dependency/environment instructions are incomplete. [NEEDS ARTIFACT]
Config Files: config.py is present but minimal.
Environment Constraints: imports include git/GitPython, unidiff, subprocess, JSON, and custom _core modules; exact dependency versions are [NEEDS EVIDENCE].
Paper-Code Mismatches: No hard mismatch proven statically; artifact completeness and result reproduction remain unverified. [EXECUTION NOT REQUESTED]
Engineering Lessons for Our Paper: Provide clear artifact manifests, exact command boundaries, and explicit static-vs-execution status to avoid ambiguity.

Consistency Check:
Claim: source/artifact supports lifetime and affected-version processing.
Paper Location: method/results text layer.
Artifact Evidence: file names and AST summaries in raw_extraction/source_static_inventory.txt.
Source Evidence: functions such as lifetime_trace, find_vcc, gen_vulnerable_version, git_log/git_diff helpers, and abstract_szz support.
Consistency: partially supported
Analysis Mode: static-only
Notes: static structure aligns with the topic, but no runtime reproduction was requested.
Use in Our Paper: with caution
""")

w("13_completeness_audit.txt", """
Raw Extraction:
- PDF text extracted: yes
- Page text extracted: yes, page count 18
- Section text extracted: yes, section file count 9, heuristic boundaries
- Agent index exists: yes
- Extraction profile exists: yes
- Layout blocks extracted: missing/not attempted
- References extracted: uncertain; reference section split needs repair
- Table extraction: caption/context-only
- Figure extraction: caption-only
- Formula/algorithm/prompt extraction: not attempted/not detected
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
- Related work support: partial

Known Gaps:
- [NEEDS TABLE REPAIR]
- [NEEDS FIGURE EXTRACTION]
- [NEEDS LAYOUT BLOCK EXTRACTION]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade: medium, because text-layer and static artifact evidence are useful for writing structure, but tables/figures/citations are not citation-ready.
""")

w("14_section_retrieval_map.txt", """
For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/02_introduction.txt
- Useful claims: lifecycle framing; difficulty of introduction-time measurement.
- Must not claim: exact affected versions performance.

For Background / Motivation:
- Read analysis/03_background_motivation.txt
- Read raw_extraction/section_text/03_background.txt
- Useful claims: repository lifetime vs broader window of exposure.
- Must not claim: deployment patching evidence.

For Method:
- Read analysis/05_method.txt
- Read raw_extraction/section_text/04_method.txt
- Read raw_extraction/source_static_inventory.txt
- Useful claims: dataset-to-estimator structure.
- Must not claim: reproduction completed.

For Experiments / Evaluation:
- Read analysis/06_experiments.txt and analysis/07_evaluation.txt
- Read raw_extraction/section_text/05_experiments.txt
- Read raw_extraction/tables/table_index.txt
- Useful claims: evaluation organization and table/figure design.
- Must not claim: exact numeric results until [NEEDS TABLE REPAIR] is resolved.

For Limitations:
- Read analysis/08_limitations_ethics.txt
- Read raw_extraction/section_text/08_limitations.txt
- Useful claims: validity-threat categories.
- Must not claim: ethics/responsible disclosure details without evidence.

For Related Work:
- Read analysis/03_background_motivation.txt and raw_extraction/section_text/07_related_work.txt
- Useful claims: vulnerability measurement positioning.
- Must not claim: verified citation metadata.
""")

print("analysis written")
