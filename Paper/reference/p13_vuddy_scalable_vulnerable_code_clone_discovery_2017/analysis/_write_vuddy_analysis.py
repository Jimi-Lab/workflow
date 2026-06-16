from pathlib import Path

ROOT = Path(r"E:\AI\Agent\workflow\Paper\reference\p13_vuddy_scalable_vulnerable_code_clone_discovery_2017")
AN = ROOT / "analysis"
PAPER_ID = "p13_vuddy_scalable_vulnerable_code_clone_discovery_2017"
PDF = r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\VUDDY\VUDDY：A Scalable Approach for Vulnerable Code Clone Discovery.pdf"
SRC = r"E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\VUDDY\VUDDY"


def w(name: str, text: str) -> None:
    (AN / name).write_text(text.strip() + "\n", encoding="utf-8", newline="\n")


w("00_meta.txt", f"""
Paper ID: p13_vuddy_scalable_vulnerable_code_clone_discovery_2017
Title: VUDDY: A Scalable Approach for Vulnerable Code Clone Discovery
Venue / Year: IEEE Symposium on Security and Privacy / 2017
Authors: Seulbae Kim; Seunghoon Woo; Heejo Lee; Hakjoo Oh
Artifact Type: Type A
Input Files:
- PDF: {PDF}
- Source/artifact directory: {SRC}
Source / Artifact Path: {SRC}
Analysis Status: complete for PDF text-layer and static-source pass; no runtime reproduction.
Agent Index Status: partial, with section/table/figure/formula/artifact evidence units.
Main Topic: scalable vulnerable code clone discovery using function-level abstraction, fingerprinting, and length-filtered hash lookup.
Why This Paper Is Relevant: It provides a code-clone-based baseline for finding vulnerable code reuse, adjacent to affected versions because vulnerable code presence and clone propagation can support version evidence.
Citation Metadata Status: DOI and venue extracted from PDF metadata, still [NEEDS CITATION VERIFICATION].
Missing Evidence: [NEEDS TABLE REPAIR]; [NEEDS FIGURE EXTRACTION]; [NEEDS LAYOUT BLOCK EXTRACTION]; [NEEDS FORMULA REPAIR]; [NEEDS ARTIFACT]; [EXECUTION NOT REQUESTED]
""")

w("01_abstract.txt", """
Problem: OSS growth causes vulnerable code clones to proliferate across projects, but many clone detection approaches do not scale to massive code bases or focus on vulnerability-specific matching.
Gap: Existing clone detectors are either too expensive at OSS scale or too generic for accurately identifying vulnerable clones.
Core Idea: VUDDY detects vulnerable code clones at function granularity using abstraction, normalization, fingerprinting, and length-filtered hash lookup.
Method: The abstract states function-level granularity, length filtering, and security-aware abstraction as the key design choices.
Evaluation Setup: The paper compares VUDDY with clone detection mechanisms and reports discovered vulnerabilities; exact numeric reuse requires table repair.
Main Results: The abstract states billion-line preprocessing and quick clone detection plus zero-day findings; exact values need table and citation verification.
Contribution Wording: The paper frames VUDDY as scalable and vulnerability-aware, not only as a general clone detector.
Limitations or Scope Boundaries: It primarily targets Type-1/Type-2-like function-level vulnerable clones and preserves security-sensitive constants/order; broader semantic clones are out of scope.
Reusable Writing Pattern: Start from ecosystem scale, connect code reuse to vulnerability propagation, then justify a narrower representation that makes the task tractable.
Relevance to Our Paper: Useful for background on vulnerable code presence and clone-based evidence, but not a direct affected versions solver.
Do Not Borrow: Do not treat clone detection outputs as verified affected versions without release/tag-level validation.
""")

w("02_introduction.txt", """
Opening Context: OSS growth and code cloning are introduced as coupled trends that increase vulnerability propagation risk.
Why the Problem Matters: Vulnerable clones can contaminate many systems and remain difficult for developers to manage at scale.
Concrete Pain Point: Generic clone detectors are not optimized for vulnerable code clone discovery and often fail scalability or security-specific accuracy needs.
Motivating Example: The paper motivates copied vulnerabilities and later uses case studies; figure extraction is needed for visual reuse.
Prior Work Framing: Prior clone detection is framed as mature but often not scalable or vulnerability-aware enough for massive OSS.
Why Prior Work Is Insufficient: The introduction emphasizes scalability barriers and mismatch between generic clone detection and vulnerable clone detection.
Technical Challenges: Large OSS corpora, clone variants, preserving vulnerability-triggering conditions, minimizing false positives, and fast lookup.
Key Insight: Function-level fingerprints combined with security-aware abstraction can reduce search cost while preserving vulnerability-relevant structure.
System / Method Preview: VUDDY preprocesses functions, abstracts/normalizes them, generates fingerprints, and compares fingerprints through key/hash lookup.
Contribution List: scalable clone detection, vulnerable code clone discovery, practical open service/use. Exact bullet wording requires citation verification.
Claim-Evidence Structure: ecosystem growth -> vulnerable clone risk -> generic detector limitations -> VUDDY design -> large-scale evaluation and case studies.
Agent Evidence Anchors: raw_extraction/section_text/02_introduction.txt
Paragraph Map:
P1: Function: establish OSS growth. Main Claim: open-source scale is rapidly increasing. Evidence Type: ecosystem statistics. Transition: code cloning risk.
P2: Function: connect clones to security. Main Claim: copied code can propagate vulnerabilities. Evidence Type: security motivation. Transition: clone detection limitations.
P3+: Function: introduce VUDDY. Main Claim: function-level and length-filtered fingerprints enable scalable vulnerable clone discovery. Evidence Type: method preview and reported results.
Reusable Moves: Quantify ecosystem growth before introducing the algorithmic bottleneck.
Risks for Our Paper: Clone existence is not the same as affected versions; our prose must separate vulnerable code clone evidence from version-level vulnerability status.
""")

w("03_background_motivation.txt", """
Domain Concepts Introduced: code clone taxonomy; Type-1/Type-2/Type-3/Type-4 clones; vulnerable code clones; abstraction; normalization; function-level granularity.
Task Definition: Given known vulnerable code and target software, detect vulnerable code clones efficiently and accurately.
Threat Model / Assumptions: The target is static code clone discovery, not dynamic exploitability or deployment patch status.
Motivating Case: Security-sensitive changes such as statement order and constants motivate why abstraction must preserve vulnerable conditions.
Why the Case Is Chosen: It distinguishes vulnerability-aware clone detection from generic similarity matching.
Definitions Needed by Readers: vulnerable function, target function, clone type, abstraction level, fingerprint tuple, length key, hash value.
How Background Leads to Method: Taxonomy and vulnerability-specific constraints justify function-level hashing and security-aware abstraction.
Writing Pattern: Define broad clone taxonomy, then narrow to clone types that preserve vulnerability conditions.
Relevance to Our Paper: Useful when describing how code-presence evidence differs from version/release evidence.
Agent Evidence Anchors: raw_extraction/section_text/03_background.txt; raw_extraction/formulas/formula_index.txt
""")

w("04_problem_definition.txt", """
Input: Known vulnerable functions or vulnerability database plus target program source.
Output: Reported vulnerable code clones in target programs.
Objects / Entities: function, vulnerable function, target function, fingerprint, length key, hash value, vulnerability database, target fingerprint dictionary.
Formal Definitions: The paper defines clone detector and abstraction-related concepts in background; exact symbolic notation needs formula repair. [NEEDS FORMULA REPAIR]
Objective: Achieve scalable and accurate vulnerable code clone discovery over large software corpora.
Constraints: Function-level granularity may miss clones below/above function boundaries; abstraction must preserve vulnerability-triggering constants/order; database contents affect coverage.
Evaluation Target: scalability, accuracy, comparison with clone detectors/ReDeBug, and real-world vulnerability findings.
Boundary Conditions: Static clone evidence only; affected versions and patch status require additional version-aware validation.
What Is Not Solved: Runtime exploitability, all semantic clone types, full vulnerability database completeness, and reproduced large-scale results in this pass. [EXECUTION NOT REQUESTED]
Reusable Formalization Pattern: Separate preprocessing index construction from online clone lookup.
""")

w("05_method.txt", """
System Overview: VUDDY uses two stages: preprocessing and clone detection.
Pipeline Stages:
1. Function retrieval.
2. Abstraction and normalization.
3. Fingerprint generation from normalized function body length and hash.
4. Key lookup by length.
5. Hash lookup inside the length bucket.
6. Vulnerability database construction and clone checking for vulnerable functions.
Core Algorithm: Function-level fingerprint tuple plus length-classified dictionary membership tests; exact symbolic formatting requires formula/layout repair.
Data Structures: Fingerprint dictionary keyed by normalized function length and mapped to hash sets; local source includes hidx-oriented scripts and checker entrypoints.
Model / Agent Components: none.
Design Choices: Function-level granularity and length-first lookup trade broad semantic clone coverage for scalability and low-cost exact/abstract matching.
Why Each Choice Is Needed: Function-level extraction makes indexing manageable; abstraction handles common renaming/comment/format changes; length keys reduce hash comparison space.
Failure Handling: [NEEDS EVIDENCE] Runtime behavior was not checked.
Complexity / Cost Discussion: Text layer states O(1) average membership lookup and scale claims, but exact numeric reuse needs table repair.
Pseudocode or Algorithm Blocks: not cleanly extracted. [NEEDS ALGORITHM REPAIR]
Static Reproducibility Signals: hmark.py, parseutility2.py, checker/check_clones.py, src/vul_hidx_generator.py, src/get_cvepatch_from_git.py, FuncParser-opt Java/ANTLR parser sources, parser JARs, README instructions.
Agent Evidence Anchors: raw_extraction/section_text/04_method.txt; raw_extraction/source_static_inventory.txt
Writing Pattern: Present algorithm as staged transformation from code to reusable index, then online lookup.
""")

w("06_experiments.txt", """
Research Questions: Scalability, accuracy, comparison with ReDeBug, case-study usefulness, and practical service deployment.
Datasets: The paper mentions large OSS corpora, Git projects, target sets up to very large scale, and vulnerability database construction; exact datasets need table/artifact verification.
Baselines: Clone detectors and ReDeBug are used in the paper; exact configurations need table repair.
Metrics: preprocessing time, clone detection time, precision/false positives/false negatives, detected vulnerable clones, and case-study findings.
Experimental Protocol: The text layer describes generated target sets and repeated experiments; this pass did not reproduce them.
Implementation Details: Local artifact contains hmark, checker, parser, CVE data generation utilities, and configuration files.
Hyperparameters / Settings: function-length threshold and abstraction levels are described in text, but exact settings need verification before citation.
Hardware / Environment: README lists OS/Python/JRE expectations; paper evaluation environment requires citation verification.
Static Reproducibility Materials: README, hmark README, checker scripts, src vulnerability DB scripts, parser source/JARs, testcode, docs examples.
Execution Status: [EXECUTION NOT REQUESTED]
What Is Measured: clone detection scalability/accuracy and vulnerable clone findings.
What Is Not Measured: affected versions accuracy or release/tag-level verification.
Agent Evidence Anchors: raw_extraction/section_text/05_experiments.txt; raw_extraction/tables/table_index.txt; raw_extraction/source_static_inventory.txt
Writing Pattern: Pair benchmark-scale evaluation with real-world case studies.
""")

w("07_evaluation.txt", """
Main Results: Text/caption extraction indicates tables and figures covering scalability, accuracy, ReDeBug comparison, and case-study findings; exact numbers are not citation-ready.
Per-RQ Findings: Scalability and accuracy are evaluated separately, followed by direct comparison with ReDeBug and case studies.
Ablation: [NEEDS EVIDENCE]
Sensitivity Analysis: [NEEDS EVIDENCE]
Case Study: Case-study sections include library reuse, kernel reuse, and intra-project code reuse.
Efficiency: Figures/tables discuss preprocessing and clone detection time; exact values require table/figure repair.
Error Analysis: ReDeBug comparison covers false positives/false negatives, but exact values require table repair.
Statistical / Validity Notes: [NEEDS EVIDENCE]
How Claims Are Supported: Main claims rely heavily on tables, figures, and case-study examples.
Unsupported or Weakly Supported Claims: Any exact speedup, billion-line timing, precision, false-positive, false-negative, or zero-day count should be treated as weak until [NEEDS TABLE REPAIR] and [NEEDS FIGURE EXTRACTION] are resolved.
Agent Evidence Anchors: raw_extraction/section_text/05_experiments.txt; raw_extraction/section_text/06_evaluation.txt; raw_extraction/tables/table_index.txt; raw_extraction/figures/figure_index.txt
Writing Pattern: Use quantitative comparison plus concrete vulnerability case studies to connect tool performance to security impact.
""")

w("08_limitations_ethics.txt", """
Stated Limitations: Discussion addresses function-level granularity, speedup opportunities, and open service deployment; exact threat-to-validity wording is not separately extracted.
Threats to Validity: [NEEDS EVIDENCE]
Ethical Considerations: The paper reports real vulnerability findings and service deployment, but responsible disclosure details need verification. [NEEDS EVIDENCE]
Security / Misuse Discussion: Static vulnerable clone discovery can identify unpatched reused code; misuse discussion is not confirmed in this extraction. [NEEDS EVIDENCE]
Responsible Disclosure: [NEEDS EVIDENCE]
Scope Boundaries: Function-level static clone detection, not full semantic equivalence or affected versions inference.
Writing Pattern: Discuss granularity tradeoffs and operational deployment separately from benchmark metrics.
Relevance to Our Paper: Useful for showing why static code-presence evidence must be constrained by verifier gates before affected versions claims.
""")

w("09_figures_tables.txt", """
Figure / Table Inventory:
ID: table_001 to table_005
Agent Evidence Unit IDs: p13_vuddy_scalable_vulnerable_code_clone_discovery_2017:table:table_001 ... table_005
Purpose: scalability, accuracy, false negative/false positive, and comparison evidence.
Evidence Shown: caption/context only, with partially damaged values.
Placement in Argument: evaluation and ReDeBug comparison.
Extraction Confidence: partial
Repair Needed: [NEEDS TABLE REPAIR]
Citation Readiness: low
Figure Readiness: not applicable
Design Pattern: combine scalability table, accuracy table, and baseline comparison table.
Could Inspire Our Paper? yes, if adapted to affected versions metrics.

ID: figure_001 to figure_015
Agent Evidence Unit IDs: p13_vuddy_scalable_vulnerable_code_clone_discovery_2017:figure:figure_001 ... figure_015
Purpose: method workflow, abstraction/fingerprint examples, evaluation graphs, service screenshots, and case-study distributions.
Evidence Shown: caption/context only.
Placement in Argument: method explanation, evaluation support, and case-study evidence.
Extraction Confidence: partial
Repair Needed: [NEEDS FIGURE EXTRACTION]
Citation Readiness: low
Figure Readiness: no
Design Pattern: method pipeline figure plus evaluation/case-study visualizations.
Could Inspire Our Paper? yes, structurally.

Required Figures for Our Paper: affected versions pipeline, clone/presence evidence vs tag/version verification boundary, precision/recall or exact-set affected versions evaluation table. [NEEDS EVIDENCE from our project]
""")

w("10_writing_patterns.txt", """
Best Structural Moves:
- Motivate with ecosystem-scale code reuse before introducing the security-specific clone task.
- Narrow the scope through taxonomy and security-preserving abstraction constraints.
- Present preprocessing and online lookup as separate stages.
- Pair performance evaluation with real vulnerability case studies.

Best Transition Moves:
- From OSS growth to vulnerable clone proliferation.
- From generic clone detection to vulnerable clone detection.
- From function abstraction to scalable fingerprint lookup.
- From benchmark performance to real-world service/case-study impact.

Best Contribution Wording Pattern:
- "We propose a scalable, vulnerability-aware detection approach that indexes X and detects Y using Z."

Best Method Overview Pattern:
- Function retrieval -> abstraction/normalization -> fingerprint generation -> length key lookup -> hash lookup -> vulnerable clone reporting.

Best Experiment Framing Pattern:
- Scalability first, accuracy second, baseline comparison third, real-world cases fourth.

Useful Phrases to Paraphrase Structurally:
- "vulnerability-aware abstraction" as a design pattern.
- "preprocess once, query fast" as a structure, not copied wording.

Patterns to Avoid:
- Do not imply static clones prove exploitability.
- Do not imply clone detection directly determines affected versions.
- Do not cite numeric claims before repairing tables/figures.
""")

w("11_relevance_to_our_paper.txt", """
Direct Relevance: Medium-high for related work on vulnerable code reuse and static evidence of vulnerable code presence.
Indirect Relevance: High for designing scalable preprocessing/indexing and for discussing precision/coverage tradeoffs.
Useful for Which Section: Background, Related Work, Method motivation, Limitations.
Comparable Task Elements: known vulnerable code, target program code, function-level evidence, clone matching, vulnerability database construction.
Comparable Method Elements: abstraction, normalization, function fingerprints, hash/index lookup, parser-backed source extraction.
Comparable Evaluation Elements: scalability, accuracy, baseline comparison, false positives/false negatives, case studies.
What We Can Borrow Structurally: staged indexing pipeline, vulnerability-aware abstraction framing, benchmark-plus-case-study evaluation style.
What We Cannot Borrow: exact reported findings without table repair, runtime artifact claims without execution, or clone detections as affected versions labels.
Evidence Needed Before Use: table repair, figure extraction, citation verification, artifact/database completeness check, and explicit mapping from clone presence to affected versions verification.
Priority: medium-high
""")

w("12_artifact_consistency.txt", """
Paper Claims: VUDDY performs scalable vulnerable code clone discovery using function-level abstraction/fingerprints and efficient clone lookup.
Implemented Components: Static source shows hmark preprocessing, checker scripts, vulnerability database generation scripts, parser JAR/source, ANTLR grammars, config/README/docs, and test C files.
Unimplemented or Stubbed Components: Full database contents, large OSS corpora, benchmark outputs, and online service state are not verified. [NEEDS ARTIFACT]
Dataset Availability: testcode and documentation are visible; complete evaluation datasets are not verified locally. [NEEDS ARTIFACT]
Benchmark / Evaluation Scripts Visible by Static Inspection: checker scripts and hmark/src utilities exist; benchmark reproduction scripts for paper-scale experiments are not confirmed as complete.
Static Reproduction Instructions or Missing Instructions: README provides hmark and checker usage, but local database construction and full paper reproduction need artifact verification.
Config Files: config.py, dep.sh, README.md, hmark/README.md, and tools/cvedatagen README are present.
Environment Constraints: README lists Python/JRE/OS expectations; parser JARs and Java/ANTLR sources are present.
Paper-Code Mismatches: No direct mismatch proven; the local artifact appears to be a maintained hmark/VUDDY implementation, but paper-scale database/evaluation artifacts are incomplete in this static view.
Engineering Lessons for Our Paper: Separate index generation, database construction, clone checking, and result interpretation; document what is static evidence versus reproduced evidence.

Consistency Check:
Claim: VUDDY uses function-level parsing and fingerprint/hash lookup.
Paper Location: Method sections.
Artifact Evidence: hmark/hmark.py, hmark/parseutility2.py, tools/parseutility.py, checker/check_clones.py, FuncParser-opt sources/JARs.
Source Evidence: raw_extraction/source_static_inventory.txt
Consistency: supported
Analysis Mode: static-only
Notes: Implementation structure matches paper-level components; runtime not checked.
Use in Our Paper: yes, as related-work/method evidence with caution.

Consistency Check:
Claim: VUDDY reproduces paper-scale billion-line evaluation locally.
Paper Location: Evaluation sections.
Artifact Evidence: local scripts and parser artifacts exist, but full corpora/results are not visible.
Source Evidence: raw_extraction/source_static_inventory.txt
Consistency: unclear
Analysis Mode: static-only
Notes: [NEEDS ARTIFACT]; [EXECUTION NOT REQUESTED]
Use in Our Paper: no, unless artifact completeness is verified.
""")

w("13_completeness_audit.txt", """
Raw Extraction:
- PDF text extracted: yes
- Page text extracted: yes, page count 20
- Section text extracted: yes, section file count 9, heuristic boundaries
- Agent index exists: yes
- Extraction profile exists: yes
- Layout blocks extracted: missing/not attempted
- References extracted: yes, text-layer only
- Table extraction: caption/context-only
- Figure extraction: caption-only
- Formula/algorithm/prompt extraction: formula partial; algorithm not confidently extracted; prompt not detected
- OCR needed: no

Section Analysis:
- 00_meta.txt through 12_artifact_consistency.txt: complete
- Are analysis files section-oriented enough for writing? yes, with repair labels

Source / Artifact Static Analysis:
- Source inventory exists: yes
- README/config inspected: yes
- Main entrypoints inspected: yes by static AST/regex/file layout
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
- [NEEDS FORMULA REPAIR]
- [NEEDS CITATION VERIFICATION]
- [NEEDS ARTIFACT]
- [EXECUTION NOT REQUESTED]

Usefulness Grade: medium-high, because text-layer method/source evidence is strong for related-work and method framing, while quantitative and case-study claims need repair and artifact verification.
""")

w("14_section_retrieval_map.txt", """
For Introduction:
- Read analysis/02_introduction.txt
- Read raw_extraction/section_text/02_introduction.txt
- Useful claims: OSS growth, vulnerable clone motivation, scalability bottleneck.
- Must not claim: affected versions correctness.

For Background / Motivation:
- Read analysis/03_background_motivation.txt
- Read raw_extraction/section_text/03_background.txt
- Useful claims: clone taxonomy and vulnerability-aware abstraction constraints.
- Must not claim: all semantic clones are covered.

For Method:
- Read analysis/05_method.txt
- Read raw_extraction/section_text/04_method.txt
- Read raw_extraction/source_static_inventory.txt
- Useful claims: function retrieval, abstraction/normalization, fingerprinting, length/hash lookup.
- Must not claim: runtime parser/checker behavior in this pass.

For Experiments / Evaluation:
- Read analysis/06_experiments.txt and analysis/07_evaluation.txt
- Read raw_extraction/section_text/05_experiments.txt and section_text/06_evaluation.txt
- Read raw_extraction/tables/table_index.txt and figures/figure_index.txt
- Useful claims: evaluation structure and case-study design.
- Must not claim: exact numbers until [NEEDS TABLE REPAIR] and [NEEDS FIGURE EXTRACTION] are resolved.

For Limitations:
- Read analysis/08_limitations_ethics.txt
- Read raw_extraction/section_text/08_limitations.txt
- Useful claims: function-level granularity and deployment/service discussion.
- Must not claim: responsible disclosure details without evidence.

For Related Work:
- Read raw_extraction/section_text/07_related_work.txt
- Useful claims: clone-detection and vulnerable-code-discovery positioning.
- Must not claim: verified BibTeX until citation verification.
""")

print("analysis written")
