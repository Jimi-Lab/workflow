# Related Work Taxonomy

## A. Direct Affected-Version Identification

Core papers: p01, p09, p20, p32, p33.

Use:
- Define the direct task and metrics.
- Contrast commit-interval inference, version-tree/log methods, static+LLM vulnerable-version methods, and VulnVersion's per-tag state verification.

Draft positioning:
- p01 is the main task/baseline benchmark.
- p09 is the ICSE direct predecessor using SZZ-derived version ranges.
- p32 is the version-tree/developer-log predecessor.
- p20 and p33 are context-aware or LLM-assisted vulnerable-version systems.

## B. SZZ and Commit-Level Localization

Core papers: p04, p06, p08, p11, p14, p16, p19, p25.

Use:
- Explain why finding BIC/VIC is useful but insufficient.
- Motivate root-cause evidence extraction and repository search.
- Borrow ablation/cost/error-analysis structure.

Draft boundary:
- These methods usually output commits, not affected release tags.
- Their metrics should not be mixed with affected-version metrics.

## C. Recurring Vulnerability, Clone, and Code-Reuse Detection

Core papers: p02, p05, p07, p10, p12, p13.

Use:
- Explain static evidence, patch signatures, clone matching, and scalable indexing.
- Contrast code resemblance with vulnerability-state verification.
- Borrow staged filtering and scalability evaluation.

Draft boundary:
- Code clone or reused-code detection can be evidence for vulnerable state, but it is not a complete affected-version verdict.

## D. Agent/LLM Methodology and Resource Evaluation

Core papers: p04, p16, p20, p25, p33.

Use:
- Justify agent-assisted semantic judgment only after deterministic evidence preparation.
- Define token/cost/time/tool-call reporting.
- Plan model/backbone/context ablations.

Draft boundary:
- Keep agent claims scoped. For now, VulnVersion method is a structured placeholder and effectiveness is [NEEDS EXPERIMENT].

## E. Empirical Measurement and Validity

Core papers: p01, p03, p08, p11, p32.

Use:
- Write dataset construction, label validity, manual verification, lower-bound recall, and generalizability.

Draft boundary:
- Avoid overclaiming from heuristic or manually sampled validation.
