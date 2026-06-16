# Transferable Writing Patterns

## Introduction Pattern

Use a five-step introduction:

1. Security operations need accurate affected-version sets, not only CVE IDs.
2. Public metadata and direct tools are unreliable or incomplete.
3. Existing approaches split into commit-tracing, code-matching, and context-aware/LLM validation families.
4. The key gap is not just better matching; it is repository-grounded per-tag vulnerability state verification.
5. VulnVersion addresses this by separating deterministic planning from agent-assisted tag verdicts.

Source patterns:
- p01: task-first motivation, tracing/matching taxonomy, RQ-driven empirical gap.
- p09/p32: affected-version metadata matters to remediation and NVD correction.
- p07/p13/p05: clone/signature methods scale but do not prove semantic vulnerability presence.
- p16/p25: agents can search repository evidence, but current agent papers stop at BIC identification.
- p20/p33: LLM/context-aware methods support vulnerable-version tasks but need resource and ablation reporting.

## Contribution Pattern

Recommended contribution framing:

- A problem reformulation: affected-version identification as repository-grounded per-tag vulnerability state verification.
- A framework: patch-family filtering, root-cause evidence extraction, release-line planning, and agent tag verdicts.
- An evaluation plan: p01 dataset, p01 baselines, CVE-level and version-level metrics, ablations, and cost metrics.
- A writing boundary: final effectiveness claims are [NEEDS EXPERIMENT].

Do not claim "first" until citation verification and remaining related-work PDFs are analyzed.

## Method Writing Pattern

Write each module as "failure mode -> design response -> output artifact":

- Noisy patches -> Step1 fix-family filtering -> `patch_semantics.json`.
- Touched-code/root-cause mismatch -> Step2 root-cause VET -> `root_cause_vet.json`.
- Multi-branch release history -> Step3 repository-aware version-line planning -> `tag_plan.json` and `vuln_tree.json`.
- Semantic tag judgment -> agent verdict with scoped evidence -> `per_tag_verdict.jsonl`.

Source patterns:
- p01: stage-wise decomposition.
- p02: cheap-to-expensive verification cascade.
- p06/p14: patch/statement semantic evidence.
- p16/p25: task-specific agent tools and context compression.
- p32: version tree and branch directions.

## Evaluation Writing Pattern

Each RQ should have:

- Setup: dataset split and baselines.
- Metrics: exact formulas or references to table.
- Result table or figure placeholder.
- Finding sentence, left as [NEEDS EXPERIMENT] until results exist.
- Error-analysis hook.

Source patterns:
- p01: RQ1-RQ4 structure and CVE/version metrics.
- p04/p06/p20/p25/p33: ablation and model-sensitivity structure.
- p02/p05/p07/p13: scalability/efficiency structure.
- p32: lower-bound recall and manual workload when full FN verification is expensive.

## Threats-to-Validity Pattern

Use separate paragraphs for:

- Construct validity: exact-set vs version-level metrics.
- Internal validity: stage errors and agent verdict errors.
- External validity: C/C++ dataset and project/release practices.
- Baseline validity: paper-reported vs reproduced baselines.
- Artifact/citation validity: table repair, figure extraction, BibTeX verification.
- Dual use: patch-based affected-version identification can help defenders and attackers.

Source patterns:
- p01/p03/p11: empirical dataset and label-noise validity.
- p07: dual-use patch-search discussion.
- p04/p16/p25/p33: LLM/model/context/cost threats.
