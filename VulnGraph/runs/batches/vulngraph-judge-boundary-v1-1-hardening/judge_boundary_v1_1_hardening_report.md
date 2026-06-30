# VulnGraph Judge Boundary v1.1 Correctness Hardening

## Execution boundary

- Development set only: 30 CVEs.
- No 100-CVE validation.
- No Neo4j.
- No attacker-perspective module; unavailable compatibility retained.
- No affected-version ground truth in Judge inputs.
- Converter output is a separate deterministic artifact.

## Old v1 consistency audit

- 30 cases replayed without model calls.
- 5 selected judgments were absent from selected event lists across 4 cases.
- 2 decision/role conflicts across 2 cases.
- 7 cases had rejected-stat mismatches.
- Audit: `judge_boundary_consistency_audit.json`.

## Judge v1.1

- Model output contains only `candidate_judgments`.
- Wrapper derives selected/rejected/uncertain views.
- `uncertain_boundary` was removed; uncertainty is a decision.
- Every input candidate must appear exactly once.
- Semantic retry contains the full original boundary input and contract errors.
- Trailing-comma JSON defects are repaired deterministically without a model retry.

### Targeted 7-CVE gate

- Parse: 7/7.
- Contract: 7/7.
- Candidate accounting: 18/18.
- Backend failures: 0.
- Repair retries: 0.
- Runtime: 387.078 s.

### Dev30

- Parse: 30/30.
- Contract: 30/30.
- Candidate accounting: 61/61.
- Selected: 22; rejected: 12; uncertain: 27.
- Backend failures: 0.
- Repair retries: 0.
- Runtime: 1166.031 s.

## Converter v1.1

- Contract output is re-linted before conversion.
- Contract-rejected cases are fail-closed with `prediction_status=blocked` and empty predictions.
- Vulnerability activation is evaluated per wrapper-owned boundary group.
- Prerequisites cannot activate a vulnerability alone.
- Fix completion uses AND across patch families and OR across equivalent commits within a family.
- Final dev30 blocked cases: 0.
- Final converter runtime: 53.485 s.

## All-case paper metrics

| Metric | v1 | v1.1 |
|---|---:|---:|
| Exact Accuracy | 0.233333 | 0.266667 |
| NMR | 0.333333 | 0.333333 |
| Micro Precision | 0.676941 | 0.713217 |
| Micro Recall | 0.294001 | 0.283589 |
| Micro F1 | 0.409955 | 0.405818 |
| FP versions | 283 | 230 |
| FN versions | 1424 | 1445 |

## Error attribution

- `no_selected_boundary_events`: 12 cases.
- `prerequisite_without_activation`: 3 cases.
- Correctness hardening reduced broad false positives but increased false negatives.
- This development result is not sufficient to authorize frozen 100-CVE validation without reviewing the 15 uncertainty-bearing conversion cases.
