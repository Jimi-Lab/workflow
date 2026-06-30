# Judge Boundary v1 vs v1.1

## Judge contract

| Metric | v1 | v1.1 |
|---|---:|---:|
| Parse accepted | 29/30 | 30/30 |
| Contract accepted | 29/30 | 30/30 |
| Semantic repair retries | 13 | 0 |
| Selected events | 18 | 22 |
| Rejected judgments/views | 0 | 12 |
| Uncertain judgments | 25 | 27 |

Frozen v1 consistency audit:

- selected judgments missing from selected events: 5 across 4 cases
- decision/role conflicts: 2 across 2 cases
- rejected-stat mismatch cases: 7

v1.1 accounted all 61 input candidates exactly once and derives all views in wrapper code.

## All-case affected-version metrics

| Metric | v1 | v1.1 | Delta |
|---|---:|---:|---:|
| Exact Accuracy | 0.233333 | 0.266667 | +0.033333 |
| NMR | 0.333333 | 0.333333 | +0.000000 |
| Micro Precision | 0.676941 | 0.713217 | +0.036276 |
| Micro Recall | 0.294001 | 0.283589 | -0.010412 |
| Micro F1 | 0.409955 | 0.405818 | -0.004137 |
| False-positive versions | 283 | 230 | -53 |
| False-negative versions | 1424 | 1445 | +21 |

## Interpretation

v1.1 improves contract consistency, exact accuracy, and precision, while recall and micro F1 decline slightly. The state machine removes broad event-union behavior and reduces false positives, but 12 cases have no selected boundary event and three selected cases contain prerequisite-only groups. These cases contribute empty predictions and higher false negatives.

This is a correctness-hardening result, not evidence that final affected-version performance is solved. No 100-CVE validation was run.
