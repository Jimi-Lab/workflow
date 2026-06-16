# TDSC-style VersionTree Builder Simulator

Dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json`.

GT is used only for oracle probe verdicts and final metrics.

## Overall Metrics

| builder | avg lines | singleton ratio | avg probes | p95 | exact CVEs | FN CVEs | version FN | precision | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| current_version_registry | 37.00 | 0.0000 | 118.90 | 163.00 | 30/1128 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| tdsc_hybrid_repo_aware | 37.00 | 0.0000 | 118.90 | 163.00 | 30/1128 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| tdsc_version_tree | 37.00 | 0.0000 | 118.90 | 163.00 | 30/1128 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |

## Affected-line Continuity

| builder | affected lines | non-contiguous lines | non-contiguous CVEs | continuity |
| --- | ---: | ---: | ---: | ---: |
| current_version_registry | 361 | 2 | 1 | 0.994460 |
| tdsc_hybrid_repo_aware | 361 | 2 | 1 | 0.994460 |
| tdsc_version_tree | 361 | 2 | 1 | 0.994460 |

## Interpretation

- A builder is not better just because its version tree is more fine-grained.
- It must reduce probes without increasing version FN or reducing exact CVEs.
- `tdsc_version_tree` is the generic major.minor rule; `tdsc_hybrid_repo_aware` is the repo-aware hypothesis.
