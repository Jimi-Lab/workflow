# TDSC-style VersionTree Builder Simulator

Dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json`.

GT is used only for oracle probe verdicts and final metrics.

## Overall Metrics

| builder | avg lines | singleton ratio | avg probes | p95 | exact CVEs | FN CVEs | version FN | precision | recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| current_version_registry | 60.43 | 0.8660 | 68.36 | 123.00 | 1112/1128 | 8 | 9 | 0.999797 | 0.999848 | 0.999822 |
| tdsc_hybrid_repo_aware | 60.93 | 0.8582 | 70.43 | 123.00 | 1112/1128 | 8 | 9 | 0.999797 | 0.999848 | 0.999822 |
| tdsc_version_tree | 66.39 | 0.8414 | 76.02 | 139.00 | 1112/1128 | 8 | 9 | 0.999797 | 0.999848 | 0.999822 |

## Affected-line Continuity

| builder | affected lines | non-contiguous lines | non-contiguous CVEs | continuity |
| --- | ---: | ---: | ---: | ---: |
| current_version_registry | 19408 | 8 | 7 | 0.999588 |
| tdsc_hybrid_repo_aware | 19832 | 8 | 7 | 0.999597 |
| tdsc_version_tree | 21991 | 8 | 7 | 0.999636 |

## Interpretation

- A builder is not better just because its version tree is more fine-grained.
- It must reduce probes without increasing version FN or reducing exact CVEs.
- `tdsc_version_tree` is the generic major.minor rule; `tdsc_hybrid_repo_aware` is the repo-aware hypothesis.
