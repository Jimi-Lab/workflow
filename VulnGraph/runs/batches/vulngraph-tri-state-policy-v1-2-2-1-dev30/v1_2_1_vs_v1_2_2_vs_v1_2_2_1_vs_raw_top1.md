# v1.2.1 vs v1.2.2 vs v1.2.2.1 vs Raw Top-1

| Version | Exact | NMR | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| v1.2.1 | 0.366667 | 0.633333 | 0.619289 | 0.665345 | 0.641491 | 1342 | 825 | 675 |
| v1.2.2_optimistic_unknown_included | 0.033333 | 0.366667 | 0.249053 | 0.358453 | 0.293902 | 723 | 2180 | 1294 |
| v1.2.2.1_confirmed_only_primary | 0.166667 | 0.266667 | 0.625298 | 0.259792 | 0.367075 | 524 | 314 | 1493 |
| raw_top1_diagnostic | 0.500000 | n/a | 0.662451 | 0.753099 | 0.704872 | 1519 | 774 | 498 |

v1.2.2 is an optimistic diagnostic because it includes unknown tags. v1.2.2.1 is the fail-closed primary prediction.
