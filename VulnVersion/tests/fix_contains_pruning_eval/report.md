# Fix-Contains Hard-Pruning Evaluation

This evaluates the idea: after Step3 creates its release-tag plan, tags matched by
`git tag --contains <fix_commit>` are treated as definitely fixed and are removed
from agent probing.

The simulator uses GT labels only as an oracle for evaluation; GT is not part of
the production Step3 algorithm.

## Overall

| strategy | total probes | avg probes | p95 | exact CVEs | FN CVEs | FP CVEs | micro P | micro R | micro F1 | hard-pruned GT tags/CVEs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `baseline_current_any_fs1` | 79757 | 70.71 | 130.0 | 1114/1128 | 8 | 2 | 0.999915 | 0.999848 | 0.999882 | 0/0 |
| `hard_prune_any` | 62865 | 55.73 | 108.0 | 1072/1128 | 50 | 2 | 0.999915 | 0.995282 | 0.997593 | 270/42 |
| `hard_prune_all` | 64714 | 57.37 | 115.0 | 1076/1128 | 46 | 3 | 0.999898 | 0.995502 | 0.997695 | 255/37 |
| `hard_prune_any_after_first` | 76510 | 67.83 | 117.0 | 1071/1128 | 51 | 2 | 0.999914 | 0.988095 | 0.993969 | 192/6 |
| `hard_prune_all_after_first` | 77764 | 68.94 | 120.0 | 1074/1128 | 48 | 3 | 0.999897 | 0.988247 | 0.994038 | 181/2 |

## Highest-Risk Cases

### hard_prune_any

| repo | CVE | probes saved | additional FN tags | hard-pruned GT tags |
| --- | --- | ---: | ---: | ---: |
| wireshark | CVE-2021-22191 | 34 | 123 | 123 |
| wireshark | CVE-2021-4185 | 28 | 72 | 72 |
| linux | CVE-2023-5178 | 40 | 26 | 26 |
| FFmpeg | CVE-2021-38114 | 44 | 4 | 4 |
| FFmpeg | CVE-2020-22019 | 38 | 4 | 4 |
| FFmpeg | CVE-2020-20451 | 43 | 3 | 3 |
| FFmpeg | CVE-2022-48434 | 7 | 3 | 3 |
| qemu | CVE-2021-3409 | 36 | 1 | 1 |
| linux | CVE-2022-3105 | 24 | 1 | 1 |
| linux | CVE-2022-20158 | 23 | 1 | 1 |
| linux | CVE-2022-20368 | 23 | 1 | 1 |
| linux | CVE-2022-20423 | 23 | 1 | 1 |
| linux | CVE-2022-3107 | 23 | 1 | 1 |
| linux | CVE-2022-48629 | 23 | 1 | 1 |
| linux | CVE-2022-1729 | 22 | 1 | 1 |
| linux | CVE-2022-48630 | 22 | 1 | 1 |
| linux | CVE-2023-4387 | 22 | 1 | 1 |
| linux | CVE-2022-36946 | 21 | 1 | 1 |
| linux | CVE-2023-2177 | 21 | 1 | 1 |
| linux | CVE-2022-2308 | 20 | 1 | 1 |

### hard_prune_all

| repo | CVE | probes saved | additional FN tags | hard-pruned GT tags |
| --- | --- | ---: | ---: | ---: |
| wireshark | CVE-2021-22191 | 34 | 123 | 123 |
| wireshark | CVE-2021-4185 | 28 | 72 | 72 |
| linux | CVE-2023-5178 | 40 | 26 | 26 |
| FFmpeg | CVE-2020-20451 | 3 | 2 | 0 |
| linux | CVE-2022-3105 | 24 | 1 | 1 |
| linux | CVE-2022-20158 | 23 | 1 | 1 |
| linux | CVE-2022-20368 | 23 | 1 | 1 |
| linux | CVE-2022-20423 | 23 | 1 | 1 |
| linux | CVE-2022-3107 | 23 | 1 | 1 |
| linux | CVE-2022-48629 | 23 | 1 | 1 |
| linux | CVE-2022-1729 | 22 | 1 | 1 |
| linux | CVE-2022-48630 | 22 | 1 | 1 |
| linux | CVE-2023-4387 | 22 | 1 | 1 |
| linux | CVE-2022-36946 | 21 | 1 | 1 |
| linux | CVE-2023-2177 | 21 | 1 | 1 |
| linux | CVE-2022-2308 | 20 | 1 | 1 |
| linux | CVE-2022-3643 | 19 | 1 | 1 |
| linux | CVE-2022-42328 | 19 | 1 | 1 |
| linux | CVE-2022-42329 | 19 | 1 | 1 |
| linux | CVE-2022-4378 | 19 | 1 | 1 |

### hard_prune_any_after_first

| repo | CVE | probes saved | additional FN tags | hard-pruned GT tags |
| --- | --- | ---: | ---: | ---: |
| wireshark | CVE-2021-22191 | 25 | 115 | 115 |
| wireshark | CVE-2021-4185 | 21 | 66 | 66 |
| ImageMagick | CVE-2020-27829 | 10 | 56 | 0 |
| curl | CVE-2023-23916 | 7 | 41 | 0 |
| curl | CVE-2024-9681 | 8 | 37 | 0 |
| curl | CVE-2022-32206 | 7 | 37 | 0 |
| curl | CVE-2023-38545 | 7 | 34 | 0 |
| curl | CVE-2022-27775 | 7 | 25 | 0 |
| curl | CVE-2021-22897 | 7 | 24 | 0 |
| curl | CVE-2022-32207 | 7 | 20 | 0 |
| curl | CVE-2021-22890 | 7 | 19 | 0 |
| curl | CVE-2022-32205 | 8 | 17 | 0 |
| curl | CVE-2024-2004 | 8 | 16 | 0 |
| curl | CVE-2023-46219 | 7 | 15 | 0 |
| curl | CVE-2020-8169 | 7 | 14 | 0 |
| curl | CVE-2023-23914 | 8 | 13 | 0 |
| curl | CVE-2023-23915 | 8 | 13 | 0 |
| curl | CVE-2023-38039 | 8 | 13 | 0 |
| ImageMagick | CVE-2020-25663 | 10 | 12 | 0 |
| curl | CVE-2022-43551 | 8 | 12 | 0 |

### hard_prune_all_after_first

| repo | CVE | probes saved | additional FN tags | hard-pruned GT tags |
| --- | --- | ---: | ---: | ---: |
| wireshark | CVE-2021-22191 | 25 | 115 | 115 |
| wireshark | CVE-2021-4185 | 21 | 66 | 66 |
| ImageMagick | CVE-2020-27829 | 10 | 56 | 0 |
| curl | CVE-2023-23916 | 7 | 41 | 0 |
| curl | CVE-2024-9681 | 8 | 37 | 0 |
| curl | CVE-2022-32206 | 7 | 37 | 0 |
| curl | CVE-2023-38545 | 7 | 34 | 0 |
| curl | CVE-2022-27775 | 7 | 25 | 0 |
| curl | CVE-2021-22897 | 7 | 24 | 0 |
| curl | CVE-2022-32207 | 7 | 20 | 0 |
| curl | CVE-2021-22890 | 7 | 19 | 0 |
| curl | CVE-2022-32205 | 8 | 17 | 0 |
| curl | CVE-2024-2004 | 8 | 16 | 0 |
| curl | CVE-2023-46219 | 7 | 15 | 0 |
| curl | CVE-2020-8169 | 7 | 14 | 0 |
| curl | CVE-2023-23914 | 8 | 13 | 0 |
| curl | CVE-2023-23915 | 8 | 13 | 0 |
| curl | CVE-2023-38039 | 8 | 13 | 0 |
| ImageMagick | CVE-2020-25663 | 10 | 12 | 0 |
| curl | CVE-2022-43551 | 8 | 12 | 0 |

