# Global-State Line Scheduler Simulator

GT is used only as selected-probe oracle and final evaluator.

| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | avg active lines | avg irrelevant active lines | irrelevant active % | version FN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| control_current | 68.06 | 75 | 123 | 1116/1128 | 8 | 4 | 49.15 | 31.95 | 64.99% | 9 | 0.999797 | 0.999848 | 0.999822 |
| file_first_nohit_nofix | 59.38 | 64 | 116 | 1115/1128 | 9 | 4 | 44.09 | 26.89 | 60.98% | 31 | 0.999797 | 0.999476 | 0.999636 |
| file_transition_nohit_nofix | 59.38 | 64 | 116 | 1115/1128 | 9 | 4 | 44.09 | 26.89 | 60.98% | 31 | 0.999797 | 0.999476 | 0.999636 |
| global_scout_s2_families_without_positive | 59.45 | 64 | 116 | 1115/1128 | 9 | 4 | 44.13 | 26.92 | 61.01% | 31 | 0.999797 | 0.999476 | 0.999636 |
| global_scout_s3_all | 66.23 | 72 | 119 | 1116/1128 | 8 | 4 | 49.73 | 32.53 | 65.40% | 9 | 0.999797 | 0.999848 | 0.999822 |
| global_scout_s3_families_without_positive | 59.44 | 64 | 116 | 1115/1128 | 9 | 4 | 44.12 | 26.91 | 61.00% | 31 | 0.999797 | 0.999476 | 0.999636 |
| global_scout_s4_all | 64.88 | 71 | 118 | 1116/1128 | 8 | 4 | 48.52 | 31.32 | 64.54% | 9 | 0.999797 | 0.999848 | 0.999822 |
