# Global-State Line Scheduler Simulator

GT is used only as selected-probe oracle and final evaluator.

| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | avg active lines | avg irrelevant active lines | irrelevant active % | version FN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| control_current | 84.80 | 90 | 133 | 19/20 | 1 | 0 | 29.65 | 18.30 | 61.72% | 1 | 1.000000 | 0.999387 | 0.999693 |
| file_first_nohit_nofix | 70.50 | 48 | 125 | 19/20 | 1 | 0 | 25.25 | 13.90 | 55.05% | 1 | 1.000000 | 0.999387 | 0.999693 |
| file_transition_nohit_nofix | 70.50 | 48 | 125 | 19/20 | 1 | 0 | 25.25 | 13.90 | 55.05% | 1 | 1.000000 | 0.999387 | 0.999693 |
| global_scout_s2_families_without_positive | 70.50 | 48 | 125 | 19/20 | 1 | 0 | 25.25 | 13.90 | 55.05% | 1 | 1.000000 | 0.999387 | 0.999693 |
| global_scout_s3_all | 79.20 | 73 | 130 | 19/20 | 1 | 0 | 29.85 | 18.50 | 61.98% | 1 | 1.000000 | 0.999387 | 0.999693 |
| global_scout_s3_families_without_positive | 70.50 | 48 | 125 | 19/20 | 1 | 0 | 25.25 | 13.90 | 55.05% | 1 | 1.000000 | 0.999387 | 0.999693 |
| global_scout_s4_all | 77.50 | 67 | 130 | 19/20 | 1 | 0 | 29.00 | 17.65 | 60.86% | 1 | 1.000000 | 0.999387 | 0.999693 |
