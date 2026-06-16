# Dynamic Line Activation Scheduler Simulator

Dataset: `DataSet\BaseDataOrder.json`

GT is used only as the simulator oracle. VET evidence changes priority/order only.

| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | avg active lines | irrelevant active % | version FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `control_transition_scout_s4_expand2_allfixfile_s4` | 57.92 | 50 | 104 | 11/12 | 1 | 0 | 21.33 | 44.53% | 1 | 1.000000 | 0.999074 | 0.999537 |
| `family_interval_closure_only` | 53.58 | 42 | 96 | 11/12 | 1 | 0 | 20.00 | 40.83% | 1 | 1.000000 | 0.999074 | 0.999537 |
| `evidence_ranked_scout_queue` | 50.75 | 42 | 87 | 10/12 | 2 | 0 | 17.83 | 35.05% | 11 | 1.000000 | 0.989815 | 0.994881 |
| `late_all_fix_file_scout` | 55.33 | 44 | 99 | 11/12 | 1 | 0 | 20.00 | 40.83% | 1 | 1.000000 | 0.999074 | 0.999537 |
| `ranked_positive_neighbor` | 53.33 | 45 | 86 | 9/12 | 3 | 0 | 19.50 | 46.15% | 39 | 1.000000 | 0.963889 | 0.981612 |
| `hybrid_dynamic_scheduler` | 42.25 | 34 | 74 | 8/12 | 4 | 0 | 14.75 | 33.33% | 66 | 1.000000 | 0.938889 | 0.968481 |

## Deltas vs Control

{
  "evidence_ranked_scout_queue": {
    "avg_probe_delta": -7.166666666666664,
    "exact_cve_delta": -1,
    "irrelevant_active_line_delta": -3.25,
    "version_fn_delta": 10
  },
  "family_interval_closure_only": {
    "avg_probe_delta": -4.333333333333329,
    "exact_cve_delta": 0,
    "irrelevant_active_line_delta": -1.333333333333334,
    "version_fn_delta": 0
  },
  "hybrid_dynamic_scheduler": {
    "avg_probe_delta": -15.666666666666664,
    "exact_cve_delta": -3,
    "irrelevant_active_line_delta": -4.583333333333333,
    "version_fn_delta": 65
  },
  "late_all_fix_file_scout": {
    "avg_probe_delta": -2.5833333333333286,
    "exact_cve_delta": 0,
    "irrelevant_active_line_delta": -1.333333333333334,
    "version_fn_delta": 0
  },
  "ranked_positive_neighbor": {
    "avg_probe_delta": -4.583333333333329,
    "exact_cve_delta": -2,
    "irrelevant_active_line_delta": -0.5,
    "version_fn_delta": 38
  }
}
