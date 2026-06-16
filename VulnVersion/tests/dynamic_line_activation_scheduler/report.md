# Dynamic Line Activation Scheduler Simulator

Dataset: `DataSet\BaseDataOrder.json`

GT is used only as the simulator oracle. VET evidence changes priority/order only.

| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | avg active lines | irrelevant active % | version FN | P | R | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `control_transition_scout_s4_expand2_allfixfile_s4` | 45.06 | 39 | 92 | 1115/1128 | 9 | 4 | 33.02 | 47.90% | 10 | 0.999797 | 0.999831 | 0.999814 |
| `family_interval_closure_only` | 42.88 | 37 | 87 | 1106/1128 | 18 | 4 | 31.80 | 45.93% | 208 | 0.999796 | 0.996483 | 0.998137 |
| `evidence_ranked_scout_queue` | 36.75 | 26 | 82 | 1110/1128 | 14 | 4 | 26.19 | 34.41% | 50 | 0.999797 | 0.999154 | 0.999476 |
| `late_all_fix_file_scout` | 42.42 | 37 | 86 | 1112/1128 | 12 | 4 | 30.81 | 44.24% | 38 | 0.999797 | 0.999357 | 0.999577 |
| `ranked_positive_neighbor` | 43.01 | 38 | 84 | 993/1128 | 131 | 4 | 31.68 | 48.51% | 1680 | 0.999791 | 0.971590 | 0.985489 |
| `hybrid_dynamic_scheduler` | 32.96 | 23 | 75 | 1010/1128 | 114 | 4 | 23.96 | 32.07% | 2308 | 0.999789 | 0.960970 | 0.979995 |

## Deltas vs Control

{
  "evidence_ranked_scout_queue": {
    "avg_probe_delta": -8.311170212765958,
    "exact_cve_delta": -5,
    "irrelevant_active_line_delta": -6.807624113475178,
    "version_fn_delta": 40
  },
  "family_interval_closure_only": {
    "avg_probe_delta": -2.1852836879432616,
    "exact_cve_delta": -9,
    "irrelevant_active_line_delta": -1.210106382978724,
    "version_fn_delta": 198
  },
  "hybrid_dynamic_scheduler": {
    "avg_probe_delta": -12.10372340425532,
    "exact_cve_delta": -105,
    "irrelevant_active_line_delta": -8.132978723404257,
    "version_fn_delta": 2298
  },
  "late_all_fix_file_scout": {
    "avg_probe_delta": -2.6436170212765973,
    "exact_cve_delta": -3,
    "irrelevant_active_line_delta": -2.1861702127659584,
    "version_fn_delta": 28
  },
  "ranked_positive_neighbor": {
    "avg_probe_delta": -2.0531914893617014,
    "exact_cve_delta": -122,
    "irrelevant_active_line_delta": -0.44769503546099365,
    "version_fn_delta": 1670
  }
}

## Admission Decision

No dynamic policy in this run is ready to replace the control scheduler.

- `evidence_ranked_scout_queue` reduces avg probes and irrelevant lines, but adds version FN.
- `late_all_fix_file_scout` is the safest cost-reduction candidate, but still adds version FN.
- `ranked_positive_neighbor` and `hybrid_dynamic_scheduler` are unsafe with the current evidence score.
- Current cheap VET evidence can guide priority, but is not reliable enough to defer affected lines safely.
