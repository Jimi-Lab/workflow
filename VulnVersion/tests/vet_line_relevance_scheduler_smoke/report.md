# VET Line Relevance Scheduler Simulator

Dataset: `DataSet/BaseDataOrder.json`.

VET evidence changes only activation priority/gates. It does not emit CERT_ABSENT/CERT_FIXED verdicts.

| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | avg active lines | irrelevant active % | version FN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `base_allfixfile_s4` | 57.90 | 44 | 105 | 19/20 | 1 | 0 | 21.75 | 47.82% | 1 | 1.000000 | 0.999387 | 0.999693 |
| `vet_neighbor_t0.20` | 52.60 | 41 | 104 | 15/20 | 5 | 0 | 19.90 | 49.25% | 90 | 1.000000 | 0.944785 | 0.971609 |
| `vet_neighbor_t0.30` | 52.60 | 41 | 104 | 15/20 | 5 | 0 | 19.90 | 49.25% | 90 | 1.000000 | 0.944785 | 0.971609 |
| `vet_ranked_scout_all_gates_t0.20` | 39.75 | 25 | 82 | 14/20 | 6 | 0 | 13.60 | 30.15% | 145 | 1.000000 | 0.911043 | 0.953451 |
| `vet_ranked_scout_neighbor_t0.20` | 44.30 | 31 | 82 | 14/20 | 6 | 0 | 15.75 | 37.46% | 110 | 1.000000 | 0.932515 | 0.965079 |
| `vet_ranked_scout_neighbor_t0.30` | 44.30 | 31 | 82 | 14/20 | 6 | 0 | 15.75 | 37.46% | 110 | 1.000000 | 0.932515 | 0.965079 |
| `vet_ranked_scout_only` | 50.65 | 36 | 96 | 18/20 | 2 | 0 | 18.10 | 38.12% | 11 | 1.000000 | 0.993252 | 0.996614 |
| `vet_scout_t0.20_neighbor_t0.20` | 44.05 | 31 | 97 | 15/20 | 5 | 0 | 15.55 | 37.94% | 135 | 1.000000 | 0.917178 | 0.956800 |
| `vet_scout_t0.30_neighbor_t0.30` | 44.05 | 31 | 97 | 15/20 | 5 | 0 | 15.55 | 37.94% | 135 | 1.000000 | 0.917178 | 0.956800 |
