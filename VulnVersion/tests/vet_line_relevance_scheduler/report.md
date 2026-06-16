# VET Line Relevance Scheduler Simulator

Dataset: `DataSet/BaseDataOrder.json`.

VET evidence changes only activation priority/gates. It does not emit CERT_ABSENT/CERT_FIXED verdicts.

| strategy | avg probes | p50 | p95 | exact | FN CVEs | FP CVEs | avg active lines | irrelevant active % | version FN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `base_allfixfile_s4` | 45.06 | 39 | 92 | 1115/1128 | 9 | 4 | 33.02 | 47.90% | 10 | 0.999797 | 0.999831 | 0.999814 |
| `vet_neighbor_t0.20` | 43.01 | 38 | 84 | 993/1128 | 131 | 4 | 31.68 | 48.51% | 1680 | 0.999791 | 0.971590 | 0.985489 |
| `vet_neighbor_t0.30` | 43.01 | 38 | 84 | 993/1128 | 131 | 4 | 31.68 | 48.51% | 1680 | 0.999791 | 0.971590 | 0.985489 |
| `vet_ranked_scout_all_gates_t0.20` | 31.47 | 22 | 76 | 982/1128 | 142 | 4 | 22.63 | 29.52% | 2622 | 0.999788 | 0.955660 | 0.977226 |
| `vet_ranked_scout_neighbor_t0.20` | 34.63 | 24 | 77 | 1020/1128 | 104 | 4 | 24.93 | 34.67% | 2074 | 0.999790 | 0.964927 | 0.982049 |
| `vet_ranked_scout_neighbor_t0.30` | 34.63 | 24 | 77 | 1020/1128 | 104 | 4 | 24.93 | 34.67% | 2074 | 0.999790 | 0.964927 | 0.982049 |
| `vet_ranked_scout_only` | 36.75 | 26 | 82 | 1110/1128 | 14 | 4 | 26.19 | 34.41% | 50 | 0.999797 | 0.999154 | 0.999476 |
| `vet_scout_t0.20_neighbor_t0.20` | 37.45 | 32 | 80 | 996/1128 | 128 | 4 | 27.37 | 41.29% | 2454 | 0.999788 | 0.958501 | 0.978709 |
| `vet_scout_t0.30_neighbor_t0.30` | 37.45 | 32 | 80 | 996/1128 | 128 | 4 | 27.37 | 41.29% | 2454 | 0.999788 | 0.958501 | 0.978709 |
