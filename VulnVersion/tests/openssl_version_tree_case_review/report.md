# OpenSSL VersionTree Case Review

Dataset: `DataSet\BaseDataOrder.json`

GT is used only for affected-line impact review and final simulator metrics.

## Variant Decision Table

| variant | avg probes | exact CVEs | version FN | unsafe affected CVEs | review affected CVEs | decision |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| current | 79.86 | 48/50 | 1 | 0 | 0 | baseline |
| generic_major_minor_single_family | 57.18 | 48/50 | 1 | 21 | 32 | reject: unsafe cross-origin affected cases |
| major_minor_family_partition | 62.46 | 48/50 | 1 | 0 | 32 | candidate-after-review: lower cost but patch-series merges need review |
| hybrid_patch_series_family_partition | 69.50 | 48/50 | 1 | 0 | 0 | candidate: equivalent to current_plus_merge_mainline_09 in this run |
| current_plus_merge_mainline_09 | 69.50 | 48/50 | 1 | 0 | 0 | candidate: safe-first guarded OpenSSL strategy |

## Interpretation

- `unsafe_cross_origin` means mainline/fips/engine are merged. This must not enter the main path even if GT-oracle metrics do not drop.
- `candidate_legacy_mainline_09_merge` only merges OpenSSL mainline `0.9.x` current lines. This is the safest current cost-saving candidate.
- `review_patch_series_merge` merges current patch-series lines such as `1.0.0/1.0.1/1.0.2` or `1.1.0/1.1.1`. It needs manual case review before adoption.

## Recommendation

Do not use generic_major_minor_single_family for OpenSSL. If source code is changed, first implement a guarded OpenSSL option equivalent to `current_plus_merge_mainline_09`: merge only mainline 0.9.x current lines, keep fips/engine families separate, and keep 1.x patch-series lines unchanged. `major_minor_family_partition` has better probe reduction but should wait for manual review of patch-series affected cases.
