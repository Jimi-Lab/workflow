# Branch Boundary Root Cause Audit

- Mode: deterministic, no model, pre-change audit
- Cases: 30
- Input candidates: 61
- Unmaterialized blame variant SHAs: 20

## Taxonomy

- blame_variant_not_materialized: 13
- branch_grouping_error: 2
- converter_state_error: 4
- fix_equivalence_error: 2
- judge_over_abstention: 12
- prerequisite_semantics_error: 4

## CVE-2020-11984 Global AND Reproduction

- Maintenance candidate 99c59e refs: origin/2.4.x, origin/2.4.x-mpm_fdqueue, origin/tlsv1.3-for-2.4.x
- Trunk candidate 23394f refs: trunk, origin, origin/trunk, origin/trunk-ssl-handshake-nonblocking
- Maintenance fix 0c543e refs: origin/2.4.x
- Trunk fix fb08e4 refs: trunk, origin, origin/trunk, origin/trunk-ssl-handshake-nonblocking
- 99c59e -> 0c543e: True
- 23394f -> fb08e4: True
- 0c543e -> fb08e4: False
- fb08e4 -> 0c543e: False
- v1.1 fix semantics: all_patch_families
- v1.1 prediction count: 0

v1.1 requires all patch families and all selected prerequisites in one global group. The 2.4.x activation/fix and trunk prerequisite/fix are DAG-divergent. No release tag can satisfy both branch-local boundary conditions and both fixes, so the global state produces an empty prediction.

## Per-CVE Attribution

| CVE | Repo | Candidates | Selected | Prediction | Taxonomy |
|---|---|---:|---:|---:|---|
| CVE-2020-10251 | ImageMagick | 2 | 1 | 0 | blame_variant_not_materialized, converter_state_error, prerequisite_semantics_error |
| CVE-2020-10702 | qemu | 1 | 1 | 6 | none |
| CVE-2020-11647 | wireshark | 3 | 0 | 0 | blame_variant_not_materialized, judge_over_abstention |
| CVE-2020-11869 | qemu | 2 | 2 | 4 | none |
| CVE-2020-11947 | qemu | 1 | 1 | 64 | none |
| CVE-2020-11984 | httpd | 3 | 2 | 0 | blame_variant_not_materialized, branch_grouping_error, converter_state_error, fix_equivalence_error, prerequisite_semantics_error |
| CVE-2020-11985 | httpd | 1 | 1 | 0 | converter_state_error, prerequisite_semantics_error |
| CVE-2020-11993 | httpd | 1 | 0 | 0 | blame_variant_not_materialized, judge_over_abstention |
| CVE-2020-12284 | FFmpeg | 1 | 0 | 0 | judge_over_abstention |
| CVE-2020-13164 | wireshark | 2 | 2 | 574 | none |
| CVE-2020-13904 | FFmpeg | 5 | 0 | 0 | blame_variant_not_materialized, branch_grouping_error, fix_equivalence_error, judge_over_abstention |
| CVE-2020-14212 | FFmpeg | 3 | 0 | 0 | judge_over_abstention |
| CVE-2020-15389 | openjpeg | 3 | 0 | 0 | blame_variant_not_materialized, judge_over_abstention |
| CVE-2020-15466 | wireshark | 2 | 0 | 0 | blame_variant_not_materialized, judge_over_abstention |
| CVE-2020-19667 | ImageMagick | 3 | 0 | 0 | blame_variant_not_materialized, judge_over_abstention |
| CVE-2020-1967 | openssl | 1 | 1 | 3 | none |
| CVE-2020-1971 | openssl | 2 | 0 | 0 | blame_variant_not_materialized, judge_over_abstention |
| CVE-2020-25663 | ImageMagick | 2 | 0 | 0 | blame_variant_not_materialized, judge_over_abstention |
| CVE-2020-27814 | openjpeg | 1 | 0 | 0 | judge_over_abstention |
| CVE-2020-27823 | openjpeg | 1 | 1 | 3 | none |
| CVE-2020-8169 | curl | 4 | 1 | 14 | none |
| CVE-2020-8177 | curl | 3 | 2 | 14 | none |
| CVE-2020-8231 | curl | 2 | 1 | 62 | blame_variant_not_materialized |
| CVE-2021-23840 | openssl | 2 | 1 | 8 | none |
| CVE-2022-0171 | linux | 2 | 1 | 0 | blame_variant_not_materialized, converter_state_error, prerequisite_semantics_error |
| CVE-2022-0185 | linux | 1 | 1 | 16 | none |
| CVE-2022-0264 | linux | 1 | 1 | 4 | none |
| CVE-2022-0286 | linux | 2 | 1 | 5 | blame_variant_not_materialized |
| CVE-2022-0322 | linux | 1 | 1 | 25 | none |
| CVE-2022-0433 | linux | 3 | 0 | 0 | judge_over_abstention |

## Scope

- This audit does not use affected-version ground truth to construct candidates, branches, rules, or prompts.
- It does not call OpenCode or DeepSeek.
- Candidate commits remain raw candidates and are not validated BICs.
