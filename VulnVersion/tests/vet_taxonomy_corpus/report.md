# VET Taxonomy Corpus

This corpus is a stratified case-study set for deriving VET archetypes from the VulnVersion dataset.
All archetypes in this report are heuristic seeds and must be reviewed before becoming Step2 rules.

## Summary

- total_cves: 1128
- completed_cves: 1128
- failed_cves: 0
- selected_cases: 81
- target_size: 81

## Selected Cases

| repo | CVE | patch_type | chunks | family | archetype_seed |
| --- | --- | --- | ---: | --- | --- |
| FFmpeg | CVE-2020-22041 | add_only | 12 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2020-14212 | mixed | 46 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2020-22037 | mixed | 32 | multi_commit | status_error_handling_or_logic_correction |
| FFmpeg | CVE-2020-13904 | mixed | 30 | multi_commit | parser_state_or_protocol_invariant |
| FFmpeg | CVE-2022-2566 | mixed | 6 | multi_commit | bounds_length_check |
| ImageMagick | CVE-2023-3195 | add_only | 2 | single_commit | bounds_length_check |
| ImageMagick | CVE-2020-27753 | mixed | 16 | single_commit | missing_guard_added_validation |
| ImageMagick | CVE-2023-3745 | mixed | 4 | multi_commit | bounds_length_check |
| ImageMagick | CVE-2021-39212 | mixed | 5 | multi_commit | unknown_requires_manual_review |
| ImageMagick | CVE-2020-27771 | mixed | 4 | multi_commit | bounds_length_check |
| curl | CVE-2024-2379 | add_only | 4 | single_commit | permission_capability_check |
| curl | CVE-2024-6197 | del_only | 1 | single_commit | unsafe_operation_replacement |
| curl | CVE-2021-22922 | mixed | 89 | single_commit | status_error_handling_or_logic_correction |
| curl | CVE-2023-27536 | add_only | 3 | single_commit | permission_capability_check |
| curl | CVE-2022-32221 | add_only | 1 | single_commit | permission_capability_check |
| httpd | CVE-2021-44790 | add_only | 1 | single_commit | bounds_length_check |
| httpd | CVE-2020-11993 | mixed | 140 | multi_commit | parser_state_or_protocol_invariant |
| httpd | CVE-2020-9490 | mixed | 25 | multi_commit | status_error_handling_or_logic_correction |
| httpd | CVE-2022-23943 | mixed | 29 | multi_commit | bounds_length_check |
| httpd | CVE-2021-33193 | mixed | 37 | single_commit | missing_guard_added_validation |
| linux | CVE-2022-39189 | add_only | 7 | single_commit | permission_capability_check |
| linux | CVE-2022-44034 | del_only | 20 | single_commit | vulnerable_branch_removed |
| linux | CVE-2022-20568 | mixed | 150 | single_commit | permission_capability_check |
| linux | CVE-2022-24448 | add_only | 1 | single_commit | missing_guard_added_validation |
| linux | CVE-2024-26758 | del_only | 1 | single_commit | vulnerable_branch_removed |
| openjpeg | CVE-2020-6851 | add_only | 2 | multi_commit | bounds_length_check |
| openjpeg | CVE-2020-27845 | mixed | 5 | single_commit | bounds_length_check |
| openjpeg | CVE-2020-27844 | mixed | 2 | multi_commit | bounds_length_check |
| openjpeg | CVE-2020-27824 | mixed | 1 | single_commit | unsafe_operation_replacement |
| openjpeg | CVE-2020-27823 | mixed | 1 | single_commit | unsafe_operation_replacement |
| openssl | CVE-2023-0217 | add_only | 5 | single_commit | null_lifetime_refcount |
| openssl | CVE-2022-3996 | del_only | 1 | single_commit | permission_capability_check |
| openssl | CVE-2023-0464 | mixed | 17 | single_commit | permission_capability_check |
| openssl | CVE-2023-2975 | mixed | 1 | single_commit | null_lifetime_refcount |
| openssl | CVE-2022-2097 | mixed | 2 | single_commit | unknown_requires_manual_review |
| qemu | CVE-2020-14394 | add_only | 5 | single_commit | permission_capability_check |
| qemu | CVE-2021-3392 | del_only | 4 | single_commit | permission_capability_check |
| qemu | CVE-2021-3416 | mixed | 15 | multi_commit | bounds_length_check |
| qemu | CVE-2021-3544 | mixed | 5 | multi_commit | unknown_requires_manual_review |
| qemu | CVE-2021-3527 | mixed | 4 | multi_commit | missing_guard_added_validation |
| wireshark | CVE-2020-11647 | add_only | 7 | single_commit | parser_state_or_protocol_invariant |
| wireshark | CVE-2022-0581 | mixed | 22 | single_commit | missing_guard_added_validation |
| wireshark | CVE-2020-7045 | mixed | 21 | single_commit | null_lifetime_refcount |
| wireshark | CVE-2020-28030 | mixed | 4 | single_commit | parser_state_or_protocol_invariant |
| wireshark | CVE-2022-0582 | mixed | 10 | single_commit | null_lifetime_refcount |
| linux | CVE-2022-4095 | del_only | 2 | single_commit | permission_capability_check |
| linux | CVE-2022-28389 | del_only | 1 | single_commit | vulnerable_branch_removed |
| linux | CVE-2022-28390 | del_only | 1 | single_commit | vulnerable_branch_removed |
| linux | CVE-2022-47938 | del_only | 1 | single_commit | unsafe_operation_replacement |
| linux | CVE-2023-0469 | del_only | 1 | single_commit | bounds_length_check |
| FFmpeg | CVE-2020-20451 | add_only | 6 | multi_commit | unknown_requires_manual_review |
| FFmpeg | CVE-2020-22019 | add_only | 6 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2020-22031 | add_only | 6 | multi_commit | bounds_length_check |
| linux | CVE-2022-2602 | add_only | 5 | single_commit | missing_guard_added_validation |
| linux | CVE-2022-27666 | add_only | 5 | single_commit | bounds_length_check |
| curl | CVE-2021-22923 | mixed | 89 | single_commit | status_error_handling_or_logic_correction |
| linux | CVE-2023-52474 | mixed | 39 | single_commit | bounds_length_check |
| curl | CVE-2023-28322 | mixed | 38 | single_commit | permission_capability_check |
| FFmpeg | CVE-2020-22016 | mixed | 19 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2020-20450 | mixed | 16 | multi_commit | null_lifetime_refcount |
| FFmpeg | CVE-2020-22021 | mixed | 16 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2021-38114 | mixed | 16 | multi_commit | status_error_handling_or_logic_correction |
| FFmpeg | CVE-2020-22026 | mixed | 15 | multi_commit | bounds_length_check |
| FFmpeg | CVE-2020-22048 | mixed | 15 | multi_commit | unknown_requires_manual_review |
| FFmpeg | CVE-2020-35964 | mixed | 15 | multi_commit | bounds_length_check |
| httpd | CVE-2022-31813 | mixed | 15 | multi_commit | permission_capability_check |
| FFmpeg | CVE-2020-20453 | mixed | 14 | multi_commit | unknown_requires_manual_review |
| FFmpeg | CVE-2022-48434 | mixed | 14 | multi_commit | parser_state_or_protocol_invariant |
| httpd | CVE-2021-44224 | mixed | 13 | multi_commit | null_lifetime_refcount |
| curl | CVE-2021-22890 | mixed | 36 | single_commit | permission_capability_check |
| linux | CVE-2022-2991 | mixed | 34 | single_commit | bounds_length_check |
| linux | CVE-2024-26690 | mixed | 34 | single_commit | status_error_handling_or_logic_correction |
| httpd | CVE-2020-13950 | mixed | 29 | single_commit | null_lifetime_refcount |
| linux | CVE-2023-5633 | mixed | 29 | single_commit | permission_capability_check |
| linux | CVE-2023-52452 | mixed | 26 | single_commit | bounds_length_check |
| httpd | CVE-2020-11985 | mixed | 3 | single_commit | input_validation_invariant |
| linux | CVE-2023-52578 | mixed | 3 | single_commit | input_validation_invariant |
| wireshark | CVE-2021-4182 | mixed | 3 | single_commit | input_validation_invariant |
| ImageMagick | CVE-2021-4219 | mixed | 2 | single_commit | input_validation_invariant |
| wireshark | CVE-2021-4190 | mixed | 13 | single_commit | missing_guard_added_validation |
| linux | CVE-2023-32252 | mixed | 25 | single_commit | null_lifetime_refcount |

## Use

- Use `selected_dataset.json` for compact multi-stage case studies.
- Use `vet_archetype_seed.jsonl` as Step2 VET drafting input.
- Do not treat `vet_archetype_seed` as ground truth; it is a deterministic seed for manual/agent review.