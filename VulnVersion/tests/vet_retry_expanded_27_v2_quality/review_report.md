# VET Case Review

## Summary

- stage: expanded_27_v2
- dry_run: False
- planned_cases: 27
- completed_cases: 27
- agent_failed_cases: 0
- needs_manual_review_cases: 0
- quality.finding_count: 28
- quality.severity_counts: {'warn': 28}
- quality.step2_admission_ready: False

## Cases

| repo | CVE | patch_type | chunks | family | seed | status |
| --- | --- | --- | ---: | --- | --- | --- |
| FFmpeg | CVE-2020-22019 | add_only | 6 | multi_commit | bounds_length_check | reviewed |
| FFmpeg | CVE-2020-20453 | mixed | 14 | multi_commit | unknown_requires_manual_review | reviewed |
| FFmpeg | CVE-2020-22037 | mixed | 32 | multi_commit | status_error_handling_or_logic_correction | reviewed |
| ImageMagick | CVE-2020-27771 | mixed | 4 | multi_commit | bounds_length_check | reviewed |
| ImageMagick | CVE-2021-4219 | mixed | 2 | single_commit | input_validation_invariant | reviewed |
| ImageMagick | CVE-2021-39212 | mixed | 5 | multi_commit | unknown_requires_manual_review | reviewed |
| curl | CVE-2024-2379 | add_only | 4 | single_commit | permission_capability_check | reviewed |
| curl | CVE-2024-6197 | del_only | 1 | single_commit | unsafe_operation_replacement | reviewed |
| curl | CVE-2021-22922 | mixed | 89 | single_commit | status_error_handling_or_logic_correction | reviewed |
| httpd | CVE-2020-11985 | mixed | 3 | single_commit | input_validation_invariant | reviewed |
| httpd | CVE-2020-9490 | mixed | 25 | multi_commit | status_error_handling_or_logic_correction | reviewed |
| httpd | CVE-2020-11993 | mixed | 140 | multi_commit | parser_state_or_protocol_invariant | reviewed |
| linux | CVE-2022-2602 | add_only | 5 | single_commit | missing_guard_added_validation | reviewed |
| linux | CVE-2022-44034 | del_only | 20 | single_commit | vulnerable_branch_removed | reviewed |
| linux | CVE-2022-47938 | del_only | 1 | single_commit | unsafe_operation_replacement | reviewed |
| openjpeg | CVE-2020-6851 | add_only | 2 | multi_commit | bounds_length_check | reviewed |
| openjpeg | CVE-2020-27823 | mixed | 1 | single_commit | unsafe_operation_replacement | reviewed |
| openjpeg | CVE-2020-27824 | mixed | 1 | single_commit | unsafe_operation_replacement | reviewed |
| openssl | CVE-2023-0217 | add_only | 5 | single_commit | null_lifetime_refcount | reviewed |
| openssl | CVE-2022-2097 | mixed | 2 | single_commit | unknown_requires_manual_review | reviewed |
| openssl | CVE-2022-3996 | del_only | 1 | single_commit | permission_capability_check | reviewed |
| qemu | CVE-2020-14394 | add_only | 5 | single_commit | permission_capability_check | reviewed |
| qemu | CVE-2021-3544 | mixed | 5 | multi_commit | unknown_requires_manual_review | reviewed |
| qemu | CVE-2021-3416 | mixed | 15 | multi_commit | bounds_length_check | reviewed |
| wireshark | CVE-2020-11647 | add_only | 7 | single_commit | parser_state_or_protocol_invariant | reviewed |
| wireshark | CVE-2021-4182 | mixed | 3 | single_commit | input_validation_invariant | reviewed |
| wireshark | CVE-2020-28030 | mixed | 4 | single_commit | parser_state_or_protocol_invariant | reviewed |
