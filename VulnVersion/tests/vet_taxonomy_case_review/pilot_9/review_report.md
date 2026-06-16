# VET Case Review

## Summary

- stage: pilot_9
- dry_run: False
- planned_cases: 9
- completed_cases: 9
- agent_failed_cases: 0
- needs_manual_review_cases: 0
- quality.finding_count: 45
- quality.severity_counts: {'warn': 45}
- quality.step2_admission_ready: False

## Cases

| repo | CVE | patch_type | chunks | family | seed | status |
| --- | --- | --- | ---: | --- | --- | --- |
| FFmpeg | CVE-2020-22019 | add_only | None | None | bounds_length_check | reviewed |
| ImageMagick | CVE-2020-27771 | mixed | None | None | bounds_length_check | reviewed |
| curl | CVE-2024-2379 | add_only | None | None | permission_capability_check | reviewed |
| httpd | CVE-2020-11985 | mixed | None | None | input_validation_invariant | reviewed |
| linux | CVE-2022-2602 | add_only | None | None | missing_guard_added_validation | reviewed |
| openjpeg | CVE-2020-6851 | add_only | None | None | bounds_length_check | reviewed |
| openssl | CVE-2023-0217 | add_only | None | None | null_lifetime_refcount | reviewed |
| qemu | CVE-2020-14394 | add_only | None | None | permission_capability_check | reviewed |
| wireshark | CVE-2020-11647 | add_only | None | None | parser_state_or_protocol_invariant | reviewed |
