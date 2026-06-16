# Step1 -> Step2 Joint Validation

This simulator validates the Step1 artifact adapter used by Step2.
It does not claim Step3 probe reduction until the Step3 scheduler consumes RootCauseVet.

## Summary

- total_cves: 1128
- completed_cves: 1128
- failed_cves: 0
- cves_with_priority_patterns: 1126
- total_priority_patterns: 12729
- total_certificate_candidates: 0
- wrong_certificate_risk_from_adapter: 0
- stage3_probe_reduction_measured: False

## Per Repo

| repo | cves | failures | avg priority patterns | certificate candidates |
| --- | ---: | ---: | ---: | ---: |
| FFmpeg | 71 | 0 | 10.676 | 0 |
| ImageMagick | 72 | 0 | 7.375 | 0 |
| curl | 68 | 0 | 22.368 | 0 |
| httpd | 30 | 0 | 37.367 | 0 |
| linux | 717 | 0 | 9.821 | 0 |
| openjpeg | 13 | 0 | 6.231 | 0 |
| openssl | 50 | 0 | 13.1 | 0 |
| qemu | 57 | 0 | 7.772 | 0 |
| wireshark | 50 | 0 | 11.54 | 0 |
