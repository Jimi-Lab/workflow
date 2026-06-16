# Fix Upper-Bound Filter Analysis

This report evaluates using seed fix commits as an upper-bound tag filter.
Candidate tags are release tags that do not contain any seed fix commit.

## Overall

- cves: `411`
- full_gt_coverage_cves: `400`
- has_gt_miss_cves: `7`
- has_unmapped_cves: `4`
- commit_error_cves: `0`
- micro_gt_coverage: `0.994971`
- avg_gt_coverage: `0.9985`
- avg_release_tags: `318.4891`
- avg_candidate_tags: `249.056`
- avg_excluded_tags: `69.4331`
- avg_candidate_tag_rate: `0.7842`
- avg_tag_reduction_rate: `0.2158`
- avg_release_lines: `22.6204`
- avg_candidate_lines: `18.2822`
- avg_fully_excluded_lines: `4.3382`
- avg_affected_lines: `6.674`

## By Repo

| repo | cves | full GT coverage | micro coverage | avg candidate tag rate | avg tag reduction | avg lines | avg candidate lines | avg fully excluded lines |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 67 | 0.998515 | 0.868 | 0.132 | 36.0 | 28.0282 | 7.9718 |
| ImageMagick | 72 | 72 | 1.0 | 0.5821 | 0.4179 | 2.0 | 1.2639 | 0.7361 |
| curl | 68 | 64 | 1.0 | 0.8373 | 0.1627 | 1.0 | 1.0 | 0.0 |
| httpd | 30 | 30 | 1.0 | 0.9608 | 0.0392 | 7.0 | 7.0 | 0.0 |
| openjpeg | 13 | 13 | 1.0 | 0.7343 | 0.2657 | 12.0 | 10.1538 | 1.8462 |
| openssl | 50 | 50 | 1.0 | 0.9501 | 0.0499 | 24.0 | 23.7 | 0.3 |
| qemu | 57 | 56 | 0.999543 | 0.6096 | 0.3904 | 59.0 | 44.9123 | 14.0877 |
| wireshark | 50 | 48 | 0.977964 | 0.8246 | 0.1754 | 32.0 | 25.56 | 6.44 |

## Worst Misses

- `wireshark` `CVE-2021-22191`: missed `123` / `401`, coverage `0.693267`, candidate rate `0.751244`
- `wireshark` `CVE-2021-4185`: missed `72` / `455`, coverage `0.841758`, candidate rate `0.835821`
- `FFmpeg` `CVE-2020-22019`: missed `4` / `36`, coverage `0.888889`, candidate rate `0.839895`
- `FFmpeg` `CVE-2021-38114`: missed `4` / `315`, coverage `0.987302`, candidate rate `0.816273`
- `FFmpeg` `CVE-2020-20451`: missed `3` / `227`, coverage `0.986784`, candidate rate `0.834646`
- `FFmpeg` `CVE-2022-48434`: missed `3` / `224`, coverage `0.986607`, candidate rate `0.981627`
- `qemu` `CVE-2021-3409`: missed `1` / `60`, coverage `0.983333`, candidate rate `0.586735`
