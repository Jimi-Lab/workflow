# Fix Upper-Bound Filter Analysis

This report evaluates using seed fix commits as an upper-bound tag filter.
Candidate tags are release tags that do not contain any seed fix commit.

## Overall

- cves: `1128`
- full_gt_coverage_cves: `1082`
- has_gt_miss_cves: `42`
- has_unmapped_cves: `4`
- commit_error_cves: `0`
- micro_gt_coverage: `0.995434`
- avg_gt_coverage: `0.9942`
- avg_release_tags: `185.9654`
- avg_candidate_tags: `150.0443`
- avg_excluded_tags: `35.9211`
- avg_candidate_tag_rate: `0.8248`
- avg_tag_reduction_rate: `0.1752`
- avg_release_lines: `60.3644`
- avg_candidate_lines: `48.1613`
- avg_fully_excluded_lines: `12.203`
- avg_affected_lines: `17.2057`

## By Repo

| repo | cves | full GT coverage | micro coverage | avg candidate tag rate | avg tag reduction | avg lines | avg candidate lines | avg fully excluded lines |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 67 | 0.998515 | 0.868 | 0.132 | 36.0 | 28.0282 | 7.9718 |
| ImageMagick | 72 | 72 | 1.0 | 0.5821 | 0.4179 | 2.0 | 1.2639 | 0.7361 |
| curl | 68 | 64 | 1.0 | 0.8373 | 0.1627 | 1.0 | 1.0 | 0.0 |
| httpd | 30 | 30 | 1.0 | 0.9608 | 0.0392 | 7.0 | 7.0 | 0.0 |
| linux | 717 | 682 | 0.996547 | 0.8481 | 0.1519 | 82.0 | 65.2887 | 16.7113 |
| openjpeg | 13 | 13 | 1.0 | 0.7343 | 0.2657 | 12.0 | 10.1538 | 1.8462 |
| openssl | 50 | 50 | 1.0 | 0.9501 | 0.0499 | 24.0 | 23.7 | 0.3 |
| qemu | 57 | 56 | 0.999543 | 0.6096 | 0.3904 | 59.0 | 44.9123 | 14.0877 |
| wireshark | 50 | 48 | 0.977964 | 0.8246 | 0.1754 | 32.0 | 25.56 | 6.44 |

## Worst Misses

- `wireshark` `CVE-2021-22191`: missed `123` / `401`, coverage `0.693267`, candidate rate `0.751244`
- `wireshark` `CVE-2021-4185`: missed `72` / `455`, coverage `0.841758`, candidate rate `0.835821`
- `linux` `CVE-2023-5178`: missed `26` / `26`, coverage `0.0`, candidate rate `0.636364`
- `FFmpeg` `CVE-2020-22019`: missed `4` / `36`, coverage `0.888889`, candidate rate `0.839895`
- `FFmpeg` `CVE-2021-38114`: missed `4` / `315`, coverage `0.987302`, candidate rate `0.816273`
- `FFmpeg` `CVE-2020-20451`: missed `3` / `227`, coverage `0.986784`, candidate rate `0.834646`
- `FFmpeg` `CVE-2022-48434`: missed `3` / `224`, coverage `0.986607`, candidate rate `0.981627`
- `linux` `CVE-2022-1729`: missed `1` / `40`, coverage `0.975`, candidate rate `0.8`
- `linux` `CVE-2022-20158`: missed `1` / `85`, coverage `0.988235`, candidate rate `0.790909`
- `linux` `CVE-2022-20368`: missed `1` / `85`, coverage `0.988235`, candidate rate `0.790909`
- `linux` `CVE-2022-20423`: missed `1` / `1`, coverage `0.0`, candidate rate `0.790909`
- `linux` `CVE-2022-2308`: missed `1` / `6`, coverage `0.833333`, candidate rate `0.818182`
- `linux` `CVE-2022-3105`: missed `1` / `17`, coverage `0.941176`, candidate rate `0.781818`
- `linux` `CVE-2022-3107`: missed `1` / `20`, coverage `0.95`, candidate rate `0.790909`
- `linux` `CVE-2022-36402`: missed `1` / `44`, coverage `0.977273`, candidate rate `0.863636`
- `linux` `CVE-2022-3643`: missed `1` / `44`, coverage `0.977273`, candidate rate `0.827273`
- `linux` `CVE-2022-36946`: missed `1` / `87`, coverage `0.988506`, candidate rate `0.809091`
- `linux` `CVE-2022-42328`: missed `1` / `6`, coverage `0.833333`, candidate rate `0.827273`
- `linux` `CVE-2022-42329`: missed `1` / `6`, coverage `0.833333`, candidate rate `0.827273`
- `linux` `CVE-2022-4378`: missed `1` / `14`, coverage `0.928571`, candidate rate `0.827273`
