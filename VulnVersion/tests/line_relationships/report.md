# Step3 Line Relationship Analysis

This report analyzes affected-version patterns over release lines and line-family order.

## Overall

- total_cves: `1128`
- line_level_contiguous_cves: `1111`
- line_level_multirun_cves: `17`
- line_avg: `60.36`
- affected_line_avg: `17.21`
- max_line_run_count: `3`
- total_line_gap_count: `26`

## Endpoint Shapes

- `aa_full`: `18636`
- `aa_gap`: `4`
- `an_prefix_like`: `558`
- `na_suffix_like`: `112`
- `nn_empty`: `48683`
- `nn_middle`: `98`

## Line Shapes

- `full`: `18636`
- `middle`: `98`
- `multi_interval`: `8`
- `none`: `48683`
- `prefix`: `556`
- `suffix`: `110`

## By Repo

| repo | cves | lines avg | affected lines avg | line contiguous CVEs | multirun CVEs | max runs | endpoint nn_middle | endpoint aa_gap |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 36.0 | 12.28 | 71 | 0 | 1 | 0 | 1 |
| ImageMagick | 72 | 2.0 | 1.21 | 72 | 0 | 1 | 15 | 0 |
| curl | 68 | 1.0 | 1.0 | 68 | 0 | 1 | 64 | 0 |
| httpd | 30 | 7.0 | 2.8 | 29 | 1 | 2 | 14 | 0 |
| linux | 717 | 82.0 | 23.24 | 717 | 0 | 1 | 0 | 0 |
| openjpeg | 13 | 12.0 | 5.77 | 13 | 0 | 1 | 0 | 0 |
| openssl | 50 | 24.0 | 2.98 | 38 | 12 | 3 | 2 | 1 |
| qemu | 57 | 59.0 | 15.75 | 57 | 0 | 1 | 0 | 1 |
| wireshark | 50 | 32.0 | 10.2 | 46 | 4 | 2 | 3 | 1 |

## Worst Multi-Run CVEs

- `openssl` `CVE-2022-4304`: affected lines `6`, max runs `3`, gaps `2`
- `wireshark` `CVE-2020-11647`: affected lines `20`, max runs `2`, gaps `4`
- `wireshark` `CVE-2024-24476`: affected lines `24`, max runs `2`, gaps `4`
- `wireshark` `CVE-2022-0586`: affected lines `21`, max runs `2`, gaps `3`
- `httpd` `CVE-2020-11993`: affected lines `2`, max runs `2`, gaps `1`
- `openssl` `CVE-2021-23840`: affected lines `2`, max runs `2`, gaps `1`
- `openssl` `CVE-2021-3712`: affected lines `2`, max runs `2`, gaps `1`
- `openssl` `CVE-2021-4160`: affected lines `3`, max runs `2`, gaps `1`
- `openssl` `CVE-2022-0778`: affected lines `3`, max runs `2`, gaps `1`
- `openssl` `CVE-2022-1292`: affected lines `3`, max runs `2`, gaps `1`
- `openssl` `CVE-2022-2068`: affected lines `3`, max runs `2`, gaps `1`
- `openssl` `CVE-2023-0286`: affected lines `3`, max runs `2`, gaps `1`
- `openssl` `CVE-2023-0466`: affected lines `4`, max runs `2`, gaps `1`
- `openssl` `CVE-2023-3446`: affected lines `4`, max runs `2`, gaps `1`
- `openssl` `CVE-2023-5678`: affected lines `4`, max runs `2`, gaps `1`
- `openssl` `CVE-2024-0727`: affected lines `5`, max runs `2`, gaps `1`
- `wireshark` `CVE-2021-22235`: affected lines `2`, max runs `2`, gaps `1`
