# Affected Version Monotonicity / Contiguity Report

This report checks whether each CVE's `affected_version` forms a contiguous subset on each repo release line.

Definitions:
- `contiguous subset`: after mapping affected tags onto one line and sorting by version, their indices form one continuous interval.
- `input monotonic`: the original dataset order, restricted to one line, is non-decreasing by version index.

## Overall

- total_cves: `1128`
- all_lines_contiguous_cves: `1121`
- has_noncontiguous_line_cves: `7`
- all_lines_input_monotonic_cves: `1077`
- has_nonmonotonic_input_line_cves: `51`
- fully_mapped_cves: `1124`
- partially_or_unmapped_cves: `4`

## By Repo

| repo | cves | contiguous_cves | noncontiguous_cves | input_monotonic_cves | fully_mapped | noncontiguous_lines |
|---|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 70 | 1 | 71 | 71 | 2 |
| ImageMagick | 72 | 70 | 2 | 72 | 72 | 2 |
| curl | 68 | 68 | 0 | 68 | 64 | 0 |
| httpd | 30 | 30 | 0 | 30 | 30 | 0 |
| linux | 717 | 717 | 0 | 717 | 717 | 0 |
| openjpeg | 13 | 13 | 0 | 13 | 13 | 0 |
| openssl | 50 | 49 | 1 | 47 | 50 | 1 |
| qemu | 57 | 56 | 1 | 57 | 57 | 1 |
| wireshark | 50 | 48 | 2 | 2 | 50 | 2 |

## Top Noncontiguous Repo Lines

- `FFmpeg` / line `4.1`: `1` CVEs
- `FFmpeg` / line `4.2`: `1` CVEs
- `wireshark` / line `1.12`: `1` CVEs
- `wireshark` / line `3.2`: `1` CVEs
- `qemu` / line `2.4`: `1` CVEs
- `openssl` / line `1.1.0`: `1` CVEs
- `ImageMagick` / line `7.1`: `1` CVEs
- `ImageMagick` / line `7.0`: `1` CVEs
