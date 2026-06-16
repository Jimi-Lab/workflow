# Fix Containment by Affected Line

This report checks whether dataset fix commits are contained by release tags on each affected release line.

It does not run BAPEE or patch-equivalence expansion.

## Overall

- total_cves: `50`
- total_affected_lines: `149`
- affected_lines_with_fix: `48`
- affected_lines_without_fix: `101`
- affected_lines_without_fix_rate: `0.6779`
- cves_with_any_affected_line_without_fix: `36`
- cves_all_affected_lines_have_fix: `14`
- cves_with_no_fix_containing_line: `0`

## By Repo

| repo | cves | affected lines | with fix | without fix | without-fix rate | CVEs any no-fix line | CVEs all lines have fix |
|---|---:|---:|---:|---:|---:|---:|---:|
| openssl | 50 | 149 | 48 | 101 | 0.6779 | 36 | 14 |

## Worst CVEs by Affected Lines Without Fix

- `openssl` `CVE-2024-9143`: affected lines `10`, without fix `9`
- `openssl` `CVE-2024-5535`: affected lines `9`, without fix `8`
- `openssl` `CVE-2020-1971`: affected lines `6`, without fix `5`
- `openssl` `CVE-2022-4304`: affected lines `6`, without fix `5`
- `openssl` `CVE-2023-0464`: affected lines `5`, without fix `4`
- `openssl` `CVE-2023-0465`: affected lines `5`, without fix `4`
- `openssl` `CVE-2023-2650`: affected lines `4`, without fix `4`
- `openssl` `CVE-2023-3817`: affected lines `5`, without fix `4`
- `openssl` `CVE-2024-0727`: affected lines `5`, without fix `4`
- `openssl` `CVE-2024-4741`: affected lines `5`, without fix `4`
- `openssl` `CVE-2023-0215`: affected lines `4`, without fix `3`
- `openssl` `CVE-2023-0466`: affected lines `4`, without fix `3`
- `openssl` `CVE-2023-3446`: affected lines `4`, without fix `3`
- `openssl` `CVE-2023-5678`: affected lines `4`, without fix `3`
- `openssl` `CVE-2024-2511`: affected lines `4`, without fix `3`
- `openssl` `CVE-2024-4603`: affected lines `4`, without fix `3`
- `openssl` `CVE-2024-6119`: affected lines `4`, without fix `3`
- `openssl` `CVE-2021-23841`: affected lines `3`, without fix `2`
- `openssl` `CVE-2021-4160`: affected lines `3`, without fix `2`
- `openssl` `CVE-2022-0778`: affected lines `3`, without fix `2`
- `openssl` `CVE-2022-1292`: affected lines `3`, without fix `2`
- `openssl` `CVE-2022-1473`: affected lines `3`, without fix `2`
- `openssl` `CVE-2022-2068`: affected lines `3`, without fix `2`
- `openssl` `CVE-2023-0286`: affected lines `3`, without fix `2`
- `openssl` `CVE-2023-4807`: affected lines `3`, without fix `2`
- `openssl` `CVE-2023-6129`: affected lines `3`, without fix `2`
- `openssl` `CVE-2023-6237`: affected lines `3`, without fix `2`
- `openssl` `CVE-2021-23840`: affected lines `2`, without fix `1`
- `openssl` `CVE-2021-3712`: affected lines `2`, without fix `1`
- `openssl` `CVE-2021-4044`: affected lines `2`, without fix `1`
- `openssl` `CVE-2022-2097`: affected lines `2`, without fix `1`
- `openssl` `CVE-2022-2274`: affected lines `1`, without fix `1`
- `openssl` `CVE-2022-4450`: affected lines `2`, without fix `1`
- `openssl` `CVE-2023-1255`: affected lines `2`, without fix `1`
- `openssl` `CVE-2023-2975`: affected lines `2`, without fix `1`
- `openssl` `CVE-2023-5363`: affected lines `2`, without fix `1`
