# Fix Containment by Affected Line

This report checks whether dataset fix commits are contained by release tags on each affected release line.

It does not run BAPEE or patch-equivalence expansion.

## Overall

- total_cves: `72`
- total_affected_lines: `87`
- affected_lines_with_fix: `71`
- affected_lines_without_fix: `16`
- affected_lines_without_fix_rate: `0.1839`
- cves_with_any_affected_line_without_fix: `16`
- cves_all_affected_lines_have_fix: `55`
- cves_with_no_fix_containing_line: `0`

## By Repo

| repo | cves | affected lines | with fix | without fix | without-fix rate | CVEs any no-fix line | CVEs all lines have fix |
|---|---:|---:|---:|---:|---:|---:|---:|
| ImageMagick | 72 | 87 | 71 | 16 | 0.1839 | 16 | 55 |

## Worst CVEs by Affected Lines Without Fix

- `ImageMagick` `CVE-2021-39212`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2021-4219`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2022-0284`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2022-1114`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2022-2719`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2022-28463`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2022-3213`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2022-32545`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2022-32546`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2022-32547`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2023-1289`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2023-1906`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2023-3195`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2023-34474`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2023-34475`: affected lines `2`, without fix `1`
- `ImageMagick` `CVE-2023-5341`: affected lines `2`, without fix `1`
