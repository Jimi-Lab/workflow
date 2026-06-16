# Fix Containment by Affected Line

This report checks whether dataset fix commits are contained by release tags on each affected release line.

It does not run BAPEE or patch-equivalence expansion.

## Overall

- total_cves: `13`
- total_affected_lines: `75`
- affected_lines_with_fix: `0`
- affected_lines_without_fix: `75`
- affected_lines_without_fix_rate: `1.0000`
- cves_with_any_affected_line_without_fix: `12`
- cves_all_affected_lines_have_fix: `0`
- cves_with_no_fix_containing_line: `0`

## By Repo

| repo | cves | affected lines | with fix | without fix | without-fix rate | CVEs any no-fix line | CVEs all lines have fix |
|---|---:|---:|---:|---:|---:|---:|---:|
| openjpeg | 13 | 75 | 0 | 75 | 1.0000 | 12 | 0 |

## Worst CVEs by Affected Lines Without Fix

- `openjpeg` `CVE-2020-27824`: affected lines `10`, without fix `10`
- `openjpeg` `CVE-2020-27845`: affected lines `10`, without fix `10`
- `openjpeg` `CVE-2020-27842`: affected lines `9`, without fix `9`
- `openjpeg` `CVE-2020-27843`: affected lines `9`, without fix `9`
- `openjpeg` `CVE-2021-29338`: affected lines `9`, without fix `9`
- `openjpeg` `CVE-2022-1122`: affected lines `9`, without fix `9`
- `openjpeg` `CVE-2020-15389`: affected lines `4`, without fix `4`
- `openjpeg` `CVE-2020-27841`: affected lines `4`, without fix `4`
- `openjpeg` `CVE-2020-8112`: affected lines `4`, without fix `4`
- `openjpeg` `CVE-2020-27814`: affected lines `3`, without fix `3`
- `openjpeg` `CVE-2020-27823`: affected lines `3`, without fix `3`
- `openjpeg` `CVE-2020-6851`: affected lines `1`, without fix `1`
