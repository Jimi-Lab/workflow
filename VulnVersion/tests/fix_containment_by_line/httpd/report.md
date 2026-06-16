# Fix Containment by Affected Line

This report checks whether dataset fix commits are contained by release tags on each affected release line.

It does not run BAPEE or patch-equivalence expansion.

## Overall

- total_cves: `30`
- total_affected_lines: `84`
- affected_lines_with_fix: `12`
- affected_lines_without_fix: `72`
- affected_lines_without_fix_rate: `0.8571`
- cves_with_any_affected_line_without_fix: `24`
- cves_all_affected_lines_have_fix: `6`
- cves_with_no_fix_containing_line: `18`

## By Repo

| repo | cves | affected lines | with fix | without fix | without-fix rate | CVEs any no-fix line | CVEs all lines have fix |
|---|---:|---:|---:|---:|---:|---:|---:|
| httpd | 30 | 84 | 12 | 72 | 0.8571 | 24 | 6 |

## Worst CVEs by Affected Lines Without Fix

- `httpd` `CVE-2021-44224`: affected lines `6`, without fix `6`
- `httpd` `CVE-2022-22721`: affected lines `6`, without fix `6`
- `httpd` `CVE-2022-28615`: affected lines `6`, without fix `6`
- `httpd` `CVE-2020-13950`: affected lines `5`, without fix `5`
- `httpd` `CVE-2020-1934`: affected lines `5`, without fix `5`
- `httpd` `CVE-2020-35452`: affected lines `6`, without fix `5`
- `httpd` `CVE-2021-39275`: affected lines `6`, without fix `5`
- `httpd` `CVE-2022-22720`: affected lines `5`, without fix `5`
- `httpd` `CVE-2020-1927`: affected lines `4`, without fix `4`
- `httpd` `CVE-2021-30641`: affected lines `5`, without fix `4`
- `httpd` `CVE-2022-28330`: affected lines `3`, without fix `3`
- `httpd` `CVE-2021-26690`: affected lines `2`, without fix `2`
- `httpd` `CVE-2021-26691`: affected lines `2`, without fix `2`
- `httpd` `CVE-2022-23943`: affected lines `2`, without fix `2`
- `httpd` `CVE-2022-28614`: affected lines `2`, without fix `2`
- `httpd` `CVE-2022-30522`: affected lines `2`, without fix `2`
- `httpd` `CVE-2020-11985`: affected lines `2`, without fix `1`
- `httpd` `CVE-2020-11993`: affected lines `2`, without fix `1`
- `httpd` `CVE-2021-31618`: affected lines `1`, without fix `1`
- `httpd` `CVE-2021-34798`: affected lines `2`, without fix `1`
- `httpd` `CVE-2021-36160`: affected lines `1`, without fix `1`
- `httpd` `CVE-2021-41773`: affected lines `1`, without fix `1`
- `httpd` `CVE-2021-44790`: affected lines `1`, without fix `1`
- `httpd` `CVE-2022-22719`: affected lines `1`, without fix `1`
