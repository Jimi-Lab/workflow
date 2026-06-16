# Fix Containment by Affected Line

This report checks whether dataset fix commits are contained by release tags on each affected release line.

It does not run BAPEE or patch-equivalence expansion.

## Overall

- total_cves: `50`
- total_affected_lines: `1484`
- affected_lines_with_fix: `1`
- affected_lines_without_fix: `1483`
- affected_lines_without_fix_rate: `0.9993`
- cves_with_any_affected_line_without_fix: `50`
- cves_all_affected_lines_have_fix: `0`
- cves_with_no_fix_containing_line: `0`

## By Repo

| repo | cves | affected lines | with fix | without fix | without-fix rate | CVEs any no-fix line | CVEs all lines have fix |
|---|---:|---:|---:|---:|---:|---:|---:|
| linux | 50 | 1484 | 1 | 1483 | 0.9993 | 50 | 0 |

## Worst CVEs by Affected Lines Without Fix

- `linux` `CVE-2023-52615`: affected lines `70`, without fix `70`
- `linux` `CVE-2024-26756`: affected lines `70`, without fix `70`
- `linux` `CVE-2024-26804`: affected lines `70`, without fix `70`
- `linux` `CVE-2023-34256`: affected lines `66`, without fix `66`
- `linux` `CVE-2023-35824`: affected lines `66`, without fix `66`
- `linux` `CVE-2023-0394`: affected lines `64`, without fix `64`
- `linux` `CVE-2022-28390`: affected lines `60`, without fix `60`
- `linux` `CVE-2022-3111`: affected lines `60`, without fix `60`
- `linux` `CVE-2022-1974`: affected lines `58`, without fix `58`
- `linux` `CVE-2022-3061`: affected lines `55`, without fix `55`
- `linux` `CVE-2024-1086`: affected lines `54`, without fix `54`
- `linux` `CVE-2023-35001`: affected lines `53`, without fix `53`
- `linux` `CVE-2022-3594`: affected lines `50`, without fix `50`
- `linux` `CVE-2022-2964`: affected lines `49`, without fix `49`
- `linux` `CVE-2023-4128`: affected lines `48`, without fix `48`
- `linux` `CVE-2023-52469`: affected lines `47`, without fix `47`
- `linux` `CVE-2024-24860`: affected lines `47`, without fix `47`
- `linux` `CVE-2023-0615`: affected lines `44`, without fix `44`
- `linux` `CVE-2022-26490`: affected lines `38`, without fix `38`
- `linux` `CVE-2023-1855`: affected lines `35`, without fix `35`
- `linux` `CVE-2023-52439`: affected lines `31`, without fix `31`
- `linux` `CVE-2022-0435`: affected lines `30`, without fix `30`
- `linux` `CVE-2023-4133`: affected lines `29`, without fix `29`
- `linux` `CVE-2024-0565`: affected lines `29`, without fix `29`
- `linux` `CVE-2024-26589`: affected lines `29`, without fix `29`
- `linux` `CVE-2023-2177`: affected lines `26`, without fix `25`
- `linux` `CVE-2022-38457`: affected lines `23`, without fix `23`
- `linux` `CVE-2023-1075`: affected lines `23`, without fix `23`
- `linux` `CVE-2023-52492`: affected lines `22`, without fix `22`
- `linux` `CVE-2023-23004`: affected lines `20`, without fix `20`
- `linux` `CVE-2022-1055`: affected lines `16`, without fix `16`
- `linux` `CVE-2022-2938`: affected lines `15`, without fix `15`
- `linux` `CVE-2022-1516`: affected lines `11`, without fix `11`
- `linux` `CVE-2023-38427`: affected lines `9`, without fix `9`
- `linux` `CVE-2024-26629`: affected lines `9`, without fix `9`
- `linux` `CVE-2022-1671`: affected lines `7`, without fix `7`
- `linux` `CVE-2022-34494`: affected lines `6`, without fix `6`
- `linux` `CVE-2023-23001`: affected lines `6`, without fix `6`
- `linux` `CVE-2024-26708`: affected lines `6`, without fix `6`
- `linux` `CVE-2022-29156`: affected lines `5`, without fix `5`
