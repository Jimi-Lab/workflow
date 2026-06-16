# Fix Containment by Affected Line

This report checks whether dataset fix commits are contained by release tags on each affected release line.

It does not run BAPEE or patch-equivalence expansion.

## Overall

- total_cves: `57`
- total_affected_lines: `898`
- affected_lines_with_fix: `2`
- affected_lines_without_fix: `896`
- affected_lines_without_fix_rate: `0.9978`
- cves_with_any_affected_line_without_fix: `54`
- cves_all_affected_lines_have_fix: `0`
- cves_with_no_fix_containing_line: `0`

## By Repo

| repo | cves | affected lines | with fix | without fix | without-fix rate | CVEs any no-fix line | CVEs all lines have fix |
|---|---:|---:|---:|---:|---:|---:|---:|
| qemu | 57 | 898 | 2 | 896 | 0.9978 | 54 | 0 |

## Worst CVEs by Affected Lines Without Fix

- `qemu` `CVE-2020-25625`: affected lines `43`, without fix `43`
- `qemu` `CVE-2021-3507`: affected lines `43`, without fix `43`
- `qemu` `CVE-2021-20221`: affected lines `36`, without fix `36`
- `qemu` `CVE-2020-13361`: affected lines `35`, without fix `35`
- `qemu` `CVE-2020-25624`: affected lines `35`, without fix `35`
- `qemu` `CVE-2021-20257`: affected lines `35`, without fix `35`
- `qemu` `CVE-2021-4206`: affected lines `35`, without fix `35`
- `qemu` `CVE-2022-0216`: affected lines `34`, without fix `34`
- `qemu` `CVE-2021-3930`: affected lines `31`, without fix `31`
- `qemu` `CVE-2020-12829`: affected lines `30`, without fix `30`
- `qemu` `CVE-2021-3527`: affected lines `30`, without fix `30`
- `qemu` `CVE-2021-20181`: affected lines `29`, without fix `29`
- `qemu` `CVE-2021-3682`: affected lines `29`, without fix `29`
- `qemu` `CVE-2020-13765`: affected lines `29`, without fix `28`
- `qemu` `CVE-2020-25723`: affected lines `28`, without fix `28`
- `qemu` `CVE-2021-3416`: affected lines `28`, without fix `28`
- `qemu` `CVE-2021-3748`: affected lines `28`, without fix `28`
- `qemu` `CVE-2020-15863`: affected lines `26`, without fix `26`
- `qemu` `CVE-2021-20203`: affected lines `26`, without fix `26`
- `qemu` `CVE-2021-3713`: affected lines `26`, without fix `26`
- `qemu` `CVE-2021-4207`: affected lines `26`, without fix `26`
- `qemu` `CVE-2020-25084`: affected lines `25`, without fix `25`
- `qemu` `CVE-2020-11947`: affected lines `24`, without fix `24`
- `qemu` `CVE-2020-25085`: affected lines `23`, without fix `23`
- `qemu` `CVE-2021-3409`: affected lines `24`, without fix `23`
- `qemu` `CVE-2020-14394`: affected lines `15`, without fix `15`
- `qemu` `CVE-2021-3392`: affected lines `15`, without fix `15`
- `qemu` `CVE-2021-3582`: affected lines `10`, without fix `10`
- `qemu` `CVE-2021-3607`: affected lines `10`, without fix `10`
- `qemu` `CVE-2021-3608`: affected lines `10`, without fix `10`
- `qemu` `CVE-2024-42474`: affected lines `8`, without fix `8`
- `qemu` `CVE-2020-1711`: affected lines `6`, without fix `6`
- `qemu` `CVE-2021-3544`: affected lines `6`, without fix `6`
- `qemu` `CVE-2021-3545`: affected lines `6`, without fix `6`
- `qemu` `CVE-2021-3546`: affected lines `6`, without fix `6`
- `qemu` `CVE-2022-26354`: affected lines `5`, without fix `5`
- `qemu` `CVE-2020-13800`: affected lines `4`, without fix `4`
- `qemu` `CVE-2021-3929`: affected lines `4`, without fix `4`
- `qemu` `CVE-2022-0358`: affected lines `4`, without fix `4`
- `qemu` `CVE-2022-3165`: affected lines `4`, without fix `4`
