# Fix Containment by Affected Line

This report checks whether dataset fix commits are contained by release tags on each affected release line.

It does not run BAPEE or patch-equivalence expansion.

## Overall

- total_cves: `50`
- total_affected_lines: `510`
- affected_lines_with_fix: `26`
- affected_lines_without_fix: `484`
- affected_lines_without_fix_rate: `0.9490`
- cves_with_any_affected_line_without_fix: `48`
- cves_all_affected_lines_have_fix: `0`
- cves_with_no_fix_containing_line: `0`

## By Repo

| repo | cves | affected lines | with fix | without fix | without-fix rate | CVEs any no-fix line | CVEs all lines have fix |
|---|---:|---:|---:|---:|---:|---:|---:|
| wireshark | 50 | 510 | 26 | 484 | 0.9490 | 48 | 0 |

## Worst CVEs by Affected Lines Without Fix

- `wireshark` `CVE-2022-0583`: affected lines `24`, without fix `24`
- `wireshark` `CVE-2024-24476`: affected lines `24`, without fix `24`
- `wireshark` `CVE-2024-24478`: affected lines `23`, without fix `23`
- `wireshark` `CVE-2020-26421`: affected lines `21`, without fix `21`
- `wireshark` `CVE-2022-0586`: affected lines `21`, without fix `21`
- `wireshark` `CVE-2021-39923`: affected lines `20`, without fix `20`
- `wireshark` `CVE-2021-4185`: affected lines `26`, without fix `20`
- `wireshark` `CVE-2022-0582`: affected lines `20`, without fix `20`
- `wireshark` `CVE-2020-11647`: affected lines `20`, without fix `19`
- `wireshark` `CVE-2020-13164`: affected lines `20`, without fix `19`
- `wireshark` `CVE-2021-39922`: affected lines `19`, without fix `19`
- `wireshark` `CVE-2021-39924`: affected lines `19`, without fix `19`
- `wireshark` `CVE-2021-39925`: affected lines `18`, without fix `18`
- `wireshark` `CVE-2020-9431`: affected lines `14`, without fix `13`
- `wireshark` `CVE-2021-22191`: affected lines `21`, without fix `13`
- `wireshark` `CVE-2021-22207`: affected lines `12`, without fix `12`
- `wireshark` `CVE-2020-15466`: affected lines `12`, without fix `11`
- `wireshark` `CVE-2020-26420`: affected lines `11`, without fix `11`
- `wireshark` `CVE-2020-28030`: affected lines `11`, without fix `11`
- `wireshark` `CVE-2020-7045`: affected lines `11`, without fix `11`
- `wireshark` `CVE-2022-0581`: affected lines `11`, without fix `11`
- `wireshark` `CVE-2020-9430`: affected lines `11`, without fix `10`
- `wireshark` `CVE-2021-39928`: affected lines `10`, without fix `10`
- `wireshark` `CVE-2021-39929`: affected lines `10`, without fix `10`
- `wireshark` `CVE-2020-26575`: affected lines `8`, without fix `8`
- `wireshark` `CVE-2021-4182`: affected lines `8`, without fix `8`
- `wireshark` `CVE-2022-3190`: affected lines `8`, without fix `8`
- `wireshark` `CVE-2020-25862`: affected lines `8`, without fix `7`
- `wireshark` `CVE-2020-25863`: affected lines `8`, without fix `7`
- `wireshark` `CVE-2020-9428`: affected lines `7`, without fix `6`
- `wireshark` `CVE-2021-4190`: affected lines `6`, without fix `6`
- `wireshark` `CVE-2021-39921`: affected lines `5`, without fix `5`
- `wireshark` `CVE-2021-4181`: affected lines `5`, without fix `5`
- `wireshark` `CVE-2021-4186`: affected lines `5`, without fix `5`
- `wireshark` `CVE-2020-25866`: affected lines `5`, without fix `4`
- `wireshark` `CVE-2020-26418`: affected lines `4`, without fix `4`
- `wireshark` `CVE-2020-9429`: affected lines `4`, without fix `3`
- `wireshark` `CVE-2021-22173`: affected lines `2`, without fix `2`
- `wireshark` `CVE-2021-22174`: affected lines `2`, without fix `2`
- `wireshark` `CVE-2021-22222`: affected lines `2`, without fix `2`
