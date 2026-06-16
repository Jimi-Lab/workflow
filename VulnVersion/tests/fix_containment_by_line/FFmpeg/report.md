# Fix Containment by Affected Line

This report checks whether dataset fix commits are contained by release tags on each affected release line.

It does not run BAPEE or patch-equivalence expansion.

## Overall

- total_cves: `71`
- total_affected_lines: `872`
- affected_lines_with_fix: `165`
- affected_lines_without_fix: `707`
- affected_lines_without_fix_rate: `0.8108`
- cves_with_any_affected_line_without_fix: `63`
- cves_all_affected_lines_have_fix: `6`
- cves_with_no_fix_containing_line: `0`

## By Repo

| repo | cves | affected lines | with fix | without fix | without-fix rate | CVEs any no-fix line | CVEs all lines have fix |
|---|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 872 | 165 | 707 | 0.8108 | 63 | 6 |

## Worst CVEs by Affected Lines Without Fix

- `FFmpeg` `CVE-2023-47342`: affected lines `32`, without fix `31`
- `FFmpeg` `CVE-2022-3341`: affected lines `30`, without fix `30`
- `FFmpeg` `CVE-2022-3109`: affected lines `28`, without fix `28`
- `FFmpeg` `CVE-2020-20450`: affected lines `28`, without fix `27`
- `FFmpeg` `CVE-2020-22043`: affected lines `27`, without fix `27`
- `FFmpeg` `CVE-2020-22039`: affected lines `26`, without fix `26`
- `FFmpeg` `CVE-2020-22049`: affected lines `25`, without fix `25`
- `FFmpeg` `CVE-2021-3566`: affected lines `25`, without fix `25`
- `FFmpeg` `CVE-2020-22016`: affected lines `27`, without fix `24`
- `FFmpeg` `CVE-2020-20902`: affected lines `23`, without fix `23`
- `FFmpeg` `CVE-2021-38114`: affected lines `29`, without fix `22`
- `FFmpeg` `CVE-2021-38171`: affected lines `29`, without fix `22`
- `FFmpeg` `CVE-2020-20448`: affected lines `23`, without fix `21`
- `FFmpeg` `CVE-2020-22046`: affected lines `25`, without fix `21`
- `FFmpeg` `CVE-2022-48434`: affected lines `23`, without fix `21`
- `FFmpeg` `CVE-2020-20446`: affected lines `27`, without fix `20`
- `FFmpeg` `CVE-2020-13904`: affected lines `26`, without fix `19`
- `FFmpeg` `CVE-2020-22054`: affected lines `18`, without fix `18`
- `FFmpeg` `CVE-2020-22025`: affected lines `20`, without fix `16`
- `FFmpeg` `CVE-2020-35965`: affected lines `22`, without fix `16`
- `FFmpeg` `CVE-2020-22032`: affected lines `20`, without fix `15`
- `FFmpeg` `CVE-2020-22037`: affected lines `22`, without fix `15`
- `FFmpeg` `CVE-2020-22044`: affected lines `20`, without fix `15`
- `FFmpeg` `CVE-2020-20451`: affected lines `19`, without fix `14`
- `FFmpeg` `CVE-2020-22042`: affected lines `15`, without fix `14`
- `FFmpeg` `CVE-2020-20892`: affected lines `13`, without fix `13`
- `FFmpeg` `CVE-2020-22020`: affected lines `17`, without fix `12`
- `FFmpeg` `CVE-2020-22021`: affected lines `19`, without fix `12`
- `FFmpeg` `CVE-2020-22022`: affected lines `16`, without fix `11`
- `FFmpeg` `CVE-2020-22031`: affected lines `16`, without fix `11`
- `FFmpeg` `CVE-2022-1475`: affected lines `12`, without fix `11`
- `FFmpeg` `CVE-2020-22040`: affected lines `9`, without fix `9`
- `FFmpeg` `CVE-2024-7055`: affected lines `7`, without fix `7`
- `FFmpeg` `CVE-2020-20891`: affected lines `6`, without fix `6`
- `FFmpeg` `CVE-2020-20898`: affected lines `6`, without fix `6`
- `FFmpeg` `CVE-2021-38092`: affected lines `6`, without fix `6`
- `FFmpeg` `CVE-2020-21041`: affected lines `11`, without fix `5`
- `FFmpeg` `CVE-2020-20453`: affected lines `10`, without fix `4`
- `FFmpeg` `CVE-2020-20896`: affected lines `4`, without fix `4`
- `FFmpeg` `CVE-2020-22026`: affected lines `8`, without fix `4`
