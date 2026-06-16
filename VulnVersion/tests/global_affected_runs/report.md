# Global Affected-Run Analysis

This report checks whether affected versions form one contiguous run when all release tags are flattened into one repo-level sequence.

If a CVE has more than one affected run (`A ... N ... A`), global ASBS over that sequence is not monotonic.

## Overall

- total_cves: `1128`
- fully_mapped_cves: `1124`
- partially_or_unmapped_cves: `4`

| order | global_contiguous_cves | has_A_N_A_cves | max_run_count |
|---|---:|---:|---:|
| semantic_global | 991 | 137 | 8 |
| creatordate_oldest | 915 | 213 | 30 |
| creatordate_newest | 915 | 213 | 30 |

## By Repo

| repo | cves | semantic A-N-A | time-oldest A-N-A | time-newest A-N-A |
|---|---:|---:|---:|---:|
| FFmpeg | 71 | 59 | 63 | 63 |
| ImageMagick | 72 | 2 | 2 | 2 |
| curl | 68 | 0 | 0 | 0 |
| httpd | 30 | 2 | 24 | 24 |
| linux | 717 | 0 | 1 | 1 |
| openjpeg | 13 | 2 | 3 | 3 |
| openssl | 50 | 32 | 49 | 49 |
| qemu | 57 | 8 | 28 | 28 |
| wireshark | 50 | 32 | 43 | 43 |

## Worst Semantic-Order Cases

- `FFmpeg` `CVE-2022-48434`: runs `8`, affected `224` / tags `381`
- `FFmpeg` `CVE-2020-13904`: runs `7`, affected `280` / tags `381`
- `FFmpeg` `CVE-2020-20446`: runs `7`, affected `289` / tags `381`
- `FFmpeg` `CVE-2020-22021`: runs `7`, affected `187` / tags `381`
- `FFmpeg` `CVE-2020-22037`: runs `7`, affected `228` / tags `381`
- `FFmpeg` `CVE-2021-38114`: runs `7`, affected `315` / tags `381`
- `FFmpeg` `CVE-2021-38171`: runs `7`, affected `311` / tags `381`
- `FFmpeg` `CVE-2023-47342`: runs `7`, affected `351` / tags `381`
- `FFmpeg` `CVE-2020-20448`: runs `6`, affected `240` / tags `381`
- `FFmpeg` `CVE-2020-20451`: runs `6`, affected `227` / tags `381`
- `FFmpeg` `CVE-2020-20453`: runs `6`, affected `83` / tags `381`
- `FFmpeg` `CVE-2020-20902`: runs `6`, affected `240` / tags `381`
- `FFmpeg` `CVE-2020-21041`: runs `6`, affected `119` / tags `381`
- `FFmpeg` `CVE-2020-22015`: runs `6`, affected `70` / tags `381`
- `FFmpeg` `CVE-2020-22041`: runs `6`, affected `97` / tags `381`
- `FFmpeg` `CVE-2020-22042`: runs `6`, affected `161` / tags `381`
- `FFmpeg` `CVE-2020-35965`: runs `6`, affected `232` / tags `381`
- `FFmpeg` `CVE-2021-38291`: runs `6`, affected `70` / tags `381`
- `openssl` `CVE-2022-4304`: runs `6`, affected `58` / tags `264`
- `openssl` `CVE-2023-0215`: runs `6`, affected `58` / tags `264`
- `qemu` `CVE-2022-0216`: runs `6`, affected `76` / tags `196`
- `FFmpeg` `CVE-2020-20450`: runs `5`, affected `329` / tags `381`
- `FFmpeg` `CVE-2020-22016`: runs `5`, affected `308` / tags `381`
- `FFmpeg` `CVE-2020-22019`: runs `5`, affected `36` / tags `381`
- `FFmpeg` `CVE-2020-22020`: runs `5`, affected `192` / tags `381`
- `FFmpeg` `CVE-2020-22022`: runs `5`, affected `184` / tags `381`
- `FFmpeg` `CVE-2020-22025`: runs `5`, affected `233` / tags `381`
- `FFmpeg` `CVE-2020-22031`: runs `5`, affected `184` / tags `381`
- `FFmpeg` `CVE-2020-22032`: runs `5`, affected `233` / tags `381`
- `FFmpeg` `CVE-2020-22044`: runs `5`, affected `235` / tags `381`
