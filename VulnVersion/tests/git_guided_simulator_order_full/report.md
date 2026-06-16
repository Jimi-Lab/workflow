# Git-Guided Step3 Scheduler Simulator

This GT simulator compares hard fix-containment pruning with a safer paper-guided soft strategy.

Policies:
- `all_lines_asbs`: current ASBS-first cost/accuracy reference.
- `hard_no_fix_filter`: only keep tags that do not contain any seed fix commit. This is unsafe and is included as a negative control.
- `git_guided_soft`: split each line into fix-containing and no-fix segments. No-fix segments run ASBS. Fix-containing segments are not deleted; they receive sentinel probes and fall back to ASBS if a sentinel is affected.

## Overall

| policy | cves | probe avg | p95 | max | exact CVEs | recall CVEs | FN CVEs | hard-filter-miss CVEs | fixed-segment-miss CVEs | micro P | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| all_lines_asbs|s=3|fs=0 | 1128 | 87.2 | 172.0 | 178 | 1083 | 1089 | 39 | 0 | 0 | 0.999898 | 0.994656 | 0.99727 |
| git_guided_soft|s=3|fs=0 | 1128 | 84.15 | 155.0 | 175 | 1113 | 1119 | 9 | 0 | 1 | 0.999915 | 0.999814 | 0.999865 |
| git_guided_soft|s=3|fs=1 | 1128 | 85.55 | 162.0 | 181 | 1114 | 1120 | 8 | 0 | 0 | 0.999915 | 0.999848 | 0.999882 |

## By Repo

### all_lines_asbs|s=3|fs=0

| repo | cves | probe avg | p95 | max | exact CVEs | FN CVEs | micro P | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 173.9 | 177.0 | 178 | 70 | 1 | 0.999894 | 0.999788 | 0.999841 |
| ImageMagick | 72 | 15.94 | 22.0 | 23 | 64 | 7 | 0.999919 | 0.991355 | 0.995618 |
| curl | 68 | 12.07 | 17.0 | 17 | 40 | 24 | 1.0 | 0.955729 | 0.977363 |
| httpd | 30 | 38.27 | 42.0 | 42 | 26 | 4 | 1.0 | 0.998397 | 0.999198 |
| linux | 717 | 86.17 | 88.0 | 88 | 717 | 0 | 1.0 | 1.0 | 1.0 |
| openjpeg | 13 | 22.0 | 22.0 | 22 | 13 | 0 | 1.0 | 1.0 | 1.0 |
| openssl | 50 | 96.12 | 98.0 | 106 | 49 | 1 | 1.0 | 0.999443 | 0.999722 |
| qemu | 57 | 163.04 | 163.0 | 164 | 57 | 0 | 1.0 | 1.0 | 1.0 |
| wireshark | 50 | 134.54 | 138.0 | 168 | 47 | 2 | 0.999548 | 0.999661 | 0.999604 |

### git_guided_soft|s=3|fs=0

| repo | cves | probe avg | p95 | max | exact CVEs | FN CVEs | micro P | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 160.17 | 168.0 | 175 | 70 | 1 | 1.0 | 0.999788 | 0.999894 |
| ImageMagick | 72 | 11.24 | 17.0 | 17 | 70 | 1 | 0.999919 | 0.999919 | 0.999919 |
| curl | 68 | 11.22 | 12.0 | 12 | 64 | 0 | 1.0 | 1.0 | 1.0 |
| httpd | 30 | 37.43 | 42.0 | 43 | 26 | 4 | 1.0 | 0.998397 | 0.999198 |
| linux | 717 | 86.17 | 88.0 | 88 | 717 | 0 | 1.0 | 1.0 | 1.0 |
| openjpeg | 13 | 19.0 | 19.0 | 19 | 13 | 0 | 1.0 | 1.0 | 1.0 |
| openssl | 50 | 94.76 | 98.0 | 106 | 49 | 1 | 1.0 | 0.999443 | 0.999722 |
| qemu | 57 | 138.44 | 141.0 | 148 | 57 | 0 | 1.0 | 1.0 | 1.0 |
| wireshark | 50 | 123.74 | 137.0 | 156 | 47 | 2 | 0.999548 | 0.999661 | 0.999604 |

### git_guided_soft|s=3|fs=1

| repo | cves | probe avg | p95 | max | exact CVEs | FN CVEs | micro P | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 168.18 | 179.0 | 181 | 71 | 0 | 1.0 | 1.0 | 1.0 |
| ImageMagick | 72 | 12.96 | 18.0 | 18 | 70 | 1 | 0.999919 | 0.999919 | 0.999919 |
| curl | 68 | 12.22 | 13.0 | 13 | 64 | 0 | 1.0 | 1.0 | 1.0 |
| httpd | 30 | 37.83 | 42.0 | 44 | 26 | 4 | 1.0 | 0.998397 | 0.999198 |
| linux | 717 | 86.17 | 88.0 | 88 | 717 | 0 | 1.0 | 1.0 | 1.0 |
| openjpeg | 13 | 20.0 | 20.0 | 20 | 13 | 0 | 1.0 | 1.0 | 1.0 |
| openssl | 50 | 96.02 | 99.0 | 107 | 49 | 1 | 1.0 | 0.999443 | 0.999722 |
| qemu | 57 | 147.35 | 149.0 | 154 | 57 | 0 | 1.0 | 1.0 | 1.0 |
| wireshark | 50 | 128.24 | 138.0 | 161 | 47 | 2 | 0.999548 | 0.999661 | 0.999604 |


## Worst FN Cases

### all_lines_asbs|s=3|fs=0
- `ImageMagick` `CVE-2020-10251`: probes `10`, FN `51`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `curl` `CVE-2024-9681`: probes `5`, FN `37`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `ImageMagick` `CVE-2022-1115`: probes `10`, FN `24`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `curl` `CVE-2024-2004`: probes `5`, FN `16`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `curl` `CVE-2023-46219`: probes `5`, FN `15`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `curl` `CVE-2020-8169`: probes `5`, FN `14`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `curl` `CVE-2023-23914`: probes `5`, FN `13`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `curl` `CVE-2023-23915`: probes `5`, FN `13`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `curl` `CVE-2023-38039`: probes `5`, FN `13`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `ImageMagick` `CVE-2020-25663`: probes `10`, FN `12`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`

### git_guided_soft|s=3|fs=0
- `FFmpeg` `CVE-2020-20451`: probes `163`, FN `2`, FP `0`, fixed-segment missed GT `2`, hard-filter missed GT `0`, R `0.991189`
- `wireshark` `CVE-2021-22235`: probes `122`, FN `2`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.5`
- `wireshark` `CVE-2020-26421`: probes `120`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.99734`
- `openssl` `CVE-2022-2274`: probes `82`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `httpd` `CVE-2020-11993`: probes `38`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.964286`
- `httpd` `CVE-2022-28615`: probes `36`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.994505`
- `httpd` `CVE-2021-41773`: probes `33`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `httpd` `CVE-2021-44790`: probes `33`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `ImageMagick` `CVE-2023-3195`: probes `17`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.99`
- `FFmpeg` `CVE-2022-48434`: probes `175`, FN `0`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `1.0`

### git_guided_soft|s=3|fs=1
- `wireshark` `CVE-2021-22235`: probes `128`, FN `2`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.5`
- `wireshark` `CVE-2020-26421`: probes `126`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.99734`
- `openssl` `CVE-2022-2274`: probes `86`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `httpd` `CVE-2020-11993`: probes `39`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.964286`
- `httpd` `CVE-2022-28615`: probes `36`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.994505`
- `httpd` `CVE-2021-41773`: probes `33`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `httpd` `CVE-2021-44790`: probes `33`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.0`
- `ImageMagick` `CVE-2023-3195`: probes `18`, FN `1`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `0.99`
- `FFmpeg` `CVE-2021-38114`: probes `181`, FN `0`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `1.0`
- `FFmpeg` `CVE-2020-20446`: probes `179`, FN `0`, FP `0`, fixed-segment missed GT `0`, hard-filter missed GT `0`, R `1.0`

