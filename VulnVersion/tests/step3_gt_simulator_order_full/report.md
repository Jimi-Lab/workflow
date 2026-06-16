# Step3 GT Scheduler Simulator

This report simulates line-aware ASBS-first scheduling with ground-truth affected versions.
It does not call the agent and does not inspect fix commits.

Policies:
- `all_lines`: every release line is active. This is runnable but may over-estimate cost.
- `oracle_affected_lines`: only GT-affected lines are active. This is an unrealizable lower-bound for a future line scheduler.

## Overall

| policy | cves | probe avg | probe median | p90 | p95 | max | exact CVEs | recall CVEs | FP CVEs | FN CVEs | micro P | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| all_lines|sentinel=0 | 1128 | 70.98 | 83.0 | 88.0 | 109.0 | 116 | 1021 | 1030 | 6 | 98 | 0.999741 | 0.912166 | 0.953947 |
| all_lines|sentinel=1 | 1128 | 77.34 | 84.0 | 110.0 | 137.0 | 142 | 1062 | 1070 | 5 | 58 | 0.999775 | 0.978236 | 0.988888 |
| all_lines|sentinel=2 | 1128 | 82.51 | 85.0 | 142.0 | 152.0 | 155 | 1072 | 1079 | 4 | 49 | 0.999863 | 0.986979 | 0.993379 |
| all_lines|sentinel=3 | 1128 | 87.2 | 86.0 | 163.0 | 172.0 | 178 | 1083 | 1089 | 3 | 39 | 0.999898 | 0.994656 | 0.99727 |

## By Repo: all_lines, highest sentinel count

Policy: `all_lines|sentinel=3`

| repo | cves | probe avg | p95 | max | exact CVEs | micro P | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 173.9 | 177.0 | 178 | 70 | 0.999894 | 0.999788 | 0.999841 |
| ImageMagick | 72 | 15.94 | 22.0 | 23 | 64 | 0.999919 | 0.991355 | 0.995618 |
| curl | 68 | 12.07 | 17.0 | 17 | 40 | 1.0 | 0.955729 | 0.977363 |
| httpd | 30 | 38.27 | 42.0 | 42 | 26 | 1.0 | 0.998397 | 0.999198 |
| linux | 717 | 86.17 | 88.0 | 88 | 717 | 1.0 | 1.0 | 1.0 |
| openjpeg | 13 | 22.0 | 22.0 | 22 | 13 | 1.0 | 1.0 | 1.0 |
| openssl | 50 | 96.12 | 98.0 | 106 | 49 | 1.0 | 0.999443 | 0.999722 |
| qemu | 57 | 163.04 | 163.0 | 164 | 57 | 1.0 | 1.0 | 1.0 |
| wireshark | 50 | 134.54 | 138.0 | 168 | 47 | 0.999548 | 0.999661 | 0.999604 |

## Worst Probe Cases

### all_lines|sentinel=0
- `qemu` `CVE-2023-42467`: probes `116`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2024-42474`: probes `116`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2022-0216`: probes `112`, active lines `59/59`, FP `1`, FN `0`, R `1.0`
- `qemu` `CVE-2023-40360`: probes `112`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-10702`: probes `109`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-11869`: probes `109`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-11947`: probes `109`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-12829`: probes `109`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-13361`: probes `109`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-13765`: probes `109`, active lines `59/59`, FP `0`, FN `0`, R `1.0`

### all_lines|sentinel=1
- `qemu` `CVE-2023-42467`: probes `142`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2024-42474`: probes `142`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2023-40360`: probes `139`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-10702`: probes `137`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-11869`: probes `137`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-11947`: probes `137`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-12829`: probes `137`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-13361`: probes `137`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-13765`: probes `137`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-13800`: probes `137`, active lines `59/59`, FP `0`, FN `0`, R `1.0`

### all_lines|sentinel=2
- `qemu` `CVE-2023-42467`: probes `155`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2024-42474`: probes `155`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2020-22041`: probes `153`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2021-38114`: probes `153`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2023-40360`: probes `153`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-10702`: probes `152`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-11869`: probes `152`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-11947`: probes `152`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-12829`: probes `152`, active lines `59/59`, FP `0`, FN `0`, R `1.0`
- `qemu` `CVE-2020-13361`: probes `152`, active lines `59/59`, FP `0`, FN `0`, R `1.0`

### all_lines|sentinel=3
- `FFmpeg` `CVE-2020-22041`: probes `178`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2020-21041`: probes `177`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2020-22020`: probes `177`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2020-22022`: probes `177`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2020-22025`: probes `177`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2020-22031`: probes `177`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2020-22032`: probes `177`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2020-22044`: probes `177`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2020-35965`: probes `177`, active lines `36/36`, FP `0`, FN `0`, R `1.0`
- `FFmpeg` `CVE-2021-38114`: probes `177`, active lines `36/36`, FP `0`, FN `0`, R `1.0`

