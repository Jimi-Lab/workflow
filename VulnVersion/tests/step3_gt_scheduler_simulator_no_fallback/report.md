# Step3 GT Scheduler Simulator

This report simulates line-aware ASBS-first scheduling with ground-truth affected versions.
It does not call the agent and does not inspect fix commits.

Policies:
- `all_lines`: every release line is active. This is runnable but may over-estimate cost.
- `oracle_affected_lines`: only GT-affected lines are active. This is an unrealizable lower-bound for a future line scheduler.

## Overall

| policy | cves | probe avg | probe median | p90 | p95 | max | exact CVEs | recall CVEs | FP CVEs | FN CVEs | micro P | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| all_lines|sentinel=3 | 1128 | 87.16 | 86.0 | 163.0 | 172.0 | 178 | 1080 | 1086 | 3 | 42 | 0.999898 | 0.993878 | 0.996879 |
| oracle_affected_lines|sentinel=3 | 1128 | 25.94 | 16.0 | 68.0 | 76.0 | 160 | 1080 | 1086 | 3 | 42 | 0.999898 | 0.993878 | 0.996879 |

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
| openssl | 50 | 95.96 | 98.0 | 98 | 48 | 1.0 | 0.994989 | 0.997488 |
| qemu | 57 | 163.04 | 163.0 | 164 | 56 | 1.0 | 0.999086 | 0.999543 |
| wireshark | 50 | 133.88 | 138.0 | 138 | 46 | 0.999546 | 0.995593 | 0.997566 |

## Worst Probe Cases

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

