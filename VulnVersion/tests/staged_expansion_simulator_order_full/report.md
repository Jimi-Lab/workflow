# Staged Expansion Scheduler GT Simulator

This is a GT-oracle simulation. It uses affected_version as an ideal tag verdict oracle and measures scheduling behavior, not real agent accuracy.

| policy | cves | avg probes | p95 | avg seed lines | avg active lines | exact CVEs | FN CVEs | skipped-affected-line CVEs | micro P | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| all_lines_soft | 1128 | 85.55 | 162.0 | 60.36 | 60.36 | 1114 | 8 | 0 | 0.999915 | 0.999848 | 0.999882 |
| staged_nofix_stride3_file | 1128 | 70.53 | 130.0 | 48.52 | 49.31 | 1114 | 8 | 0 | 0.999915 | 0.999848 | 0.999882 |

## By Repo

### all_lines_soft

| repo | cves | avg probes | p95 | avg seed lines | avg active lines | exact CVEs | FN CVEs | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 168.18 | 179.0 | 36.0 | 36.0 | 71 | 0 | 1.0 | 1.0 |
| ImageMagick | 72 | 12.96 | 18.0 | 2.0 | 2.0 | 70 | 1 | 0.999919 | 0.999919 |
| curl | 68 | 12.22 | 13.0 | 1.0 | 1.0 | 64 | 0 | 1.0 | 1.0 |
| httpd | 30 | 37.83 | 42.0 | 7.0 | 7.0 | 26 | 4 | 0.998397 | 0.999198 |
| linux | 717 | 86.17 | 88.0 | 82.0 | 82.0 | 717 | 0 | 1.0 | 1.0 |
| openjpeg | 13 | 20.0 | 20.0 | 12.0 | 12.0 | 13 | 0 | 1.0 | 1.0 |
| openssl | 50 | 96.02 | 99.0 | 24.0 | 24.0 | 49 | 1 | 0.999443 | 0.999722 |
| qemu | 57 | 147.35 | 149.0 | 59.0 | 59.0 | 57 | 0 | 1.0 | 1.0 |
| wireshark | 50 | 128.24 | 138.0 | 32.0 | 32.0 | 47 | 2 | 0.999661 | 0.999604 |

### staged_nofix_stride3_file

| repo | cves | avg probes | p95 | avg seed lines | avg active lines | exact CVEs | FN CVEs | micro R | micro F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 71 | 134.52 | 179.0 | 28.96 | 29.21 | 71 | 0 | 1.0 | 1.0 |
| ImageMagick | 72 | 12.96 | 18.0 | 2.0 | 2.0 | 70 | 1 | 0.999919 | 0.999919 |
| curl | 68 | 12.22 | 13.0 | 1.0 | 1.0 | 64 | 0 | 1.0 | 1.0 |
| httpd | 30 | 34.5 | 39.0 | 6.3 | 6.33 | 26 | 4 | 0.998397 | 0.999198 |
| linux | 717 | 71.23 | 88.0 | 66.01 | 67.06 | 717 | 0 | 1.0 | 1.0 |
| openjpeg | 13 | 17.69 | 20.0 | 8.69 | 10.15 | 13 | 0 | 1.0 | 1.0 |
| openssl | 50 | 82.86 | 97.0 | 20.34 | 20.46 | 49 | 1 | 0.999443 | 0.999722 |
| qemu | 57 | 108.26 | 141.0 | 41.96 | 43.56 | 57 | 0 | 1.0 | 1.0 |
| wireshark | 50 | 111.84 | 138.0 | 28.32 | 28.48 | 47 | 2 | 0.999661 | 0.999604 |

