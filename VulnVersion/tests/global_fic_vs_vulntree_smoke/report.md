# Global FIC Baseline vs VulnTree Line-Local Planning

This experiment samples CVEs per repo and compares two planning strategies:

- `global_fic_baseline`: one global release-tag sequence, first global FIC, all earlier tags as candidates.
- `vuln_tree_line_local`: current Step3 planner with line-local FIC and ASBS probe scheduling.

## Overall

- cves: `9`
- global_candidate_avg: `197.33`
- global_candidate_median: `173.0`
- global_candidate_max: `502`
- vulntree_candidate_avg: `203.67`
- vulntree_candidate_median: `173.0`
- vulntree_candidate_max: `504`
- vulntree_probe_avg: `43.22`
- vulntree_probe_median: `45.0`
- vulntree_probe_max: `98`
- global_full_gt_coverage_cves: `8`
- vulntree_full_gt_candidate_coverage_cves: `9`
- global_avg_gt_coverage: `0.9333`
- vulntree_avg_gt_candidate_coverage: `1.0`
- avg_global_minus_vulntree_candidate: `-6.33`
- avg_global_minus_vulntree_probe: `154.11`
- sampled_cves: `9`
- successful_cves: `9`
- failed_cves: `0`
- per_repo: `1`
- seed: `42`
- expensive_equivalence_enabled: `False`
- line_local_planner: `fast_line_local_fic_baseline`

## By Repo

| repo | cves | global avg cand | vt avg cand | vt avg probes | global full GT | vt full GT candidate |
|---|---:|---:|---:|---:|---:|---:|
| FFmpeg | 1 | 274.0 | 316.0 | 70.0 | 0 | 1 |
| ImageMagick | 1 | 173.0 | 173.0 | 4.0 | 1 | 1 |
| curl | 1 | 169.0 | 169.0 | 3.0 | 1 | 1 |
| httpd | 1 | 190.0 | 190.0 | 15.0 | 1 | 1 |
| linux | 1 | 92.0 | 92.0 | 83.0 | 1 | 1 |
| openjpeg | 1 | 16.0 | 16.0 | 16.0 | 1 | 1 |
| openssl | 1 | 246.0 | 259.0 | 45.0 | 1 | 1 |
| qemu | 1 | 114.0 | 114.0 | 98.0 | 1 | 1 |
| wireshark | 1 | 502.0 | 504.0 | 55.0 | 1 | 1 |

## Most Expensive Global FIC Cases

- `wireshark` `CVE-2022-0582`: global `502`, vulntree candidates `504`, probes `55`
- `FFmpeg` `CVE-2020-22015`: global `274`, vulntree candidates `316`, probes `70`
- `openssl` `CVE-2024-5535`: global `246`, vulntree candidates `259`, probes `45`
- `httpd` `CVE-2020-9490`: global `190`, vulntree candidates `190`, probes `15`
- `ImageMagick` `CVE-2020-25664`: global `173`, vulntree candidates `173`, probes `4`
- `curl` `CVE-2022-35260`: global `169`, vulntree candidates `169`, probes `3`
- `qemu` `CVE-2020-13800`: global `114`, vulntree candidates `114`, probes `98`
- `linux` `CVE-2023-1075`: global `92`, vulntree candidates `92`, probes `83`
- `openjpeg` `CVE-2020-27823`: global `16`, vulntree candidates `16`, probes `16`
