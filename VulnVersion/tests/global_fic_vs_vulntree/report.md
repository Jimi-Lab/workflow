# Global FIC Baseline vs VulnTree Line-Local Planning

This experiment samples CVEs per repo and compares two planning strategies:

- `global_fic_baseline`: one global release-tag sequence, first global FIC, all earlier tags as candidates.
- `vuln_tree_line_local`: current Step3 planner with line-local FIC and ASBS probe scheduling.

## Overall

- cves: `90`
- global_candidate_avg: `201.09`
- global_candidate_median: `174.0`
- global_candidate_max: `542`
- vulntree_candidate_avg: `213.68`
- vulntree_candidate_median: `174.0`
- vulntree_candidate_max: `577`
- vulntree_probe_avg: `43.08`
- vulntree_probe_median: `45.0`
- vulntree_probe_max: `102`
- global_full_gt_coverage_cves: `79`
- vulntree_full_gt_candidate_coverage_cves: `87`
- global_avg_gt_coverage: `0.956`
- vulntree_avg_gt_candidate_coverage: `0.998`
- avg_global_minus_vulntree_candidate: `-12.59`
- avg_global_minus_vulntree_probe: `158.01`
- sampled_cves: `90`
- successful_cves: `90`
- failed_cves: `0`
- per_repo: `10`
- seed: `42`
- expensive_equivalence_enabled: `False`
- line_local_planner: `fast_line_local_fic_baseline`

## By Repo

| repo | cves | global avg cand | vt avg cand | vt avg probes | global full GT | vt full GT candidate |
|---|---:|---:|---:|---:|---:|---:|
| FFmpeg | 10 | 299.5 | 327.0 | 66.2 | 3 | 9 |
| ImageMagick | 10 | 221.0 | 221.0 | 4.3 | 10 | 10 |
| curl | 10 | 166.2 | 166.2 | 3.0 | 10 | 10 |
| httpd | 10 | 200.3 | 200.3 | 14.5 | 10 | 10 |
| linux | 10 | 94.5 | 94.5 | 83.0 | 9 | 9 |
| openjpeg | 10 | 16.2 | 16.2 | 16.0 | 10 | 10 |
| openssl | 10 | 221.4 | 249.4 | 44.1 | 8 | 10 |
| qemu | 10 | 121.0 | 121.0 | 99.2 | 9 | 9 |
| wireshark | 10 | 469.7 | 527.5 | 57.4 | 10 | 10 |

## Most Expensive Global FIC Cases

- `wireshark` `CVE-2024-24478`: global `542`, vulntree candidates `544`, probes `57`
- `wireshark` `CVE-2022-3190`: global `541`, vulntree candidates `543`, probes `57`
- `wireshark` `CVE-2021-4181`: global `502`, vulntree candidates `504`, probes `55`
- `wireshark` `CVE-2021-4186`: global `502`, vulntree candidates `504`, probes `55`
- `wireshark` `CVE-2022-0582`: global `502`, vulntree candidates `504`, probes `55`
- `wireshark` `CVE-2022-0583`: global `502`, vulntree candidates `504`, probes `55`
- `wireshark` `CVE-2021-22173`: global `451`, vulntree candidates `453`, probes `54`
- `wireshark` `CVE-2020-17498`: global `389`, vulntree candidates `577`, probes `62`
- `wireshark` `CVE-2020-15466`: global `387`, vulntree candidates `575`, probes `62`
- `wireshark` `CVE-2020-7044`: global `379`, vulntree candidates `567`, probes `62`
- `ImageMagick` `CVE-2023-5341`: global `361`, vulntree candidates `361`, probes `5`
- `FFmpeg` `CVE-2020-22038`: global `344`, vulntree candidates `344`, probes `64`
- `ImageMagick` `CVE-2023-1289`: global `342`, vulntree candidates `342`, probes `5`
- `FFmpeg` `CVE-2020-20898`: global `334`, vulntree candidates `334`, probes `63`
- `FFmpeg` `CVE-2020-22040`: global `334`, vulntree candidates `334`, probes `63`
- `FFmpeg` `CVE-2020-22029`: global `318`, vulntree candidates `330`, probes `64`
- `FFmpeg` `CVE-2020-22030`: global `318`, vulntree candidates `330`, probes `64`
- `FFmpeg` `CVE-2020-22034`: global `318`, vulntree candidates `330`, probes `64`
- `FFmpeg` `CVE-2020-22019`: global `297`, vulntree candidates `320`, probes `69`
- `ImageMagick` `CVE-2021-3962`: global `293`, vulntree candidates `293`, probes `5`
