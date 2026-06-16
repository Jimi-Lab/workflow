# Fix Upper-Bound Filter Analysis

This report evaluates using seed fix commits as an upper-bound tag filter.
Candidate tags are release tags that do not contain any seed fix commit.

## Overall

- cves: `717`
- full_gt_coverage_cves: `682`
- has_gt_miss_cves: `35`
- has_unmapped_cves: `0`
- commit_error_cves: `0`
- micro_gt_coverage: `0.996547`
- avg_gt_coverage: `0.9917`
- avg_release_tags: `110.0`
- avg_candidate_tags: `93.2887`
- avg_excluded_tags: `16.7113`
- avg_candidate_tag_rate: `0.8481`
- avg_tag_reduction_rate: `0.1519`
- avg_release_lines: `82.0`
- avg_candidate_lines: `65.2887`
- avg_fully_excluded_lines: `16.7113`
- avg_affected_lines: `23.2427`

## By Repo

| repo | cves | full GT coverage | micro coverage | avg candidate tag rate | avg tag reduction | avg lines | avg candidate lines | avg fully excluded lines |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| linux | 717 | 682 | 0.996547 | 0.8481 | 0.1519 | 82.0 | 65.2887 | 16.7113 |

## Worst Misses

- `linux` `CVE-2023-5178`: missed `26` / `26`, coverage `0.0`, candidate rate `0.636364`
- `linux` `CVE-2022-1729`: missed `1` / `40`, coverage `0.975`, candidate rate `0.8`
- `linux` `CVE-2022-20158`: missed `1` / `85`, coverage `0.988235`, candidate rate `0.790909`
- `linux` `CVE-2022-20368`: missed `1` / `85`, coverage `0.988235`, candidate rate `0.790909`
- `linux` `CVE-2022-20423`: missed `1` / `1`, coverage `0.0`, candidate rate `0.790909`
- `linux` `CVE-2022-2308`: missed `1` / `6`, coverage `0.833333`, candidate rate `0.818182`
- `linux` `CVE-2022-3105`: missed `1` / `17`, coverage `0.941176`, candidate rate `0.781818`
- `linux` `CVE-2022-3107`: missed `1` / `20`, coverage `0.95`, candidate rate `0.790909`
- `linux` `CVE-2022-36402`: missed `1` / `44`, coverage `0.977273`, candidate rate `0.863636`
- `linux` `CVE-2022-3643`: missed `1` / `44`, coverage `0.977273`, candidate rate `0.827273`
- `linux` `CVE-2022-36946`: missed `1` / `87`, coverage `0.988506`, candidate rate `0.809091`
- `linux` `CVE-2022-42328`: missed `1` / `6`, coverage `0.833333`, candidate rate `0.827273`
- `linux` `CVE-2022-42329`: missed `1` / `6`, coverage `0.833333`, candidate rate `0.827273`
- `linux` `CVE-2022-4378`: missed `1` / `14`, coverage `0.928571`, candidate rate `0.827273`
- `linux` `CVE-2022-48629`: missed `1` / `20`, coverage `0.95`, candidate rate `0.790909`
- `linux` `CVE-2022-48630`: missed `1` / `2`, coverage `0.5`, candidate rate `0.8`
- `linux` `CVE-2023-1281`: missed `1` / `30`, coverage `0.966667`, candidate rate `0.836364`
- `linux` `CVE-2023-2163`: missed `1` / `21`, coverage `0.952381`, candidate rate `0.845455`
- `linux` `CVE-2023-2166`: missed `1` / `10`, coverage `0.9`, candidate rate `0.827273`
- `linux` `CVE-2023-2177`: missed `1` / `26`, coverage `0.961538`, candidate rate `0.809091`
