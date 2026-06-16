# Step1 P4 OpenCode Real Validation

This validates Step1 region refinement against the real OpenCode backend.
It does not evaluate affected-version accuracy or Step3 probe reduction.

## Summary

- total_cves: 18
- completed_cves: 18
- failed_cves: 0
- agent_success_cves: 16
- agent_failed_cves: 2
- avg_latency_s: 154.278
- avg_regions: 4.222

## Per CVE

| repo | cve | status | regions | latency_s | unknown_agent_failed | roles |
| --- | --- | --- | ---: | ---: | ---: | --- |
| FFmpeg | CVE-2022-3965 | completed | 2 | 250.343 | 2 | {'unknown_agent_failed': 2} |
| FFmpeg | CVE-2020-24020 | completed | 9 | 264.532 | 0 | {'context_region': 1, 'primary_root_cause_region': 1, 'supporting_fix_region': 7} |
| ImageMagick | CVE-2023-3195 | completed | 2 | 365.687 | 0 | {'noise_region': 1, 'primary_root_cause_region': 1} |
| ImageMagick | CVE-2020-27768 | completed | 5 | 29.125 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 4} |
| curl | CVE-2024-9681 | completed | 4 | 88.422 | 0 | {'noise_region': 1, 'primary_root_cause_region': 2, 'supporting_fix_region': 1} |
| curl | CVE-2024-8096 | completed | 2 | 162.672 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 1} |
| httpd | CVE-2022-30522 | completed | 11 | 900.375 | 11 | {'unknown_agent_failed': 11} |
| httpd | CVE-2022-31813 | completed | 1 | 149.5 | 0 | {'primary_root_cause_region': 1} |
| linux | CVE-2022-0171 | completed | 18 | 87.14 | 0 | {'context_region': 6, 'primary_root_cause_region': 1, 'supporting_fix_region': 11} |
| linux | CVE-2022-0185 | completed | 1 | 43.204 | 0 | {'primary_root_cause_region': 1} |
| openjpeg | CVE-2020-27843 | completed | 1 | 7.531 | 0 | {'primary_root_cause_region': 1} |
| openjpeg | CVE-2020-27842 | completed | 1 | 25.015 | 0 | {'primary_root_cause_region': 1} |
| openssl | CVE-2023-1255 | completed | 5 | 63.688 | 0 | {'noise_region': 3, 'primary_root_cause_region': 1, 'supporting_fix_region': 1} |
| openssl | CVE-2023-6129 | completed | 3 | 90.297 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 2} |
| qemu | CVE-2023-0664 | completed | 4 | 96.219 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 3} |
| qemu | CVE-2020-12829 | completed | 1 | 46.937 | 0 | {'primary_root_cause_region': 1} |
| wireshark | CVE-2024-24479 | completed | 4 | 79.609 | 0 | {'context_region': 1, 'primary_root_cause_region': 1, 'supporting_fix_region': 2} |
| wireshark | CVE-2021-39926 | completed | 2 | 26.704 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 1} |
