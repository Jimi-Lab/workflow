# Step1 P4 OpenCode Real Validation

This validates Step1 region refinement against the real OpenCode backend.
It does not evaluate affected-version accuracy or Step3 probe reduction.

## Summary

- total_cves: 18
- completed_cves: 18
- failed_cves: 0
- agent_success_cves: 16
- agent_failed_cves: 2
- avg_latency_s: 96.458
- avg_regions: 4.222

## Per CVE

| repo | cve | status | regions | latency_s | unknown_agent_failed | roles |
| --- | --- | --- | ---: | ---: | ---: | --- |
| FFmpeg | CVE-2022-3965 | completed | 2 | 77.328 | 2 | {'unknown_agent_failed': 2} |
| FFmpeg | CVE-2020-24020 | completed | 9 | 32.844 | 0 | {'context_region': 1, 'primary_root_cause_region': 1, 'supporting_fix_region': 7} |
| ImageMagick | CVE-2023-3195 | completed | 2 | 21.203 | 0 | {'context_region': 1, 'primary_root_cause_region': 1} |
| ImageMagick | CVE-2020-27768 | completed | 5 | 30.484 | 0 | {'primary_root_cause_region': 5} |
| curl | CVE-2024-9681 | completed | 4 | 80.11 | 0 | {'noise_region': 1, 'primary_root_cause_region': 1, 'supporting_fix_region': 2} |
| curl | CVE-2024-8096 | completed | 2 | 23.343 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 1} |
| httpd | CVE-2022-30522 | completed | 11 | 48.5 | 0 | {'noise_region': 1, 'primary_root_cause_region': 1, 'supporting_fix_region': 9} |
| httpd | CVE-2022-31813 | completed | 1 | 16.0 | 0 | {'primary_root_cause_region': 1} |
| linux | CVE-2022-0171 | completed | 18 | 56.625 | 0 | {'context_region': 12, 'primary_root_cause_region': 1, 'supporting_fix_region': 5} |
| linux | CVE-2022-0185 | completed | 1 | 900.282 | 1 | {'unknown_agent_failed': 1} |
| openjpeg | CVE-2020-27843 | completed | 1 | 7.734 | 0 | {'primary_root_cause_region': 1} |
| openjpeg | CVE-2020-27842 | completed | 1 | 15.375 | 0 | {'supporting_fix_region': 1} |
| openssl | CVE-2023-1255 | completed | 5 | 106.391 | 0 | {'context_region': 2, 'noise_region': 2, 'primary_root_cause_region': 1} |
| openssl | CVE-2023-6129 | completed | 3 | 94.156 | 0 | {'primary_root_cause_region': 2, 'supporting_fix_region': 1} |
| qemu | CVE-2023-0664 | completed | 4 | 130.609 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 3} |
| qemu | CVE-2020-12829 | completed | 1 | 12.985 | 0 | {'primary_root_cause_region': 1} |
| wireshark | CVE-2024-24479 | completed | 4 | 33.093 | 0 | {'context_region': 1, 'primary_root_cause_region': 1, 'supporting_fix_region': 2} |
| wireshark | CVE-2021-39926 | completed | 2 | 49.188 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 1} |
