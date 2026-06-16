# Step1 P4 OpenCode Real Validation

This validates Step1 region refinement against the real OpenCode backend.
It does not evaluate affected-version accuracy or Step3 probe reduction.

## Summary

- total_cves: 3
- completed_cves: 3
- failed_cves: 0
- agent_success_cves: 1
- agent_failed_cves: 2
- avg_latency_s: 132.354
- avg_regions: 2.333

## Per CVE

| repo | cve | status | regions | latency_s | unknown_agent_failed | roles |
| --- | --- | --- | ---: | ---: | ---: | --- |
| FFmpeg | CVE-2022-3965 | completed | 2 | 94.672 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 1} |
| curl | CVE-2020-8169 | completed | 3 | 53.703 | 3 | {'unknown_agent_failed': 3} |
| openjpeg | CVE-2020-15389 | completed | 2 | 248.688 | 2 | {'unknown_agent_failed': 2} |
