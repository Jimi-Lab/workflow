# Step1 P4 OpenCode Real Validation

This validates Step1 region refinement against the real OpenCode backend.
It does not evaluate affected-version accuracy or Step3 probe reduction.

## Summary

- total_cves: 1
- completed_cves: 1
- failed_cves: 0
- agent_success_cves: 1
- agent_failed_cves: 0
- avg_latency_s: 70.422
- avg_regions: 2.0

## Per CVE

| repo | cve | status | regions | latency_s | unknown_agent_failed | roles |
| --- | --- | --- | ---: | ---: | ---: | --- |
| FFmpeg | CVE-2022-3965 | completed | 2 | 70.422 | 0 | {'primary_root_cause_region': 1, 'supporting_fix_region': 1} |
