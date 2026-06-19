# VulnGraph Judge Agent v0 Clean Smoke

Judge v0 ranks evidence-backed raw candidates only. It does not output BICs and does not perform affected-version conversion.

- cases_total: 1
- parse_ok_count: 1
- contract_ok_count: 1
- backend_failed_count: 0
- empty_message_count: 0
- forbidden_field_scan_ok: True
- attacker_context_available_count: 0
- attacker_context_unavailable_count: 1
- attacker_unavailable_but_used_count: 0
- lifecycle: raw_candidate_judged

| CVE | parse | contract | disposition | candidates | rankings |
|---|---|---:|---|---:|---|
| CVE-2020-1967 | json | True | ranked | 1 | `[{'candidate_id': 'pre-fix-line:e5ecd537cb332ded9cf6af2e2da76689c6d7230c05b896ee3dd7ad5d25ee50af', 'candidate_commit_sha': '604ba26560ca71bf8a1c127da96727b5b2b077e1', 'rank': 1, 'judgment': 'plausible_introduction_boundary', 'confidence': 'medium'}]` |
