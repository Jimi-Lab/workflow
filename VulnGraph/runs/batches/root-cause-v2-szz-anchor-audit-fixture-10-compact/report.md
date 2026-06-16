# Root Cause to SZZ Anchor Audit

This run measures parent-side statement localization and blame candidate retrieval. It does not measure BIC correctness or infer affected versions.
Fixture mode only proves pipeline integrity; it does not prove semantic anchor quality.

## Metrics

- Cases: 10
- Candidate inventory coverage: 1.000
- Statement localization precision: not computed (requires_manual_anchor_review)
- Handoff parse success: 10
- Contract acceptance: 10
- Resolved anchors: 11
- Direct old-side anchors: 9
- Add-only semantic anchors: 2
- Context-only noise rate: 0.0
- Blame-worthy anchor rate: 1.0
- Blame success rate: 0.8181818181818182
- Candidate recall diagnostic: 1.0
- Candidates per anchor: 411.45454545454544
- Fix-family coverage anchored: 11/11 (1.0)
- Fix-family accounted coverage: 11/11 (1.0)
- Fix-family uncertain coverage: 0/11 (0.0)
- Original candidate count: 4526
- Compacted candidate count: 360
- Average prompt bytes: 54931
- Multi-anchor coverage: 1 cases
- Blame success cases: 8
- Shallow history cases: `['CVE-2022-0171', 'CVE-2022-0286']`
- Fix-series candidates excluded: 0
- Invented IDs: `[]`
- Git query count: 567
- Total duration: 32.203 seconds
- Total raw response size: 9686 characters
- Token usage: unavailable unless the OpenCode backend returns usage metadata.

## Per-CVE

| CVE | Status | Parse | Contract | Anchors | Blame | Candidate commits |
| --- | --- | --- | --- | ---: | --- | ---: |
| CVE-2020-14212 | ingested_raw_candidate | json | True | 1 | success | 1 |
| CVE-2020-19667 | ingested_raw_candidate | json | True | 1 | success | 1 |
| CVE-2020-8231 | ingested_raw_candidate | json | True | 1 | success | 1 |
| CVE-2020-11984 | ingested_raw_candidate | json | True | 2 | success | 2 |
| CVE-2022-0171 | raw_candidate_censored | json | True | 1 | shallow_history | 0 |
| CVE-2022-0286 | raw_candidate_censored | json | True | 1 | shallow_history | 0 |
| CVE-2020-15389 | ingested_raw_candidate | json | True | 1 | success | 1 |
| CVE-2020-1967 | ingested_raw_candidate | json | True | 1 | success | 1 |
| CVE-2020-11869 | ingested_raw_candidate | json | True | 1 | success | 1 |
| CVE-2020-13164 | ingested_raw_candidate | json | True | 1 | success | 1 |
