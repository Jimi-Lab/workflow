# Root Cause to SZZ Anchor Audit

This run measures parent-side statement localization and blame candidate retrieval. It does not measure BIC correctness or infer affected versions.


## Metrics

- Cases: 27
- Requested / inventory built / agent accepted / blame evaluable / censored: 27 / 27 / 21 / 21 / 0
- Candidate inventory coverage: 1.000
- Statement localization precision: not computed (requires_manual_anchor_review)
- Handoff parse success: 21
- Contract acceptance: 21
- Resolved anchors: 46
- Direct old-side anchors: 35
- Add-only semantic anchors: 10
- Context-only noise rate: 0.021739130434782608
- Blame-worthy anchor rate: 0.9782608695652174
- Blame success rate: 1.0
- Candidate recall diagnostic: 1.0
- Candidates per anchor: 187.2391304347826
- Fix-family coverage anchored: 22/23 (0.9565217391304348)
- Fix-family accounted coverage: 23/23 (1.0)
- Fix-family uncertain coverage: 1/23 (0.043478260869565216)
- Fix-commit anchored coverage: 22/23 (0.9565217391304348)
- Fix-commit accounted coverage: 23/23 (1.0)
- Original candidate count: 8613
- Compacted candidate count: 706
- Mandatory candidates / budget overflow: 63 / 7
- Candidates without patch family: 0
- Root Cause hunk retention: 57/57 (1.0)
- Root Cause hunks requested / without blameable candidate: 62 / 5
- Fix commits prompt-covered: 32/32 (1.0)
- Average prompt bytes: 43701.7037037037
- Multi-anchor coverage: 15 cases
- Blame success cases: 21
- Shallow history cases: `[]`
- Fix-series candidates excluded: 0
- Invented IDs: `[]`
- Git query count: 1304
- Total duration: 2134.89 seconds
- Total raw response size: 66690 characters
- Token usage: unavailable unless the OpenCode backend returns usage metadata.

## Per-CVE

| CVE | Status | Parse | Contract | Anchors | Blame | Candidate commits |
| --- | --- | --- | --- | ---: | --- | ---: |
| CVE-2020-12284 | contract_rejected |  |  | 0 |  | 0 |
| CVE-2020-14212 | contract_rejected |  |  | 0 |  | 0 |
| CVE-2020-10251 | ingested_raw_candidate | fenced_json | True | 2 | success | 2 |
| CVE-2020-25663 | ingested_raw_candidate | fenced_json | True | 2 | success | 2 |
| CVE-2020-8169 | handoff_parse_error |  |  | 0 |  | 0 |
| CVE-2020-8177 | ingested_raw_candidate | fenced_json | True | 3 | success | 3 |
| CVE-2020-8231 | ingested_raw_candidate | fenced_json | True | 3 | success | 2 |
| CVE-2020-11984 | ingested_raw_candidate | json | True | 4 | success | 3 |
| CVE-2020-11985 | ingested_raw_candidate | fenced_json | True | 1 | success | 1 |
| CVE-2020-11993 | ingested_raw_candidate | fenced_json | True | 1 | success | 1 |
| CVE-2022-0171 | ingested_raw_candidate | fenced_json | True | 3 | success | 2 |
| CVE-2022-0185 | ingested_raw_candidate | json | True | 1 | success | 1 |
| CVE-2022-0264 | ingested_raw_candidate | fenced_json | True | 1 | success | 1 |
| CVE-2022-0286 | ingested_raw_candidate | fenced_json | True | 2 | success | 2 |
| CVE-2022-0322 | ingested_raw_candidate | json | True | 1 | success | 1 |
| CVE-2022-0433 | contract_rejected |  |  | 0 |  | 0 |
| CVE-2020-15389 | ingested_raw_candidate | fenced_json | True | 4 | success | 3 |
| CVE-2020-27823 | ingested_raw_candidate | fenced_json | True | 2 | success | 1 |
| CVE-2020-1967 | ingested_raw_candidate | fenced_json | True | 1 | success | 1 |
| CVE-2020-1971 | contract_rejected |  |  | 0 |  | 0 |
| CVE-2021-23840 | ingested_raw_candidate | fenced_json | True | 2 | success | 2 |
| CVE-2020-10702 | ingested_raw_candidate | fenced_json | True | 2 | success | 1 |
| CVE-2020-11869 | ingested_raw_candidate | fenced_json | True | 3 | success | 2 |
| CVE-2020-11947 | ingested_raw_candidate | fenced_json | True | 2 | success | 1 |
| CVE-2020-11647 | ingested_raw_candidate | fenced_json | True | 3 | success | 3 |
| CVE-2020-13164 | ingested_raw_candidate | fenced_json | True | 3 | success | 2 |
| CVE-2020-15466 | contract_rejected |  |  | 0 |  | 0 |
