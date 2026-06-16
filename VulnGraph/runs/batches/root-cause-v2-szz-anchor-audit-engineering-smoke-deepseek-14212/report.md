# Root Cause to SZZ Anchor Audit

This run measures parent-side statement localization and blame candidate retrieval. It does not measure BIC correctness or infer affected versions.


## Metrics

- Cases: 1
- Requested / inventory built / agent accepted / blame evaluable / censored: 1 / 1 / 1 / 1 / 0
- Candidate inventory coverage: 1.000
- Statement localization precision: not computed (requires_manual_anchor_review)
- Handoff parse success: 1
- Contract acceptance: 1
- Resolved anchors: 4
- Direct old-side anchors: 2
- Add-only semantic anchors: 2
- Context-only noise rate: 0.0
- Blame-worthy anchor rate: 1.0
- Blame success rate: 1.0
- Candidate recall diagnostic: 1.0
- Candidates per anchor: 157.5
- Fix-family coverage anchored: 1/1 (1.0)
- Fix-family accounted coverage: 1/1 (1.0)
- Fix-family uncertain coverage: 0/1 (0.0)
- Fix-commit anchored coverage: 2/2 (1.0)
- Fix-commit accounted coverage: 2/2 (1.0)
- Original candidate count: 630
- Compacted candidate count: 44
- Mandatory candidates / budget overflow: 12 / 4
- Candidates without patch family: 0
- Root Cause hunk retention: 10/10 (1.0)
- Root Cause hunks requested / without blameable candidate: 10 / 0
- Fix commits prompt-covered: 2/2 (1.0)
- Average prompt bytes: 73685
- Multi-anchor coverage: 1 cases
- Blame success cases: 1
- Shallow history cases: `[]`
- Fix-series candidates excluded: 0
- Invented IDs: `[]`
- Git query count: 261
- Total duration: 186.469 seconds
- Total raw response size: 4970 characters
- Token usage: unavailable unless the OpenCode backend returns usage metadata.

## Per-CVE

| CVE | Status | Parse | Contract | Anchors | Blame | Candidate commits |
| --- | --- | --- | --- | ---: | --- | ---: |
| CVE-2020-14212 | ingested_raw_candidate | fenced_json | True | 4 | success | 2 |
