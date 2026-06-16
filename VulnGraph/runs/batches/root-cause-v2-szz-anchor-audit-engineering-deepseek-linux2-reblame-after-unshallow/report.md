# Root Cause to SZZ Anchor Audit

This run measures parent-side statement localization and blame candidate retrieval. It does not measure BIC correctness or infer affected versions.


## Metrics

- Cases: 2
- Requested / inventory built / agent accepted / blame evaluable / censored: 2 / 2 / 2 / 2 / 0
- Candidate inventory coverage: 1.000
- Statement localization precision: not computed (requires_manual_anchor_review)
- Handoff parse success: 2
- Contract acceptance: 2
- Resolved anchors: 4
- Direct old-side anchors: 2
- Add-only semantic anchors: 2
- Context-only noise rate: 0.0
- Blame-worthy anchor rate: 1.0
- Blame success rate: 1.0
- Candidate recall diagnostic: 1.0
- Candidates per anchor: 122.5
- Fix-family coverage anchored: 2/2 (1.0)
- Fix-family accounted coverage: 2/2 (1.0)
- Fix-family uncertain coverage: 0/2 (0.0)
- Fix-commit anchored coverage: 2/2 (1.0)
- Fix-commit accounted coverage: 2/2 (1.0)
- Original candidate count: 490
- Compacted candidate count: 69
- Mandatory candidates / budget overflow: 3 / 1
- Candidates without patch family: 0
- Root Cause hunk retention: 3/3 (1.0)
- Root Cause hunks requested / without blameable candidate: 3 / 0
- Fix commits prompt-covered: 2/2 (1.0)
- Average prompt bytes: 50479
- Multi-anchor coverage: 2 cases
- Blame success cases: 2
- Shallow history cases: `[]`
- Fix-series candidates excluded: 0
- Invented IDs: `[]`
- Git query count: 14
- Total duration: 1.656 seconds
- Total raw response size: 6410 characters
- Token usage: unavailable unless the OpenCode backend returns usage metadata.

## Per-CVE

| CVE | Status | Parse | Contract | Anchors | Blame | Candidate commits |
| --- | --- | --- | --- | ---: | --- | ---: |
| CVE-2022-0171 | ingested_raw_candidate | fenced_json | True | 2 | success | 2 |
| CVE-2022-0286 | ingested_raw_candidate | fenced_json | True | 2 | success | 2 |
