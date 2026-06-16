# Root Cause to SZZ Anchor Audit

This run measures parent-side statement localization and blame candidate retrieval. It does not measure BIC correctness or infer affected versions.


## Metrics

- Cases: 1
- Candidate inventory coverage: 1.000
- Statement localization precision: not computed (requires_manual_anchor_review)
- Handoff parse success: 1
- Contract acceptance: 1
- Resolved anchors: 1
- Direct old-side anchors: 1
- Add-only semantic anchors: 0
- Context-only noise rate: 0.0
- Blame-worthy anchor rate: 1.0
- Blame success rate: 1.0
- Candidate recall diagnostic: 1.0
- Candidates per anchor: 1.0
- Fix-family coverage anchored: 1/1 (1.0)
- Fix-family accounted coverage: 1/1 (1.0)
- Fix-family uncertain coverage: 0/1 (0.0)
- Original candidate count: 1
- Compacted candidate count: 1
- Average prompt bytes: 9847
- Multi-anchor coverage: 0 cases
- Blame success cases: 1
- Shallow history cases: `[]`
- Fix-series candidates excluded: 0
- Invented IDs: `[]`
- Git query count: 9
- Total duration: 19.187 seconds
- Total raw response size: 1729 characters
- Token usage: unavailable unless the OpenCode backend returns usage metadata.

## Per-CVE

| CVE | Status | Parse | Contract | Anchors | Blame | Candidate commits |
| --- | --- | --- | --- | ---: | --- | ---: |
| CVE-2020-1967 | ingested_raw_candidate | fenced_json | True | 1 | success | 1 |
