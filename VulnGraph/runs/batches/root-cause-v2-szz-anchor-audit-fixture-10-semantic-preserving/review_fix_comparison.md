# Semantic-Preserving Compaction Review

This is a fixture-only engineering audit. It validates pipeline behavior and contract semantics; it does not establish semantic anchor quality, BIC correctness, or affected-version correctness.

## Scope

- Previous run: `root-cause-v2-szz-anchor-audit-fixture-10-compact`
- Current run: `root-cause-v2-szz-anchor-audit-fixture-10-semantic-preserving`
- Backend: fixture
- Real DeepSeek invocations: 0
- Judge/BIC/affected-version inference: not executed

## Before / After

| Metric | Previous compact run | Semantic-preserving run |
|---|---:|---:|
| Original candidates | 4,526 | 4,526 |
| Compacted candidates | 360 | 367 |
| Mandatory candidates | not reported | 45 |
| Budget overflow | not reported | 7 |
| Average prompt bytes | 54,931.0 | 57,087.3 |
| Root Cause hunks requested | not reported | 44 |
| Root Cause hunks with blameable full-inventory candidates | not reported | 43 |
| Root Cause hunks preserved | not reported | 43 |
| Root Cause hunks dropped by compaction | not reported | 0 |
| Eligible hunk retention | not reported | 100% (43/43) |
| Fix commits represented in prompt | not reported | 100% (12/12) |
| Fix commits contract-anchored | not reported | 100% (12/12) |
| Patch families contract-anchored | 100% (11/11) | 100% (11/11) |
| Resolved anchors | 11 | 12 |

The seven-candidate budget overflow is intentional: mandatory reservation preserves Root Cause hunk and per-fix-commit semantics before ordinary top-k truncation. Average prompt size increased by 2,156.3 bytes (3.93%) while all 43 blameable Root Cause hunks and all 12 fix commits remained represented.

## Key Regression Cases

| CVE | Original -> compact | Mandatory / overflow | Eligible Root Cause hunk retention | Fix commit prompt coverage | Notes |
|---|---:|---:|---:|---:|---|
| CVE-2020-14212 | 630 -> 44 | 12 / 4 | 10/10 | 2/2 | Both fix commits are independently represented and anchored. |
| CVE-2020-13164 | 2,423 -> 42 | 7 / 2 | 7/7 | 1/1 | One requested hunk has no blameable candidate in the full inventory; compaction dropped none. |
| CVE-2022-0171 | 462 -> 41 | 2 / 1 | 2/2 | 1/1 | History is shallow, so the case is censored and excluded from blame-success/candidate-ready denominators. |

## Formal Metric Integrity

- Requested cases: 10
- Candidate inventories built: 10
- Agent accepted: 10
- Blame evaluable: 8
- Censored: 2 (`CVE-2022-0171`, `CVE-2022-0286`)
- Blame success among evaluable cases: 8/8
- Candidate-commit-ready cases: 8
- Unique raw candidate commits: 9

The censored cases are retained for diagnostics but excluded from blame-success, candidate-commit, and BIC-ready denominators. All outputs remain `raw_candidate`.

## Remaining Limits

- Fixture selection proves the compaction, contract, resolver, and blame pipeline only.
- `CVE-2020-13164` has one Root Cause-requested hunk without a blameable candidate in the full inventory; this is an upstream candidate-generation limitation, not a compaction loss.
- Two shallow repositories remain censored in formal mode.
- No real model semantic selection was measured in this run.
