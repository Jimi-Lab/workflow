# Root Cause Agent v2 10-CVE Report

## Boundary

This run exercises the Root Cause Agent v2 workflow only. It does not run Judge Agent, BIC ranking, or affected-version conversion.

## Backend

- Backend type counts: `{'fixture': 10}`
- OpenCode real results: 0
- Fixture results: 10

## Aggregate

- Total CVEs: 10
- Status counts: `{'accepted': 10}`
- Valid JSON: 10
- Malformed JSON: 0
- Empty message: 0
- Evidence-backed RootCauseHypothesis count: 10
- Rejected count: 0
- Average packet size bytes: 45850.1
- Average evidence trace size bytes: 46141.8
- Multi-fix commit cases: `['CVE-2020-14212', 'CVE-2022-48434', 'CVE-2023-47342', 'CVE-2020-12284']`

## 10-CVE Table

| CVE | Backend | Status | Valid JSON | Evidence Obs | Hypotheses | Evidence-backed Hypotheses | Fix Commits | Multi-fix | Errors |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| CVE-2022-3965 | fixture | accepted | True | 3 | 1 | 1 | 1 | False |  |
| CVE-2020-24020 | fixture | accepted | True | 10 | 1 | 1 | 1 | False |  |
| CVE-2022-3341 | fixture | accepted | True | 3 | 1 | 1 | 1 | False |  |
| CVE-2022-3109 | fixture | accepted | True | 3 | 1 | 1 | 1 | False |  |
| CVE-2024-7055 | fixture | accepted | True | 3 | 1 | 1 | 1 | False |  |
| CVE-2020-14212 | fixture | accepted | True | 20 | 1 | 1 | 2 | True |  |
| CVE-2022-48434 | fixture | accepted | True | 6 | 1 | 1 | 2 | True |  |
| CVE-2023-47342 | fixture | accepted | True | 6 | 1 | 1 | 2 | True |  |
| CVE-2022-3964 | fixture | accepted | True | 3 | 1 | 1 | 1 | False |  |
| CVE-2020-12284 | fixture | accepted | True | 9 | 1 | 1 | 3 | True |  |

## Multi-Fix Representation

Multi-fix cases are detected by `fix_commit_count > 1`. The packet and evidence trace preserve every `FixCommit`; fixture outputs emit per-fix anchors with `fix_commit_id`, `patch_hunk_id`, and `anchor_id` mappings for smoke validation. This confirms representational support, not real semantic quality.

## Failure Attribution

`{}`

## Next Prompt/Schema Optimization

- Run the same workflow with real OpenCode backend and compare valid JSON / empty-message rates against the fixture smoke baseline.
- Keep wrapper trace as the authoritative command/evidence source; agent JSON should only reference `git_observation_refs`.
- Add stricter per-hypothesis evidence checks for specific patch hunks and changed functions after real OpenCode output is available.
- Add deterministic normalization only for syntactic fenced JSON, not for missing evidence or invented fields.
