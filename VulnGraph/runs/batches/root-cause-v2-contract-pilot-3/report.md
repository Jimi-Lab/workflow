# Root Cause Agent v2 Batch Report

## Boundary

This run exercises the Root Cause Agent v2 workflow only. It does not run Judge Agent, BIC ranking, or affected-version conversion.

## Backend

- Backend type counts: `{'opencode': 3}`
- OpenCode real results: 3
- Fixture results: 0

## Aggregate

- Total CVEs: 3
- Status counts: `{'ingested_raw': 3}`
- JSON parse status counts: `{'fenced_json': 3}`
- Valid JSON: 3
- Malformed JSON: 0
- Empty message: 0
- Evidence-backed RootCauseHypothesis count: 3
- Rejected count: 0
- FailureCase count: 0
- Contract OK count: 3
- Contract error count: 0
- Contract taxonomy: `{}`
- Average binding complete rate: 1.000
- Missing GitObservation ref cases: `[]`
- Agent command invocation cases: `[]`
- Average packet size bytes: 21967.3
- Average evidence trace size bytes: 45802.0
- Average raw response size bytes: 5507.7
- Total duration seconds: 87.703
- Multi-fix commit cases: `['CVE-2023-47342']`

## CVE Table

| CVE | Backend | Status | JSON Parse | Valid JSON | Contract OK | Contract Errors | Evidence Obs | Hypotheses | Evidence-backed Hypotheses | Fix Commits | Multi-fix | Multi-fix Mapping | Missing Obs Refs | Raw Bytes | Duration(s) | Errors |
| --- | --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: | --- |
| CVE-2022-3109 | opencode | ingested_raw | fenced_json | True | True | 0 | 3 | 1 | 1 | 1 | False | None | 0 | 4060 | 24.187 |  |
| CVE-2023-47342 | opencode | ingested_raw | fenced_json | True | True | 0 | 6 | 1 | 1 | 2 | True | True | 0 | 7535 | 42.141 |  |
| CVE-2020-24020 | opencode | ingested_raw | fenced_json | True | True | 0 | 10 | 1 | 1 | 1 | False | None | 0 | 4928 | 21.375 |  |

## Multi-Fix Representation

Multi-fix cases are detected by `fix_commit_count > 1`. The packet and evidence trace preserve every `FixCommit`; valid agent outputs are checked for `fix_commit_id`, `patch_hunk_id`, and `anchor_id` mappings. This confirms representational support, not semantic correctness.

## Failure Attribution

`{}`

## Next Prompt/Schema Optimization

- When OpenCode server is reachable, run the same workflow with real OpenCode backend and compare valid JSON / empty-message rates against the fixture smoke baseline.
- Keep wrapper trace as the authoritative command/evidence source; agent JSON should only reference `git_observation_refs`.
- Add stricter per-hypothesis evidence checks for specific patch hunks and changed functions after real OpenCode output is available.
- Add deterministic normalization only for syntactic fenced JSON, not for missing evidence or invented fields.

## OpenCode Pilot Notes

- Mode: `pilot-3`
- Selected CVEs: `['CVE-2022-3109', 'CVE-2023-47342', 'CVE-2020-24020']`
- Backend config: `{'base_url': 'http://127.0.0.1:4096', 'provider_id': None, 'model_id': None, 'agent': None, 'timeout': 300.0}`
- Seed patch results: `[{'cve_id': 'CVE-2020-24020', 'repo': 'FFmpeg', 'commit_sha': '584f396132aa19d21bb1e38ad9a5d428869290cb', 'status': 'ok', 'nodes': 28, 'edges': 28}, {'cve_id': 'CVE-2022-3109', 'repo': 'FFmpeg', 'commit_sha': '656cb0450aeb73b25d7d26980af342b37ac4c568', 'status': 'ok', 'nodes': 4, 'edges': 3}, {'cve_id': 'CVE-2023-47342', 'repo': 'FFmpeg', 'commit_sha': 'd254fe2d1da3b1cba3526c5d6417c9912e330988', 'status': 'ok', 'nodes': 4, 'edges': 3}, {'cve_id': 'CVE-2023-47342', 'repo': 'FFmpeg', 'commit_sha': 'e4d5ac8d7d2a08658b3db7dd821246fe6b35381f', 'status': 'ok', 'nodes': 4, 'edges': 3}]`
- This report contains only real `backend_type=opencode` runs. Fixture outputs are not mixed into these counts.
## Native Evidence Gate Audit

- Accepted / ingested_raw: 3
- Rejected: 0
- Partial/other: 0
- Raw response empty count: 0
- JSON parse status counts: `{'fenced_json': 3}`
- Evidence-backed RootCauseHypothesis count: 3
- FailureCase count: 0
- Contract OK count: 3
- Contract error count: 0
- Contract taxonomy: `{}`
- Invented ID cases: `[]`
- Rejected reason classes: `{}`
- Native wrapper observation provenance: `True`
- ToolCall -> ToolOutput -> GitObservation traceability: `True`
- Accepted hypothesis Anchor -> PatchHunk -> FixCommit consistency: `True`
- All agent anchors Anchor -> PatchHunk -> FixCommit consistency: `True`
- fix_set_id coverage complete cases: 3/3
- SUPPORTS only trusted explicit refs: `True`
- Semantic lifecycle no validated nodes: `True`
- Production packet leakage: `True`
- Legacy adapter count: 0
- Agent command invocation cases: 0

| CVE | Status | Parse | Contract OK | Contract Errors | Hyp | Evidence-backed | Native Prov | Traceable | Accepted Anchor OK | All Agent Anchors OK | Fix-set Complete | Lifecycle OK | Leakage OK | Legacy | Main Rejection |
| --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | ---: | --- |
| CVE-2020-24020 | ingested_raw | fenced_json | True | 0 | 1 | 1 | True | True | True | True | True | True | True | 0 |  |
| CVE-2022-3109 | ingested_raw | fenced_json | True | 0 | 1 | 1 | True | True | True | True | True | True | True | 0 |  |
| CVE-2023-47342 | ingested_raw | fenced_json | True | 0 | 1 | 1 | True | True | True | True | True | True | True | 0 |  |
