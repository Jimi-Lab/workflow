# Root Cause Agent v2 Batch Report

## Boundary

This run exercises the Root Cause Agent v2 workflow only. It does not run Judge Agent, BIC ranking, or affected-version conversion.

## Backend

- Backend type counts: `{'opencode': 1}`
- OpenCode real results: 1
- Fixture results: 0

## Aggregate

- Total CVEs: 1
- Status counts: `{'ingested_raw': 1}`
- JSON parse status counts: `{'fenced_json': 1}`
- Valid JSON: 1
- Malformed JSON: 0
- Empty message: 0
- Evidence-backed RootCauseHypothesis count: 1
- Rejected count: 0
- FailureCase count: 0
- Contract OK count: 1
- Contract error count: 0
- Contract taxonomy: `{}`
- Average binding complete rate: 1.000
- Missing GitObservation ref cases: `[]`
- Agent command invocation cases: `[]`
- Average packet size bytes: 7602.0
- Average evidence trace size bytes: 25766.0
- Average raw response size bytes: 2982.0
- Total duration seconds: 22.890
- Multi-fix commit cases: `[]`

## CVE Table

| CVE | Backend | Status | JSON Parse | Valid JSON | Contract OK | Contract Errors | Evidence Obs | Hypotheses | Evidence-backed Hypotheses | Fix Commits | Multi-fix | Multi-fix Mapping | Missing Obs Refs | Raw Bytes | Duration(s) | Errors |
| --- | --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: | --- |
| CVE-2022-3109 | opencode | ingested_raw | fenced_json | True | True | 0 | 3 | 1 | 1 | 1 | False | None | 0 | 2982 | 22.890 |  |

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

- Mode: `smoke-1`
- Selected CVEs: `['CVE-2022-3109']`
- Backend config: `{'base_url': 'http://127.0.0.1:4096', 'provider_id': None, 'model_id': None, 'agent': None, 'timeout': 300.0}`
- Seed patch results: `[{'cve_id': 'CVE-2022-3109', 'repo': 'FFmpeg', 'commit_sha': '656cb0450aeb73b25d7d26980af342b37ac4c568', 'status': 'ok', 'nodes': 4, 'edges': 3}]`
- This report contains only real `backend_type=opencode` runs. Fixture outputs are not mixed into these counts.
## Native Evidence Gate Audit

- Accepted / ingested_raw: 1
- Rejected: 0
- Partial/other: 0
- Raw response empty count: 0
- JSON parse status counts: `{'fenced_json': 1}`
- Evidence-backed RootCauseHypothesis count: 1
- FailureCase count: 0
- Contract OK count: 1
- Contract error count: 0
- Contract taxonomy: `{}`
- Invented ID cases: `[]`
- Rejected reason classes: `{}`
- Native wrapper observation provenance: `True`
- ToolCall -> ToolOutput -> GitObservation traceability: `True`
- Accepted hypothesis Anchor -> PatchHunk -> FixCommit consistency: `True`
- All agent anchors Anchor -> PatchHunk -> FixCommit consistency: `True`
- fix_set_id coverage complete cases: 1/1
- SUPPORTS only trusted explicit refs: `True`
- Semantic lifecycle no validated nodes: `True`
- Production packet leakage: `True`
- Legacy adapter count: 0
- Agent command invocation cases: 0

| CVE | Status | Parse | Contract OK | Contract Errors | Hyp | Evidence-backed | Native Prov | Traceable | Accepted Anchor OK | All Agent Anchors OK | Fix-set Complete | Lifecycle OK | Leakage OK | Legacy | Main Rejection |
| --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | --- | --- | ---: | --- |
| CVE-2022-3109 | ingested_raw | fenced_json | True | 0 | 1 | 1 | True | True | True | True | True | True | True | 0 |  |
