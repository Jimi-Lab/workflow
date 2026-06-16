# Root Cause Agent v2 Batch Report

## Boundary

This run exercises the Root Cause Agent v2 workflow only. It does not run Judge Agent, BIC ranking, or affected-version conversion.

## Backend

- Backend type counts: `{'opencode': 3}`
- Real OpenCode invocation count: 3
- Ingested raw count: 3
- Structurally rejected count: 0
- Parse error count: 0
- Backend failed count: 0
- Fixture invocation count: 0
- Legacy compatibility field `opencode_real_results` (real OpenCode and ingested_raw only): 3
- OpenCode real results: 3 (legacy compatibility: ingested real OpenCode results, not invocation count)
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
- Shared structural error count: 0
- Invented ID cases: `[]`
- Lint/ingestion parity count: 3/3
- Contract taxonomy: `{}`
- Average binding complete rate: 1.000
- Missing GitObservation ref cases: `[]`
- Agent command invocation cases: `[]`
- Average packet size bytes: 28223.3
- Average evidence trace size bytes: 47100.0
- Average raw response size bytes: 4301.0
- Total duration seconds: 70.157
- Multi-fix commit cases: `['CVE-2023-47342']`

## CVE Table

| CVE | Backend | Status | JSON Parse | Valid JSON | Contract OK | Contract Errors | Evidence Obs | Hypotheses | Evidence-backed Hypotheses | Fix Commits | Multi-fix | Multi-fix Mapping | Missing Obs Refs | Raw Bytes | Duration(s) | Errors |
| --- | --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: | --- |
| CVE-2022-3109 | opencode | ingested_raw | fenced_json | True | True | 0 | 3 | 1 | 1 | 1 | False | None | 0 | 3073 | 11.250 |  |
| CVE-2023-47342 | opencode | ingested_raw | fenced_json | True | True | 0 | 6 | 1 | 1 | 2 | True | True | 0 | 4718 | 33.844 |  |
| CVE-2020-24020 | opencode | ingested_raw | fenced_json | True | True | 0 | 10 | 1 | 1 | 1 | False | None | 0 | 5112 | 25.063 |  |

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
- Backend config: `{'base_url': 'http://127.0.0.1:4096', 'provider_id': 'google', 'model_id': 'gemini-2.5-flash', 'agent': None, 'timeout': 300.0}`
- Seed patch results: `[{'cve_id': 'CVE-2020-24020', 'repo': 'FFmpeg', 'commit_sha': '584f396132aa19d21bb1e38ad9a5d428869290cb', 'status': 'ok', 'nodes': 35, 'edges': 35}, {'cve_id': 'CVE-2022-3109', 'repo': 'FFmpeg', 'commit_sha': '656cb0450aeb73b25d7d26980af342b37ac4c568', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2023-47342', 'repo': 'FFmpeg', 'commit_sha': 'd254fe2d1da3b1cba3526c5d6417c9912e330988', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2023-47342', 'repo': 'FFmpeg', 'commit_sha': 'e4d5ac8d7d2a08658b3db7dd821246fe6b35381f', 'status': 'ok', 'nodes': 5, 'edges': 4}]`
- This report contains only real `backend_type=opencode` runs. Fixture outputs are not mixed into these counts.
