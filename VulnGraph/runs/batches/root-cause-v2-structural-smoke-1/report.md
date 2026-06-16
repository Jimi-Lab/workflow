# Root Cause Agent v2 Batch Report

## Boundary

This run exercises the Root Cause Agent v2 workflow only. It does not run Judge Agent, BIC ranking, or affected-version conversion.

## Backend

- Backend type counts: `{'opencode': 1}`
- Real OpenCode invocation count: 1
- Ingested raw count: 1
- Structurally rejected count: 0
- Parse error count: 0
- Backend failed count: 0
- Fixture invocation count: 0
- Legacy compatibility field `opencode_real_results` (real OpenCode and ingested_raw only): 1
- OpenCode real results: 1 (legacy compatibility: ingested real OpenCode results, not invocation count)
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
- Shared structural error count: 0
- Invented ID cases: `[]`
- Lint/ingestion parity count: 1/1
- Contract taxonomy: `{}`
- Average binding complete rate: 1.000
- Missing GitObservation ref cases: `[]`
- Agent command invocation cases: `[]`
- Average packet size bytes: 9249.0
- Average evidence trace size bytes: 26066.0
- Average raw response size bytes: 2936.0
- Total duration seconds: 17.421
- Multi-fix commit cases: `[]`

## CVE Table

| CVE | Backend | Status | JSON Parse | Valid JSON | Contract OK | Contract Errors | Evidence Obs | Hypotheses | Evidence-backed Hypotheses | Fix Commits | Multi-fix | Multi-fix Mapping | Missing Obs Refs | Raw Bytes | Duration(s) | Errors |
| --- | --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: | --- |
| CVE-2022-3109 | opencode | ingested_raw | fenced_json | True | True | 0 | 3 | 1 | 1 | 1 | False | None | 0 | 2936 | 17.421 |  |

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
- Backend config: `{'base_url': 'http://127.0.0.1:4096', 'provider_id': 'google', 'model_id': 'gemini-2.5-flash', 'agent': None, 'timeout': 300.0}`
- Seed patch results: `[{'cve_id': 'CVE-2022-3109', 'repo': 'FFmpeg', 'commit_sha': '656cb0450aeb73b25d7d26980af342b37ac4c568', 'status': 'ok', 'nodes': 5, 'edges': 4}]`
- This report contains only real `backend_type=opencode` runs. Fixture outputs are not mixed into these counts.
