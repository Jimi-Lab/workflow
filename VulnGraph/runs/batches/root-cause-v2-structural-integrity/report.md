# Root Cause Structural Integrity Hardening Report

## Scope

This pass hardens Root Cause Agent v2 structure only. It does not implement Judge Agent, BIC ranking, affected-version conversion, or a 10/30-CVE experiment.

## Changed Files

- `src/vulngraph/builder/patch.py`: conservative source-range and hunk-body function ownership.
- `src/vulngraph/agent_io/root_cause_schema.py`: strict aliases/IDs and canonical Agent-facing schema.
- `src/vulngraph/agent_io/root_cause_contract.py`: shared pure structural validation result.
- `src/vulngraph/agent_io/__init__.py`: shared validator exports.
- `src/vulngraph/services/ingestion.py`: ingestion consumes shared validation once.
- `src/vulngraph/prompts/root_cause_v2.md`: function, alias, condition, and fix-set contract instructions.
- `src/vulngraph/workflows/root_cause.py`: structural artifacts and corrected batch accounting.
- `src/vulngraph/agent_backend/opencode.py`: asynchronous prompt submission and error propagation.
- `scripts/replay_root_cause_structural.py`: fresh-store replay without Agent or legacy repair.
- `tests/test_root_cause_structural_integrity.py`: structural negative and parity regressions.
- `tests/test_opencode_backend_adapter.py`: async OpenCode text/error regressions.
- Existing evidence/contract/service fixtures were aligned with production graph ownership rules.

## Shared Validation Architecture

`validate_root_cause_structure(agent_output, packet, trace)` is side-effect free and returns packet indexes, trusted observations, per-semantic gate results, fix-set coverage, accepted/rejected hypothesis IDs, taxonomy, invented IDs, binding rate, and the final `ok` decision. The linter adapts this result for reporting; ingestion uses the same result for lifecycle and relationship persistence.

## Packet Fixture Root Cause

The original parity fixture omitted the production ownership chain needed to place `File` and `ChangedFunction` in packet scope. The fixture now includes `CVE -> FIXED_BY -> FixCommit` and asserts packet visibility plus PatchHunk-to-FixCommit/File/ChangedFunction mappings. Observation `file_ids` were not removed and the scope gate was not relaxed.

## Implemented Changes

- `PatchHunk -> ChangedFunction` is resolved from source ranges or actual hunk-body declarations. The `@@` header is never accepted as sole function evidence.
- Multi-line C function declarations are parsed conservatively. Ambiguous or unresolved hunks produce no `ChangedFunction` or `TOUCHES_FUNCTION` relation.
- Anchor validation requires packet-owned `function_id`, hunk ownership, exact function symbol agreement, and trusted observation scope coverage.
- Alias pairs must be identical when both are present. Empty or duplicate semantic IDs are parse errors.
- RootCauseHypothesis, VulnerablePredicate, FixPredicate, referenced GuardCondition, and referenced NegativeCondition share one pure structural validator with ingestion.
- Multi-fix completeness is evaluated by `fix_set_id` and counts only gate-accepted anchors.
- Agent-facing JSON Schema exposes canonical fields only; compatibility aliases remain parser-only and retain strict conflict rejection.
- OpenCode uses `/session/:id/prompt_async` plus message polling so asynchronous assistant errors are surfaced instead of being hidden behind a synchronous HTTP timeout.
- Reporting separates real OpenCode invocation count from `ingested_raw` count.

## Structural Trust Rules

1. Wrapper-owned ToolCall, ToolOutput, and GitObservation are the only trusted evidence sources.
2. Agent output may reference trusted observation IDs but cannot create or mutate trusted observations.
3. A gated anchor must jointly match FixCommit, PatchHunk, File, optional ChangedFunction, and a trusted observation with the same scope.
4. A hypothesis is accepted only when all referenced anchors and semantic nodes pass, vulnerable and fix predicates exist, and one declared fix set has complete accepted-anchor coverage.
5. Automatic ingestion lifecycle is at most `raw`.

## CVE-2020-24020 Function Integrity

- Hunk 2 resolves to `calculate_operand_data_length` using source-range analysis.
- It does not resolve to the misleading hunk-header context `calculate_operand_dims_count`.
- The native OpenCode pilot anchor uses:
  - PatchHunk: `patch-hunk:FFmpeg:584f396132aa19d21bb1e38ad9a5d428869290cb:libavfilter/dnn/dnn_backend_native.c:2`
  - ChangedFunction: `changed-function:FFmpeg:584f396132aa19d21bb1e38ad9a5d428869290cb:libavfilter/dnn/dnn_backend_native.c:calculate_operand_data_length`
  - Function symbol: `calculate_operand_data_length`

## Negative Tests

The regression suite covers:

- misleading `@@` function context;
- multi-line C function signatures;
- unknown function IDs;
- function ID and function name conflicts;
- function IDs owned by a different hunk;
- alias conflicts;
- empty and duplicate semantic IDs;
- referenced GuardCondition or NegativeCondition without a gated anchor;
- lint/ingestion parity;
- failed OpenCode invocations counted separately from ingestion success;
- multi-fix reporting based only on gate-accepted anchors;
- asynchronous OpenCode prompt/error handling.

## Legacy Replay

Command:

```powershell
python scripts\replay_root_cause_structural.py --source runs\batches\root-cause-v2-contract-pilot-3 --out-dir runs\batches\root-cause-v2-structural-replay-3 --reset
```

Result:

- Agent invocations: 0
- Legacy adapters: 0
- Status: 3 rejected, 0 accepted
- Structural errors: 21
- Lint/ingestion parity: true

The rejection is expected. These old outputs contain stale function mappings and incomplete structural bindings. The gate was not relaxed to preserve prior success labels.

## Real OpenCode Smoke

Command:

```powershell
python scripts\run_root_cause_opencode_pilot.py --mode smoke-1 --out-dir runs\batches\root-cause-v2-structural-smoke-1 --provider-id google --model-id gemini-2.5-flash --timeout 300 --reset
```

Result:

- Real OpenCode invocations: 1
- Valid JSON: 1
- `ingested_raw`: 1
- Evidence-backed hypotheses: 1
- Structural errors: 0
- Binding complete rate: 1.0
- Lint/ingestion parity: 1/1
- Fixture and legacy adapter usage: 0

## Real OpenCode Pilot

Command:

```powershell
python scripts\run_root_cause_opencode_pilot.py --mode pilot-3 --out-dir runs\batches\root-cause-v2-structural-pilot-3 --provider-id google --model-id gemini-2.5-flash --timeout 300 --reset
```

| CVE | Result | Contract | Binding | Evidence-backed hypotheses | Multi-fix coverage |
| --- | --- | --- | ---: | ---: | --- |
| CVE-2022-3109 | ingested_raw | pass | 1.0 | 1 | n/a |
| CVE-2023-47342 | ingested_raw | pass | 1.0 | 1 | pass |
| CVE-2020-24020 | ingested_raw | pass | 1.0 | 1 | n/a |

Aggregate:

- Real OpenCode invocations: 3
- `ingested_raw`: 3
- Structural rejection / parse error / backend failure: 0 / 0 / 0
- Invented IDs: 0
- Structural errors: 0
- Lint/ingestion parity: 3/3
- Multi-fix case `CVE-2023-47342`: complete gate-accepted anchor coverage

## Verification

```powershell
python -m pytest -q
# 104 passed in 9.24s

python -m compileall src tests scripts
# exit code 0
```

The full suite also covers invalid ToolCall/ToolOutput provenance, observation scope outside the packet, independently gated mixed hypotheses, production packet policy filtering, and exact SUPPORTS relationships in addition to the structural tests listed above.

## Environment Notes

- The default free OpenCode model returned a rate-limit error.
- `xiaoaiplus/gpt-5.4` returned insufficient quota and `openai/gpt-5.4` was at its current usage limit.
- `google/gemini-2.5-flash` passed a real provider probe and was used for the accepted smoke and pilot.
- The adapter now exposes provider errors promptly instead of reporting a misleading 300-second timeout.

## Readiness

The structural acceptance conditions are met for entering a 10-CVE Root Cause semantic evaluation. This report does not claim semantic accuracy beyond the three manually inspected pilot cases, and all accepted graph nodes remain lifecycle `raw`.

## Known Limitations

- Function range extraction is conservative brace-based parsing, not a compiler AST; unsupported languages or macro-heavy declarations may remain unresolved by design.
- Provider availability is external state. The accepted regression used `google/gemini-2.5-flash`; other configured providers were quota-limited or unreachable during this run.
- Old private ingestion helper functions remain in the module but are not used by the active Root Cause ingestion path; removing them is cleanup, not a gate requirement.
- Three structurally accepted cases establish interface integrity, not semantic accuracy or generalization.
