# Root Cause Evidence Gate Hardening Report

## Scope

This pass completes Root Cause evidence gating only. It did not call OpenCode, run a 10/30-CVE experiment, implement Judge Agent, rank BIC candidates, or convert affected versions.

## Changed Files

- `src/vulngraph/workflows/git_evidence.py`: wrapper provenance, ToolOutput records, packet-derived evidence scope, semantic validity checks, and controlled legacy replay adapter.
- `src/vulngraph/services/ingestion.py`: trusted-trace validation, anchor consistency, fix-set-aware completeness, minimum hypothesis contract, semantic lifecycle closure, and per-hypothesis FailureCase creation.
- `src/vulngraph/services/common.py`: ingestion details and collision-resistant run/hypothesis-scoped FailureCase IDs.
- `src/vulngraph/services/graph_client.py`: supplies the production packet to the ingestion gate when callers omit it.
- `src/vulngraph/services/packets.py`: excludes agent-generated anchors from Root Cause patch input and builds downstream semantic packets from the selected hypothesis closure only.
- `src/vulngraph/agent_io/root_cause_schema.py`: adds optional `fix_set_ids` without expanding the ontology.
- `src/vulngraph/builder/patch.py`: preserves dataset `fix_set_id/group_index/order` during patch import.
- `src/vulngraph/cli/main.py` and `scripts/run_root_cause_opencode_pilot.py`: pass FixCommit metadata into patch import.
- `src/vulngraph/workflows/root_cause.py`: serializes detailed gate results.
- `scripts/replay_evidence_gate_legacy.py`: offline-only controlled replay for old artifacts.
- `tests/test_evidence_gate_completion.py`, `tests/test_services.py`, and `tests/test_root_cause_workflow_v2.py`: positive and negative gate coverage.

## Wrapper Evidence Provenance

Native collector observations now contain:

```text
source=wrapper_git_trace
valid_evidence
observation_kind
command_ref
tool_output_ref
fix_commit_ids
patch_hunk_ids
file_ids
function_ids
path / claim / snippet
```

The wrapper derives these fields from the production packet and the command it actually executed. Agent output is never used to create ToolCall, ToolOutput, GitObservation, or observation scope.

`valid_evidence` is command-type aware. Successful patch commands require identifiable commit/patch output; file history requires meaningful matching history; explicit negative observations are handled separately. Failure, timeout, missing commit, empty/invalid output, or absent packet scope produces `valid_evidence=false`.

## Trusted Observation Validation

An observation can support semantic nodes only when all checks pass:

- trace, ToolCall, ToolOutput, and observation are wrapper-owned;
- CVE and trace-run scope agree;
- observation ID is unique;
- `valid_evidence=true` and `observation_kind` is present;
- `command_ref` resolves to one real ToolCall;
- `tool_output_ref` resolves to the output produced by that ToolCall;
- commit/hunk/file/function IDs exist in the packet and do not contradict packet scope.

Rejected observations remain raw debug/context nodes but cannot create `SUPPORTS` edges.

## Anchor Consistency

The CodeAnchor gate runs for single-fix and multi-fix CVEs. It verifies FixCommit and PatchHunk existence, hunk-to-commit ownership, path consistency, trusted observation references, FixCommit coverage, and hunk/file coverage when the observation exposes that scope. Optional function scope is enforced only when an explicit hunk-to-function association exists; ambiguous path-level inference is not treated as proof.

## Fix-Set-Aware Multi-Fix Gate

Fix commits are grouped by dataset `fix_set_id`. A hypothesis may select one or more fix sets through `fix_set_ids`, or through `fix_commit_ids` that map deterministically to fix sets. Every commit in at least one declared fix set must have a gated anchor. Alternative fix sets are evaluated independently rather than flattened into one mandatory collection.

`IngestionResult.details.fix_set_results` reports expected, covered, and missing commits, invalid anchors, and completeness. Tests cover one commit, multi-commit sets, multiple alternative sets, and a 15-commit set without truncation.

## Minimum Root Cause Contract

A raw hypothesis requires at least:

- one gated CodeAnchor;
- one gated VulnerablePredicate;
- one gated FixPredicate;
- one trusted GitObservation.

Each predicate must connect to a gated anchor. The hypothesis and every referenced semantic node must share trusted evidence. Guard and negative conditions remain optional.

## Semantic Lifecycle

- Gate-valid nodes referenced by a raw hypothesis: `raw`.
- Nodes referenced only by rejected hypotheses: `rejected`.
- Gate-valid but unused nodes: `candidate`.
- RiskFlag: `candidate + learning_candidate`.
- UncertaintyReason: `raw + context_only`.
- Automated ingestion never creates `validated` nodes.

Production downstream packets select the semantic closure of one raw/validated hypothesis and exclude isolated, candidate, rejected, and offline-evaluation nodes.

## FailureCase Design

Each rejected hypothesis creates a run-scoped FailureCase containing `run_id`, `hypothesis_id`, gate stage, concrete reason, rejected IDs, and related node IDs. IDs include a stable digest over run/hypothesis/reason, so repeated runs do not overwrite one another.

## Negative Tests

The added tests verify that:

- missing wrapper source and `valid_evidence=false` cannot create SUPPORTS;
- missing ToolCall, missing ToolOutput, and ToolOutput-to-ToolCall mismatch are rejected;
- agent-reported observations are ignored;
- unknown or cross-commit PatchHunks and mismatched observation commit scope reject anchors;
- missing anchor, vulnerable predicate, or fix predicate rejects a hypothesis;
- unused semantic nodes do not become raw or enter production packets;
- incomplete multi-commit fix sets reject, while complete and alternative fix sets behave independently;
- 15-commit fix sets retain all commits;
- FailureCases remain distinct across runs;
- wrapper collector IDs remain unique and failed commit commands become invalid evidence;
- prior exact SUPPORTS, run-scoped semantic IDs, fixture workflow, and JSON parsing tests remain passing.

## Verification

```text
python -m pytest -q
68 passed in 8.13s

python -m compileall src tests scripts
exit code 0
```

## Legacy 3-CVE Replay

No OpenCode request was made. Existing artifacts were replayed through `created_from=legacy_replay_adapter`, which rebuilt provenance and scope from original wrapper ToolCalls, outputs, packet data, and dataset fix-set metadata.

| CVE | Classification | Status | Trusted observations | Rejected legacy observations |
| --- | --- | --- | ---: | ---: |
| CVE-2020-24020 | legacy_reconstructed | ingested_raw | 2 | 1 duplicate-ID group |
| CVE-2022-3109 | legacy_reconstructed | ingested_raw | 3 | 0 |
| CVE-2023-47342 | legacy_reconstructed | ingested_raw | 6 | 0 |

Classification totals: native new format 0, legacy reconstructed 3, unverifiable 0. These results do not count as native-format pilot evidence. Details are stored in `legacy_replay_results.json`.

## Known Limitations

- Existing packets do not carry graph edges; function consistency is therefore deterministic only when an explicit hunk/function identifier is available.
- The old CVE-2020-24020 file-history commands used truncated duplicate IDs. The adapter preserved them as rejected debug observations instead of repairing or trusting them.
- Semantic correctness of root-cause text still requires human review or a later verifier; `ingested_raw` means structural and evidence-gate acceptance, not validation.

## Readiness

The Evidence Gate implementation is ready for a fresh native-format Root Cause smoke and then a 10-CVE semantic evaluation. The previous 3-CVE result cannot substitute for that native smoke because all three traces required legacy reconstruction.
