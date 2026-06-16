# Root Cause SZZ Anchor Audit Handoff

## Scope

This implementation stops at auditable `raw_candidate` commits. It does not identify a validated BIC, run a BIC boundary Judge, or infer affected versions.

## Changed Files

- `src/vulngraph/agent_io/szz_handoff_schema.py`: strict generation, candidate, resolved-anchor, and parse schemas.
- `src/vulngraph/agent_io/szz_handoff_contract.py`: shared pure candidate-selection validation used by lint and resolution.
- `src/vulngraph/services/pre_fix_candidates.py`: wrapper-owned parent-side candidate construction, patch-family identity, path-before handling, LF-only coordinate validation, and C-like function-range recovery.
- `src/vulngraph/services/blame_runner.py`: read-only parent validation, safe blame commands, porcelain normalization, and raw candidate aggregation.
- `src/vulngraph/prompts/szz_anchor_v1.md`: candidate-ID-only anchor selection contract.
- `src/vulngraph/workflows/szz_anchor_audit.py`: per-CVE and batch orchestration, artifacts, metrics, preconditions, and manual review templates.
- `src/vulngraph/agent_backends/szz_fixture.py`: deterministic engineering fixture, explicitly not a real agent result.
- `src/vulngraph/agent_backends/__init__.py`: exports the SZZ fixture backend.
- `src/vulngraph/workflows/__init__.py`: exports the SZZ audit workflow.
- `scripts/run_root_cause_szz_anchor_audit.py`: thin CLI wrapper with fail-closed formal-run preconditions.
- `tests/test_szz_handoff_schema.py`: strict schema and lifecycle tests.
- `tests/test_pre_fix_candidates.py`: delete, modify, add-only, new-file, rename, multi-fix, LF/form-feed, and function-range tests.
- `tests/test_szz_handoff_contract.py`: invented ID, scope, evidence binding, add-only, fix-family, multi-anchor, and parity tests.
- `tests/test_blame_runner.py`: command safety, parent-line validation, porcelain, failure, shallow, and LF/form-feed tests.
- `tests/test_szz_anchor_audit.py`: end-to-end artifacts and metric reporting tests.
- `tests/test_szz_audit_preconditions.py`: fixture-only selection and formal-run fail-closed tests.

## Architecture

```text
accepted Root Cause artifacts
  -> wrapper Git reader resolves fix parent and patch family
  -> deterministic parent-side candidate inventory
     - deleted_line
     - hunk_context
     - pre_fix_function_body
  -> candidate-ID-only SZZ anchor agent
  -> shared pure contract gate
  -> resolved raw pre-fix anchors
  -> parent/path/line/text/hash validation
  -> read-only git blame -w --line-porcelain
  -> raw candidate commits + line-level audit trace
```

Root Cause, pre-fix anchor, blame candidate, BIC boundary, and affected-version conversion remain separate lifecycle stages.

## Candidate Taxonomy

- Change type: `delete`, `modify`, `add_only`, `rename`.
- Candidate source: `deleted_line`, `hunk_context`, `pre_fix_function_body`.
- Selection mode: `direct_deleted_line`, `modified_old_side`, `add_only_semantic_target`, `context_fallback`.
- Terminal lifecycle: `raw_candidate` only.

Generated files, tests, documentation, changelogs, comments, and blank lines carry explicit flags and are rejected by the selection gate.

## Test Results

- Full pytest: `152 passed`.
- Compile: `python -m compileall src tests scripts`, exit code `0`.
- New focused tests: `27 passed` before full regression.
- Contract/resolver parity: covered by the shared `validate_szz_handoff()` result.
- Blame safety: parent SHA, `path_before`, old-side line/range, exact text, and SHA-256 are checked before blame.

## Real OpenCode Configuration

- URL: `http://127.0.0.1:4096`
- Health: healthy, OpenCode `1.2.26`
- Provider/model configured for formal runs: `deepseek/deepseek-v4-pro`
- Real anchor-agent invocation count: `0`

The formal 10-CVE run was intentionally blocked before model invocation because independent optimized Root Cause semantic labels are incomplete.

## Fixture 10-CVE Results

The fixture replaces only model selection. Candidate construction, parent validation, repository inspection, and blame use real local Git repositories.

- Statement localization coverage: `10/10`
- Handoff parse success: `10/10`
- Contract acceptance: `10/10`
- Resolved anchors: `11`
- Direct old-side anchors: `9`
- Add-only semantic anchors: `2`
- Context-only anchors: `0`
- Blame-worthy anchor rate: `1.0`
- Blame success rate: `9/11 = 0.8182`
- Fix-family coverage: `11/11`
- Multi-anchor cases: `1`
- Invented IDs: `0`
- Git queries: `567`
- Fix-series candidates excluded: `0`

Two Linux cases are `raw_candidate_censored` because the local repository is shallow:

- `CVE-2022-0171`
- `CVE-2022-0286`

`CVE-2020-19667` exposed and validated two generic fixes: LF-only Git line counting and C-like function range parsing that ignores braces in comments/literals.

## Per-CVE Failure Taxonomy

- `shallow_history`: `CVE-2022-0171`, `CVE-2022-0286`.
- `candidate_inventory_large`: `CVE-2020-13164` (`2423` candidates).
- No invented candidate IDs, parse failures, contract rejections, or direct added-line blame occurred in the final fixture run.

## Formal Run Status

The formal output directory is `runs/batches/root-cause-v2-szz-anchor-audit-10`.

- Optimized Root Cause structural acceptance: `10/10`.
- Fix commits and parents: `12/12`.
- Shallow repositories: 2 cases, diagnostic-only.
- OpenCode health: passed.
- Independent optimized semantic labels: incomplete.
- Blocking reason: `optimized_semantic_labels_incomplete`.

No formal before/after experiment or real DeepSeek anchor selection was claimed.

## Known Limitations

- Full pre-fix function bodies can create large candidate inventories; Wireshark currently produces a multi-megabyte selection prompt. A future generic retrieval/ranking layer should reduce model-visible candidates without deleting the full audit inventory.
- Patch-family exclusion currently covers exact fix commits and stable patch-id matches. Commit-message and fix-series ancestry classification remains conservative.
- Shallow Linux histories cannot support definitive blame and remain censored.
- The SZZ audit writes append-ready artifacts but does not yet materialize SZZ nodes into JSONL/Neo4j.
- Candidate recall is diagnostic only because the dataset has no BIC ground truth.
- The four-generator comparison from Task 6 is not run while formal preconditions are blocked.

## Judge Input Contract

The next BIC Boundary Judge should consume:

```json
{
  "cve_id": "...",
  "root_cause_hypothesis_ids": ["..."],
  "predicate_ids": ["..."],
  "anchor_id": "...",
  "candidate_id": "...",
  "role": "dangerous_use|missing_guard_target|...",
  "selection_mode": "direct_deleted_line|modified_old_side|add_only_semantic_target|context_fallback",
  "fix_commit_sha": "...",
  "parent_sha": "...",
  "patch_family_id": "...",
  "path_before": "...",
  "old_line": 0,
  "line_text_sha256": "...",
  "candidate_commit_sha": "...",
  "blame_trace_refs": ["..."],
  "history_status": "complete|shallow_history|failed",
  "lifecycle": "raw_candidate"
}
```

The Judge must compare candidate commit `C` and parent `C^1` against the same Root Cause invariant and return one of `INTRODUCED`, `PRESENT_BEFORE`, `ABSENT`, `FIX_SERIES`, `INSUFFICIENT`, or `CENSORED`. It must not perform affected-version conversion in the same stage.
