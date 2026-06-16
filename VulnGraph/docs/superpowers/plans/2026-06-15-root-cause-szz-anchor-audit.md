# Root Cause to SZZ Anchor Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a 10-CVE audit pipeline that converts VulnGraph Root Cause outputs into wrapper-validated pre-fix line anchors, runs change-type-aware Git blame, and produces evidence for later BIC-Judge design without claiming BIC correctness.

**Architecture:** Keep Root Cause extraction unchanged in this phase. Add a separate `RootCauseSzzHandoffV1` boundary: deterministic code constructs wrapper-owned pre-fix line candidates from each fixing commit's parent, an OpenCode anchor agent selects only candidate IDs, a pure contract gate validates those selections, and a read-only blame runner records candidate commits. Direct old-side blame and add-only semantic anchoring remain distinguishable in every artifact.

**Tech Stack:** Python 3.12, Pydantic v2, subprocess Git CLI, existing OpenCode backend wrapper, pytest, JSON/CSV/Markdown artifacts.

---

## Scope And Non-Goals

This phase must not implement or claim:

- BIC correctness or a BIC boundary verdict.
- affected-version conversion.
- branch-equivalent BIC/FIC clustering.
- changes to the frozen semantic baseline artifacts.
- CVE-specific matching rules.
- direct blame of newly added lines.

The run is an anchor/candidate audit. Its terminal lifecycle is `raw_candidate`, never `validated_bic`.

## File Structure

- Create `src/vulngraph/agent_io/szz_handoff_schema.py`: Pydantic generation and resolved-artifact schemas.
- Create `src/vulngraph/agent_io/szz_handoff_contract.py`: pure candidate-selection validation.
- Create `src/vulngraph/services/pre_fix_candidates.py`: deterministic parent-side candidate inventory.
- Create `src/vulngraph/services/blame_runner.py`: read-only line blame and trace normalization.
- Create `src/vulngraph/prompts/szz_anchor_v1.md`: candidate-selection prompt; IDs must be copied, never invented.
- Create `src/vulngraph/workflows/szz_anchor_audit.py`: orchestration and report aggregation.
- Modify `src/vulngraph/workflows/__init__.py`: export the new workflow API.
- Create `scripts/run_root_cause_szz_anchor_audit.py`: CLI for the frozen 10-CVE experiment.
- Create `tests/test_szz_handoff_schema.py`: schema and parsing tests.
- Create `tests/test_pre_fix_candidates.py`: add/delete/modify/rename and multi-fix inventory tests.
- Create `tests/test_szz_handoff_contract.py`: invented-ID, scope, source-role, and add-only gate tests.
- Create `tests/test_blame_runner.py`: blame parser and command-construction tests.
- Create `tests/test_szz_anchor_audit.py`: end-to-end fixture artifact tests.

The workspace is not a Git worktree. Do not initialize Git and do not create commits; use test-green checkpoints after each task.

### Task 1: Define The SZZ Handoff Schemas

**Files:**
- Create: `src/vulngraph/agent_io/szz_handoff_schema.py`
- Test: `tests/test_szz_handoff_schema.py`

- [ ] **Step 1: Write failing schema tests**

Cover these exact invariants:

```python
def test_anchor_selection_requires_wrapper_candidate_id():
    payload = valid_selection_payload()
    payload["selected_anchors"][0]["candidate_id"] = ""
    assert not parse_szz_anchor_selection(json.dumps(payload)).ok


def test_resolved_anchor_preserves_parent_side_coordinates():
    anchor = ResolvedPreFixAnchorV1(
        anchor_id="pre-fix-anchor:1",
        candidate_id="pre-fix-line:1",
        cve_id="CVE-TEST-1",
        fix_set_id="fix-set:1",
        fix_commit_id="fix-commit:1",
        fix_commit_sha="b" * 40,
        parent_sha="a" * 40,
        patch_hunk_id="patch-hunk:1",
        path_before="src/a.c",
        path_after="src/a.c",
        old_line_start=17,
        old_line_end=17,
        line_text="dangerous_use(ptr);",
        line_text_sha256="hash",
        role="dangerous_use",
        selection_mode="direct_deleted_line",
        root_cause_hypothesis_ids=["hypothesis:1"],
        predicate_ids=["predicate:1"],
        git_observation_refs=["git-observation:1"],
        rationale="This old-side use violates the stated invariant.",
        confidence=0.9,
        lifecycle="raw_candidate",
    )
    assert anchor.parent_sha == "a" * 40
    assert anchor.old_line_start == 17
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python -m pytest -q tests/test_szz_handoff_schema.py`

Expected: collection failure because `szz_handoff_schema` does not exist.

- [ ] **Step 3: Implement exact schema families**

Define:

```python
AnchorRole = Literal[
    "dangerous_use",
    "missing_guard_target",
    "state_declaration",
    "control_predecessor",
    "data_source",
    "propagation",
    "sink",
    "cleanup_target",
    "callback_registration",
    "recursion_entry",
]

SelectionMode = Literal[
    "direct_deleted_line",
    "modified_old_side",
    "add_only_semantic_target",
    "context_fallback",
]

CandidateSource = Literal[
    "deleted_line",
    "hunk_context",
    "pre_fix_function_body",
]
```

Add these models:

- `PreFixLineCandidateV1`: wrapper-owned candidate ID, CVE/fix/hunk scope, old/new paths, parent SHA, exact old-side line/range/text/hash, function identity, candidate source, generated/test/doc/comment flags, and Git observation refs.
- `SelectedPreFixAnchorV1`: agent-owned selection using only candidate IDs plus role, root-cause/predicate IDs, rationale, confidence.
- `RootCauseSzzHandoffV1`: agent run metadata, failure mode, trigger, violated invariant, vulnerable state, propagation list, sink, fix mechanism, selected anchors, excluded hunk IDs, uncertainty reasons.
- `ResolvedPreFixAnchorV1`: joined wrapper candidate plus agent semantics; lifecycle fixed to `raw_candidate`.
- `SzzAnchorSelectionParseResult` and `parse_szz_anchor_selection()` using the same fenced-JSON behavior as Root Cause parsing.

Do not include `predicted_bic`, `affected_versions`, or free-form commit SHAs in the agent generation schema.

- [ ] **Step 4: Run schema tests**

Run: `python -m pytest -q tests/test_szz_handoff_schema.py`

Expected: all tests pass.

### Task 2: Build Wrapper-Owned Pre-Fix Candidate Inventory

**Files:**
- Create: `src/vulngraph/services/pre_fix_candidates.py`
- Test: `tests/test_pre_fix_candidates.py`

- [ ] **Step 1: Write failing pure-function tests**

Test these cases with synthetic packets and a fake source reader:

1. Delete-only hunk emits each nonblank deleted old line as `deleted_line`.
2. Modify hunk emits old-side deleted lines, never the newly added replacement line.
3. Add-only hunk emits nonblank old context and the complete pre-fix changed-function body as separate candidates.
4. New-file add-only hunk emits no parent-line candidate and records `new_file_without_parent_anchor`.
5. Rename uses `path_before` for blame and preserves `path_after` for patch linkage.
6. Changelog, generated, test, comment-only, and blank lines receive exclusion flags.
7. Equivalent multi-fix commits retain separate parent-side coordinates but share a computed stable patch family ID.

The inventory API must be:

```python
def build_pre_fix_candidate_inventory(
    *,
    packet: dict[str, Any],
    repo_path: Path,
    source_reader: PreFixSourceReader,
) -> PreFixCandidateInventoryV1:
    ...
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python -m pytest -q tests/test_pre_fix_candidates.py`

Expected: module import failure.

- [ ] **Step 3: Implement deterministic candidate construction**

For each `PatchHunk`:

1. Resolve the actual fix SHA and first parent through Git, not the model.
2. Preserve `old_path`, `new_path`, hunk index, old/new ranges, and change type.
3. Create stable candidate IDs from repo, fix SHA, old path, old line, and text hash.
4. For hunks with deleted lines, emit old deleted lines as primary candidates.
5. For add-only hunks, emit context candidates and pre-fix function-body candidates; mark all of them `add_only_semantic_target` eligible, not direct proof.
6. Compute `line_text_sha256` from exact parent content and reject coordinate/text disagreement.
7. Compute a stable patch family ID using `git patch-id --stable` semantics through a small Git helper.

Do not use `@@` function headers as authoritative function ownership. Reuse the existing source-range function resolver pattern.

- [ ] **Step 4: Run candidate tests**

Run: `python -m pytest -q tests/test_pre_fix_candidates.py`

Expected: all tests pass.

### Task 3: Add The Candidate-Only Anchor Agent Contract

**Files:**
- Create: `src/vulngraph/prompts/szz_anchor_v1.md`
- Create: `src/vulngraph/agent_io/szz_handoff_contract.py`
- Test: `tests/test_szz_handoff_contract.py`

- [ ] **Step 1: Write failing contract tests**

Required test cases:

- invented candidate ID is rejected;
- candidate from another fix commit/hunk is rejected;
- an added-line coordinate is rejected because no wrapper candidate owns it;
- direct deleted-line selection without shared root-cause predicate evidence is rejected;
- add-only selection from a random nearby comment is rejected by role/file flags;
- one hypothesis may select multiple complementary anchors;
- every declared fix family must have at least one accepted anchor or an explicit uncertainty reason;
- lint and resolver use the same pure validation result.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python -m pytest -q tests/test_szz_handoff_contract.py`

Expected: module import failure.

- [ ] **Step 3: Implement a pure validation result**

Define `SzzHandoffValidationResult` with:

```python
accepted_anchor_ids: list[str]
rejected_anchor_ids: list[str]
resolved_anchors: list[ResolvedPreFixAnchorV1]
errors: list[str]
taxonomy: dict[str, int]
invented_ids: list[str]
fix_family_coverage: dict[str, bool]
ok: bool
```

Taxonomy must include:

```text
unknown_candidate_id
candidate_scope_mismatch
added_line_not_blameable
parent_coordinate_mismatch
non_source_anchor
comment_or_blank_anchor
weak_root_cause_binding
add_only_context_only
fix_family_incomplete
duplicate_anchor_selection
```

Gate errors reject the selection. `add_only_context_only` is a warning if at least one stronger function-body semantic target exists; it is an error when every selected add-only anchor is only local context.

- [ ] **Step 4: Write the prompt**

The prompt must require the agent to:

- summarize `failure_mode`, `trigger`, `violated_invariant`, `vulnerable_state`, `propagation`, `sink`, and `fix_mechanism` from the accepted Root Cause graph;
- select only provided candidate IDs;
- prefer the smallest set that closes trigger/state/sink evidence;
- for add-only guards, select the pre-existing dangerous use or state being protected;
- never select the new guard itself as a blame target;
- distinguish `uncertain` from unsupported invention;
- return strict JSON only.

- [ ] **Step 5: Run contract tests**

Run: `python -m pytest -q tests/test_szz_handoff_contract.py`

Expected: all tests pass.

### Task 4: Implement Read-Only Blame Tracing

**Files:**
- Create: `src/vulngraph/services/blame_runner.py`
- Test: `tests/test_blame_runner.py`

- [ ] **Step 1: Write failing parser and command tests**

Verify:

- commands use the fix commit's resolved parent;
- commands use `path_before`;
- each line/range uses `git blame -w --line-porcelain -L start,end parent -- path`;
- porcelain output is normalized into line-level records;
- multiple lines mapping to one commit aggregate counts but preserve per-line provenance;
- blame failure returns a typed status, not an empty successful result;
- shallow repository detection produces `shallow_history`.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python -m pytest -q tests/test_blame_runner.py`

Expected: module import failure.

- [ ] **Step 3: Implement trace models and runner**

Each trace must record:

```text
anchor_id
candidate_id
fix_commit_sha
parent_sha
path_before
old_line
line_text_sha256
blamed_commit_sha
blamed_original_path
blamed_original_line
author_time
committer_time
boundary_marker
status
stderr
```

Aggregate candidates by commit, but do not rank one as the BIC. Preserve `anchor_ids`, roles, vote counts, and source modes for later Judge input.

- [ ] **Step 4: Run blame tests**

Run: `python -m pytest -q tests/test_blame_runner.py`

Expected: all tests pass.

### Task 5: Build The 10-CVE Audit Workflow

**Files:**
- Create: `src/vulngraph/workflows/szz_anchor_audit.py`
- Modify: `src/vulngraph/workflows/__init__.py`
- Create: `scripts/run_root_cause_szz_anchor_audit.py`
- Test: `tests/test_szz_anchor_audit.py`

- [ ] **Step 1: Write failing end-to-end fixture tests**

The fixture run must produce per CVE:

```text
pre_fix_candidate_inventory.json
szz_handoff_prompt.txt
raw_szz_handoff_response.txt
parsed_szz_handoff.json
szz_handoff_lint.json
resolved_pre_fix_anchors.json
blame_trace.json
candidate_commits.json
```

Batch outputs:

```text
summary.json
szz_anchor_audit.csv
failure_taxonomy.json
report.md
manual_anchor_review_template.csv
```

Assert lifecycle is `raw_candidate` and no output field is named `correct_bic` or `affected_versions`.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python -m pytest -q tests/test_szz_anchor_audit.py`

Expected: module import failure.

- [ ] **Step 3: Implement orchestration**

Inputs:

- optimized Root Cause run directory;
- dataset path;
- repository root;
- output directory;
- provider/model/timeout;
- explicit CVE list.

Fail closed when a Root Cause artifact is missing or structurally rejected. Never silently fall back to all patch lines.

Batch metrics must include:

```text
cases_total
handoff_parse_success
handoff_contract_acceptance
resolved_anchor_count
direct_old_side_anchor_count
add_only_semantic_anchor_count
context_only_anchor_count
blame_success_rate
unique_candidate_commits
median_candidates_per_case
fix_family_anchor_coverage
shallow_history_cases
```

- [ ] **Step 4: Run all new tests**

Run: `python -m pytest -q tests/test_szz_handoff_schema.py tests/test_pre_fix_candidates.py tests/test_szz_handoff_contract.py tests/test_blame_runner.py tests/test_szz_anchor_audit.py`

Expected: all tests pass.

### Task 6: Run The Frozen 10-CVE Audit

**Files:**
- Read: `runs/batches/root-cause-v2-optimized-contract-10/**`
- Create: `runs/batches/root-cause-v2-szz-anchor-audit-10/**`

- [ ] **Step 1: Verify preconditions**

Confirm:

- all 10 optimized Root Cause cases are structurally accepted;
- optimized semantic labels have been completed independently using the frozen rubric;
- all 12 fixing commits and parents exist;
- repository history is non-shallow, or the case is marked diagnostic-only;
- OpenCode health is recorded.

Do not use SZZ results to fill missing Root Cause semantic labels.

- [ ] **Step 2: Run exact audit command**

```powershell
python scripts\run_root_cause_szz_anchor_audit.py `
  --root-cause-run runs\batches\root-cause-v2-optimized-contract-10 `
  --dataset E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json `
  --repo-root E:\AI\Agent\workflow\VulnVersion\repo `
  --out-dir runs\batches\root-cause-v2-szz-anchor-audit-10 `
  --cves CVE-2020-14212 CVE-2020-19667 CVE-2020-8231 CVE-2020-11984 CVE-2022-0171 CVE-2022-0286 CVE-2020-15389 CVE-2020-1967 CVE-2020-11869 CVE-2020-13164 `
  --provider-id deepseek `
  --model-id deepseek-v4-pro `
  --timeout 300 `
  --reset
```

- [ ] **Step 3: Perform manual anchor review**

For every selected anchor label:

```text
root_cause_binding_correct
parent_line_exists
line_role_correct
minimal_anchor
blame_worthy
context_only_noise
fix_family_covered
notes
```

Allowed values: `0`, `1`, `N/A`, `UNKNOWN`.

- [ ] **Step 4: Compare four candidate generators**

Use the same 10 cases and report, without BIC-ground-truth claims:

1. all deleted old lines;
2. AgenticSZZ-style add-only local context;
3. existing MAS-SZZ vulnerable statements;
4. VulnGraph SZZ handoff anchors.

Compare anchor precision, blame success, candidates per case, context-noise rate, multi-anchor coverage, and downstream affected-version sensitivity using the already frozen common converter. Clearly mark the converter metric as downstream consistency, not BIC accuracy.

- [ ] **Step 5: Run regression verification**

Run:

```powershell
python -m pytest -q
python -m compileall src tests scripts
```

Expected: all tests pass; compileall exits 0.

## Acceptance Criteria

Phase 1 is complete only when:

1. All selected blame targets are wrapper-owned parent-side candidate IDs.
2. Added lines are never passed directly to `git blame` at the parent revision.
3. Direct, modified-old-side, add-only semantic, and context fallback strategies remain separately measurable.
4. Multi-fix/backport commits are not merged before parent-side blame; patch-family identity is preserved.
5. Every blame candidate has line-level provenance back to Root Cause hypothesis and predicate IDs.
6. The report explicitly states that BIC correctness is not measured because `BaseDataSet_30.json` lacks BIC labels.
7. No production Root Cause prompt/schema change is made until manual anchor review shows which handoff fields are stable.

## Decision After This Plan

Only after the 10-CVE anchor audit should the next plan choose between:

- promoting stable SZZ handoff fields into `RootCauseAgentOutputV2`; or
- keeping SZZ anchor selection as a separate agent boundary.

The next independent sub-project is the BIC Boundary Judge: evaluate candidate commit `C` and parent `C^1` against the same root-cause invariant, return `INTRODUCED`, `PRESENT_BEFORE`, `ABSENT`, `FIX_SERIES`, `INSUFFICIENT`, or `CENSORED`, then cluster branch-equivalent introductions. It must not be implemented as part of this plan.
