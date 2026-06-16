# Root Cause Agent 10-CVE First-Round Report

## Experimental boundary

- Agent backend: OpenCode 1.2.26
- Model: `opencode/north-mini-code-free`
- Cases: `BaseDataSet_10.json`
- CVE text: `BaseData_nvd.json`
- Repository snapshots: local repositories under `VulnVersion/repo`
- Per-case timeout: 120 seconds
- Runtime task: root-cause extraction only; no target judgement or affected-version planning
- Git access: strict `vg_git_*` read-only allowlist
- Lifecycle: accepted agent semantics remain `raw`, not `validated`

The local VulnVersion files were used only as evaluation inputs. No old Step2/VET implementation was imported or executed.

## Current construction

```text
CVE description + CWE + repo + primary fix commit
  -> CVE/repo-scoped graph traversal
  -> bounded packet (40 nodes / 24,000 chars / 3 hops)
  -> Root Cause system prompt + RootCauseAgentOutput JSON Schema
  -> fresh OpenCode session
  -> strict read-only vg_git_* tool loop
  -> JSON parsing + Pydantic reference validation
  -> at most one schema-only repair turn
  -> append-only graph events + materialized snapshots
```

The semantic output is decomposed into:

```text
CodeAnchor
VulnerablePredicate
FixPredicate
GuardCondition
NegativeApplicabilityCondition
RootCauseHypothesis
RiskFlag
```

The graph records the agent run, command invocations and outputs, semantic nodes, and typed relations such as `supports`, `anchored_by`, `requires`, `blocked_by`, `constrained_by`, and `excluded_by`.

## Results

| CVE | Repo | Runtime status | Commands | Anchors | Vulnerable predicates | Manual patch review |
|---|---|---:|---:|---:|---:|---|
| CVE-2021-29338 | openjpeg | Malformed JSON | - | - | - | Not evaluable |
| CVE-2020-27560 | ImageMagick | Success | 5 | 4 | 1 | Core root cause correct |
| CVE-2023-21106 | linux | Success | 12 | 7 | 2 | Core root cause correct |
| CVE-2020-22029 | FFmpeg | OpenCode empty-message failure | - | - | - | Not evaluable |
| CVE-2023-6237 | openssl | Malformed JSON | - | - | - | Not evaluable |
| CVE-2020-8286 | curl | Success | 5 | 9 | 2 | Core root cause correct |
| CVE-2021-33193 | httpd | Malformed JSON | - | - | - | Not evaluable |
| CVE-2021-22191 | wireshark | Success | 7 | 8 | 4 | Broadly patch-aligned |
| CVE-2022-3165 | qemu | Malformed JSON | - | - | - | Not evaluable |
| CVE-2021-20313 | ImageMagick | OpenCode empty-message failure | - | - | - | Not evaluable |

Aggregate metrics:

```text
Schema/runtime success:          4 / 10
Evidence-bearing success:        4 / 10
Malformed JSON:                  4 / 10
OpenCode empty-message failure:  2 / 10
Total successful Git commands:   29
Successful cases needing repair: 2 / 4
Average successful runtime:      64.09 s
Total batch runtime:              979.70 s
```

## Semantic review

### CVE-2020-27560 / ImageMagick

The agent correctly identified division by zero in `OptimizeLayerFrames` when `ticks_per_second` is zero and correctly linked the fix to `PerceptibleReciprocal`. The `multi_commit_fix` risk flag is unsupported by the supplied single-commit patch and should not be promoted.

### CVE-2023-21106 / Linux

The agent correctly identified the concurrent replacement of `ctx->comm/cmdline`, the unsynchronized `kfree(*paramp)`, and the mutex-based fix. The `missing_parent` risk flag is inaccurate: the supplied fix commit and its parent are locally resolvable.

### CVE-2020-8286 / curl

The agent correctly identified that OCSP responses were checked without matching the response to the peer certificate ID. The extracted fix predicate matches the use of `OCSP_cert_to_id` and `OCSP_resp_find_status`.

### CVE-2021-22191 / Wireshark

The agent correctly found the URL/file-opening surfaces and the patch's MIME allowlist and clipboard behavior. The root-cause statement is broader than a single code predicate, and the speculative statement that clipboard copying may remain exploitable is not supported by this patch.

## First-round conclusions

1. The graph schema can represent useful root-cause evidence. All four accepted cases produced patch-aligned anchors, vulnerable predicates, fix predicates, and a hypothesis.
2. End-to-end reliability is currently insufficient: only 40% of cases reached an ingestible result.
3. The dominant failure is not graph retrieval. It is the Agent/backend output protocol: malformed JSON and OpenCode empty assistant messages account for all six failures.
4. Referential validation is useful but incomplete. It checks that IDs exist, but it does not yet prove that command excerpts exactly match the real OpenCode tool outputs.
5. `RiskFlag` is substantially noisier than the core root-cause hypothesis. Risk claims need a separate evidence requirement or should be omitted in v1.
6. Multi-commit fixes are not properly represented by the current seed path. `CVE-2020-22029` has two known fix commits, while the current agent packet treats the first as primary and the second only as a hint.

## Next optimization order

Do not enlarge the graph first. The next iteration should address reliability in this order:

1. Capture the complete OpenCode tool trace directly instead of trusting agent-reported command excerpts.
2. Replace free-form final JSON generation with constrained/structured output or a deterministic JSON normalization stage.
3. Detect idle empty assistant messages immediately instead of waiting for the full timeout.
4. Require at least one successful Git observation and one evidence-backed predicate before accepting a hypothesis.
5. Gate or temporarily remove `RiskFlag` until each flag has explicit command evidence.
6. Represent all fix commits as first-class `FixCommit` nodes and require the agent to explain whether they are alternatives, backports, or a multi-commit fix.

The next experiment should rerun the same ten cases after these protocol changes. Changing the dataset at the same time would make the comparison weaker.
