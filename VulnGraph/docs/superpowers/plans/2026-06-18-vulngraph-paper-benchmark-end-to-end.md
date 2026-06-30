# VulnGraph Paper Benchmark End-to-End Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans`. Execute exactly one phase at a time and stop for review at every gate.

**Goal:** Build an end-to-end, evidence-constrained VulnGraph system that predicts the complete affected-version set for every CVE in the official 1,128-CVE benchmark and targets results above the paper's strongest reported baselines.

**Architecture:** Model vulnerability existence as an attacker-reachable predicate condition over the Git commit DAG. Use LLMs for evidence-bound root-cause and commit-event judgment, deterministic Git analysis for history reconstruction, branch-specific predicate-state inference for release classification, and graph-backed prior retrieval for chronology-safe cross-case adaptation.

**Tech Stack:** Python, Pydantic, Git CLI, OpenCode, `deepseek/deepseek-v4-pro`, pytest, JSON/CSV artifacts, and Neo4j after the JSON contracts stabilize. JSON remains the reproducible interchange format; Neo4j is required for the final graph-backed adaptation experiment, not for the first end-to-end baseline.

---

## Dataset Definition

- Official source artifact: `E:\AI\Agent\workflow\VulnVersion\DataSet\Dataset.json`.
- Canonical execution dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json`.
- `BaseDataOrder.json` is a deterministic reordered copy of the official artifact. It changes list order only and preserves every CVE, repository, CWE, fixing commit, and affected-version set.
- Both files contain 1,128 CVEs from 9 repositories and 59,240 affected-version labels.
- All formal VulnGraph runs, split generation, and evaluation use `BaseDataOrder.json`. `Dataset.json` is retained only for provenance and semantic-equivalence checks.
- `Dataset-1.json`, `BaseDataTest.json`, and other derived files are forbidden as formal experiment inputs unless a later plan explicitly assigns them a role.
- `affected_version` is ground truth. It may be read only by split generation and the audit/evaluation layer; it must never enter Root Cause, SZZ/history, Judge, conversion, prompt, model view, or blind artifacts.
- The paper reports 59,187 labels while its released artifact contains 59,240. Record this 53-label Linux discrepancy as a paper-artifact inconsistency; do not modify the official artifact to reproduce the table.
- Record SHA-256, record counts, repository counts, fixing-commit counts, affected-label counts, and semantic equivalence between the two official copies in `benchmark_manifest.json`.

## Baseline-Derived Foundation and Gaps

VulnGraph is built on the benchmark and empirical findings of *Vulnerability-Affected Versions Identification: How Far Have We Come?* The prior study's strengths are evaluation foundations that must be preserved; its observed failures define the technical gaps that VulnGraph must improve.

Foundation to preserve:

- Evaluate every CVE as a complete affected-version set, not only as a BIC prediction.
- Report vulnerability-level exact correctness and no-miss behavior together with pooled version-level TP/FP/FN and micro Precision/Recall/F1.
- Evaluate all input CVEs. Parse failures, contract failures, censored histories, and empty predictions must not disappear from the primary denominator.
- Decompose tracing into statement selection, history tracing, inducing/event selection, and affected-version inference, then attribute failures stage by stage.
- Measure robustness by code-change type, modification scope, and branch context rather than reporting only aggregate performance.
- Preserve the paper's Table III numbers as historical references and reproduce the same column semantics when adding VulnGraph.

Gaps to improve and connect to contributions:

- Noisy or semantically wrong statement selection motivates attacker-condition-guided root cause and anchor selection.
- One-step under-tracing, unrestricted over-tracing, inaccurate inducing-commit selection, add-only failure, and weak cross-branch patch reuse motivate evidence-constrained branch-specific vulnerability-state reconstruction.
- Exact or coarse signature matching without vulnerability-condition verification motivates boundary predicate verification.
- Static per-CVE behavior that cannot learn from prior reviewed cases motivates graph-backed continual adaptation.

The baseline study reports, on a random manual sample of 100 CVEs, 49 incorrect heuristic statement selections, 28 incorrect LLM4SZZ statement selections, 30 cases requiring multi-step tracing, 16 V-SZZ over-traces, 12 V-SZZ under-traces, 12 FP and 29 FN commit judgments from LLM4SZZ, and 13 missed cross-branch patch cases. These are historical diagnostic references, not VulnGraph results.

The paper does not identify the sampled 100 CVEs. The locally available released analysis code under `E:\AI\Agent\workflow\Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\HowFarAreWeCode` contains `rq1.py`, `rq3.py`, and `rq4.py`, but no `rq2.py`, sample list, random seed, or RQ2 sample manifest. Therefore VulnGraph must not claim to reuse the authors' unknown 100 cases. It creates and publishes its own deterministic 100-CVE validation/audit manifest.

## Research Objective and Novelty Invariants

The target is not a better standalone BIC selector. The target is complete affected-version identification:

```text
CVE + fixing commits + repository history
-> structured vulnerability condition
-> vulnerability-relevant commit events
-> predicate state over Git DAG branches
-> verified affected release tags
```

The paper makes three headline claims. Existing SZZ, agentic SZZ, temporal-history, semantic-verification, and affected-version methods overlap with individual implementation techniques, so those techniques must not be presented as standalone novelty.

1. **Attacker-condition-guided affected-version reasoning:** represent attacker-controlled input, trigger, exploit preconditions, vulnerable state transition, sink, and impact path as evidence-bound predicates, then use those predicates to guide root-cause anchors, history events, and release-state decisions. The contribution is not ATT&CK labeling or a security knowledge graph by itself; it is using attack feasibility conditions to improve affected-version identification.
2. **Graph-backed continual adaptation for affected-version identification:** persist evidence, decisions, failures, and reviewed outcomes from earlier CVEs and retrieve priors by repository, CWE, root-cause pattern, patch pattern, and attack pattern. The contribution is the chronology-safe learning and decision adaptation mechanism, not merely storing artifacts in Neo4j.
3. **Evidence-constrained branch-specific vulnerability-state reconstruction:** reconstruct when the full attacker-reachable vulnerability condition becomes active or inactive on each branch, including multiple prerequisites, backports, equivalent fixes, and reintroduction, and directly emit the affected release set. This is an improvement over a one-BIC abstraction, but it must be compared against prior affected-version methods; the claim must not say that VulnGraph is the first system to output affected versions.

Wrapper-owned candidate IDs, strict contracts, adaptive `blame/log` tracing, commit-event labels, Git-DAG propagation, and boundary semantic verification are supporting mechanisms for Claim 3. They improve factuality, recall, and branch-state reconstruction, but are not independent headline novelties without evidence of a previously unaddressed technical distinction.

Each claim requires an ablation. A feature without measurable contribution to Exact Accuracy, NMR, micro F1, robustness, or failure reduction is not a paper contribution and must not be presented as novelty.

## Frozen Decisions

- Primary objective: vulnerability-level Exact Accuracy. NMR and paper-compatible version-level micro F1 are mandatory non-regression metrics.
- Existing `BaseDataSet_30.json` cases are the development set. `VulnGraphValidationSet_100.json` is the fixed 100-CVE validation and RQ2-audit set, generated with recorded-seed stratification over repository, code-change type, modification scope, and branch context, with explicit coverage of rare add-only, del-only, multi-file, merge-fix, multi-fix, and multi-branch cases. The remaining CVEs are an unassigned benchmark pool at this stage, not frozen test data.
- Store the exact 100 CVE IDs, selection strata, seed, canonical dataset hash, selected dataset hash, and generator version in `VulnGraph/data/benchmark/rq2_validation_sample_manifest.json`. Call this the VulnGraph validation sample, not the paper's original random sample.
- DeepSeek may be used in every semantic stage. API cost, token cost, wall-clock time, and target-machine resources do not constrain the method-design phase.
- Still record model calls, sessions, prompt bytes, retries, Git commands, and duration for reproducibility and the paper's efficiency discussion.
- Do not truncate evidence or candidate history solely to save cost. Operational timeouts must be configurable and retryable and must produce explicit censored/unknown states rather than silently dropping evidence.
- Different CVEs and different candidate judgments use independent OpenCode sessions. Conflict adjudication uses a fresh session.
- Use the paper's reported baseline numbers as historical references. Because the released artifact differs from the paper table, do not claim exact same-snapshot baseline reproduction.
- Minimal structured attacker perspective is part of the core method. The non-adaptive end-to-end pipeline is stabilized first; graph-backed cross-case adaptation is then implemented and frozen before any final held-out benchmark run. Full migration of every raw artifact to Neo4j may remain deferred.

## Canonical Dataflow

Existing `*_probe.py` workflows remain frozen diagnostic artifacts. Do not extend them into additional production stages. Add one canonical pipeline:

```text
Benchmark/CVE metadata
-> Root Cause V3 + Attacker Perspective
-> Adaptive History Search
-> Commit Event Judge V1
-> Git-DAG Predicate State Engine
-> Boundary Predicate Verification
-> Graph-Backed Prior Retrieval and Adaptation
-> AffectedVersionPredictionV1
-> Paper-Compatible Evaluator
```

Public contracts:

- `RootCauseOutputV3`: hypotheses, vulnerable/fix predicates, anchors, attack-path components, evidence refs, and an `all_of/any_of/not` vulnerability-condition expression over predicate IDs.
- `HistoryEvidencePacketV1`: candidate SHA, all parents, origin path/line, before/after code, commit delta, history method, fix family, branch relation, and uncertainty.
- `CommitEventJudgmentV1`: `INTRODUCES_COMPONENT`, `REMOVES_COMPONENT`, `REINTRODUCES_COMPONENT`, `REFACTOR_ONLY`, or `UNKNOWN`, bound to predicate IDs and evidence refs.
- `AffectedVersionPredictionV1` public output contains only `cve_id`, `affected_versions`, `evidence`, and `uncertainty`. Every release tag omitted from `affected_versions` is evaluated as not affected. Internal per-tag states, event lineage, and unresolved diagnostics remain audit artifacts and must not change this public closed-world output contract.

Public output example:

```json
{
  "cve_id": "CVE-YYYY-NNNN",
  "affected_versions": ["tag-1", "tag-2"],
  "evidence": [],
  "uncertainty": []
}
```

## Paper Evaluation Questions and Required Outputs

- **RQ1 Overall Effectiveness:** How accurately does VulnGraph identify complete affected-version sets compared with the tools in the baseline paper? Output a Table III-compatible table.
- **RQ2 Stage Failure Analysis:** Where do VulnGraph errors arise across attacker/root-cause modeling, anchor selection, history reconstruction, commit-event judgment, DAG state propagation, and boundary verification? Manually audit the frozen 100-CVE validation sample.
- **RQ3 Patch-Type Sensitivity:** How robust is VulnGraph under Add-only/Del-only/Mixed changes, single-function/multi-function/multi-file scope, and single-branch/multi-branch development?
- **RQ4 Component Contribution:** How much does each supporting mechanism and each of the three headline contributions improve Exact Accuracy, NMR, micro F1, stage recall, and robustness?
- **RQ5 Continual Adaptation:** Does chronology-safe graph-backed adaptation improve later CVEs, and under which repository/CWE/root-cause/patch/attack-pattern similarities does it help or cause negative transfer?

Required Table III-compatible columns:

```text
Type | Tool | Vuln TP | Accuracy | NM | NMR |
Version FP | Version FN | Version TP | Precision | Recall | F1
```

The VulnGraph row uses all 1,128 CVEs and the paper-compatible evaluation universe. Failed or missing final outputs are evaluated as empty `affected_versions`, not removed. Accepted-only and macro metrics are diagnostics and must not replace the primary all-case row.

Canonical CLI:

```powershell
python scripts\run_vulngraph_affected_versions.py `
  --dataset E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json `
  --split <dev|validation|test|all> `
  --repo-root E:\AI\Agent\workflow\VulnVersion\repo `
  --provider-id deepseek --model-id deepseek-v4-pro `
  --out-dir runs\batches\<run-name>
```

## Phase 0: Benchmark Alignment and Full Preflight

- Implement the paper-compatible evaluator: vulnerability-level exact TP and Accuracy, No-Miss count and NMR, pooled version-level TP/FP/FN, and micro Precision/Recall/F1. Keep existing macro metrics under a separate `diagnostic_macro_metrics` namespace.
- Port the paper artifact's repository-specific tag normalization and non-release filtering. Generic release-tag filtering remains diagnostic only.
- Generate the fixed `30/100` development-validation split and `rq2_validation_sample_manifest.json`; prove zero overlap, deterministic regeneration, stratum coverage, and no GT use beyond split generation. Do not freeze the remaining benchmark pool until a later reviewed final-test protocol is written.
- Run preflight across all 1,128 CVEs: repository presence, shallow status, fixing SHA existence, all parents, merge shape, changed paths, tag availability, fix-family cardinality, and missing/unmapped GT tags.
- Produce dataset and repository statistics suitable for the paper: patch type, scope, multi-fix, merge-fix, add-only, branch model, missing history, tag mapping, CWE distribution, and affected-label distribution.
- Fail closed before model calls if the dataset hash, repo mapping, or split manifest differs from the frozen manifest.

**Gate:** evaluator fixture tests pass; official dataset semantics are frozen; every CVE has an explicit runnable/censored reason; no GT field appears in blind artifacts.

## RQ2 Manual Stage-Failure Measurement Protocol

- Audit all 100 cases in the frozen validation sample after blind predictions are complete. Two reviewers label independently; disagreements receive third-reviewer adjudication. Report initial disagreement, Cohen's Kappa, adjudicated labels, and person-hours.
- Use a fixed per-CVE form with stage verdicts `correct`, `incorrect`, `incomplete`, `not_reached`, and `unknown`, each bound to artifact evidence.
- **S1 Attacker/root cause:** attack-condition support, vulnerable/fix predicate correctness, irrelevant hunk inclusion, missing component, and wrong vulnerable statement.
- **S2 History reconstruction:** direct-blame sufficiency, multi-step requirement, add-only localization, rename/move/copy, merge-parent handling, over-tracing, under-tracing, true-event Recall@k, and censored history.
- **S3 Commit-event judgment:** wrong event type, wrong boundary, unsupported semantic claim, top-event correctness, MRR, abstention, and repeat consistency.
- **S4 DAG/version inference:** missed branch, wrong ancestry, missed equivalent fix/backport, reintroduction, merge conflict, and incorrect predicate-state propagation.
- **S5 Boundary verification:** vulnerable-condition FP/FN, relocation failure, incorrect code-state equivalence class, and unresolved conflict.
- Report both unconditional all-case failure rates and conditional rates among cases reaching each stage. Do not infer an upstream failure solely from a wrong final version set.
- Compare VulnGraph's diagnostic counts with the baseline paper's published 100-case counts only as contextual reference because the sampled CVEs are not known to be identical.

## Phase 1: Root Cause V3

- Build a traceable CVE-description cache outside the agent. Preserve raw source, URL, retrieval time, normalized description, and failure reason.
- Extend the existing Root Cause contract with evidence-bound attack-path components and vulnerability-condition expressions.
- Preserve wrapper-owned IDs and existing anchor/predicate/fix-family gates. Do not add CVE-specific rules.
- Run the 30-CVE development set and independently review semantic root cause, predicate completeness, attack-path support, and anchor quality.

**Gate:** 30/30 parse and contract acceptance after valid retries; zero invented IDs; no semantic regression from the frozen baseline; unsupported attack claims remain unavailable/unknown instead of fabricated.

## Phase 2: Adaptive History Search

- For every accepted anchor, run normal, `-w`, `-M`, and `-C` blame and preserve origin path, origin line, revision, parent, and porcelain trace.
- Trigger recursive porcelain blame, `git log -L`, path-scoped `git log -S/-G`, rename/copy tracing, and per-parent merge diffs when variants disagree, paths do not match, commits are merges/boundaries/fix-series, or the event remains semantically uncertain.
- For add-only fixes, derive the protected operation/data source from the added guard and locate the corresponding fix-parent code before history tracing.
- Materialize candidate-parent and candidate-current code, exact diff, function context, ancestry, patch-id, fix-family relation, and branch relation.

**Gate:** every development CVE has at least one candidate or an evidence-backed censored reason; every candidate has verifiable before/after evidence; manually labeled valid-event Recall@k is at least 95%.

## Phase 3: Commit Event Judge V1

- Judge each candidate in an independent session using complete Root Cause, attack-path, before/after, history, and fix evidence.
- Conflicting candidates receive two independent judgments and a fresh-session arbiter on disagreement.
- Parse/schema repair may use a compact repair prompt. Any semantic contract failure must retry with the complete original evidence plus contract errors; compact semantic repair is forbidden.
- Deterministic code performs hard factual exclusion. The Judge classifies semantic events and uncertainty; it does not output affected versions or an unconstrained BIC.
- Preserve initial and final parse/contract results, repair taxonomy, and accepted-only metrics.

**Gate:** rejected outputs never enter rankings or conversion; repeat top-event consistency reaches at least 90%; candidate-level Top-1, Recall@k, MRR, and abstention are manually evaluated on development data.

## Phase 4: Git-DAG Predicate State Engine

- Build reusable per-repository indexes for peeled tag commits, parent edges, merge bases, event/fix reachability, patch equivalence, and branch-local fix families. Git remains the source of truth; caches are derived artifacts.
- Propagate each predicate's state through the DAG. For a tag and predicate, use the maximal reachable events under ancestry; consistent maximal events determine state, while conflicting incomparable events produce `INCONCLUSIVE` pending verification.
- A branch-local fix deactivates only predicates on descendants that contain that fix or a validated equivalent/backport event.
- A tag is `AFFECTED` only when its vulnerability-condition expression evaluates true and no applicable fix predicate is active.
- Support multiple prerequisites, multiple introductions, reintroduction, merge conflict, branch-local backport, and equivalent fixes.

**Gate:** deterministic DAG fixtures cover single branch, divergent branches, merge, backport, equivalent fix, reintroduction, and conflicting maximal events; no version-name ordering is used as ancestry evidence.

## Phase 5: Boundary Predicate Verification

- Group release tags by root-cause-relevant code-state fingerprints. Tags with identical predicate-relevant code share a provisional state.
- Use DeepSeek to verify every distinct state class, interval boundary, branch change point, and unresolved/conflicting state with complete evidence.
- Verify vulnerable predicates, fix predicates, trigger, preconditions, sink, and required path components. Missing locations trigger bounded symbol/token relocation with explicit evidence.
- Propagate verified class verdicts to member tags. Internally retain per-tag state and uncertainty, then project only tags classified as affected into `AffectedVersionPredictionV1.affected_versions`; omitted tags are negative predictions under the evaluator's closed-world semantics.
- Release filtering defines the evaluation universe only; it must not alter history candidates or event judgment.

**Gate:** every official release tag receives a verdict or explicit `INCONCLUSIVE`; blind predictions contain no GT; boundary decisions cite source evidence.

## Phase 6: Graph-Backed Continual Adaptation

- Define a stable graph schema for CVE, repository, CWE, attack condition, root-cause pattern, patch pattern, anchor decision, commit event, release-state decision, failure mode, and reviewed outcome.
- Process training/development cases in chronological order. A case may retrieve only facts and reviewed outcomes available before its cutoff time; future cases, validation/test labels, and ground-truth affected-version sets are forbidden.
- Retrieve and calibrate priors by repository, CWE, root-cause pattern, patch pattern, and attack pattern. Priors may influence search ordering, anchor/event ranking, and abstention, but may not invent paths, lines, SHAs, predicates, or release labels.
- Measure cold-start versus adaptive performance, learning curves, negative transfer, retrieval coverage, and the contribution of each prior type. Keep a non-adaptive frozen pipeline as the paired control.
- Materialize the stable schema in Neo4j and retain a deterministic JSON export for reproducibility.

**Gate:** chronology and GT-leakage tests pass; every retrieved prior has provenance and cutoff time; adaptive gains survive ablation without increasing unsupported claims or negative transfer beyond the declared threshold.

## Phase 7: Validation and Final Benchmark Freezing

- Complete implementation and ablations on the 30-CVE development set.
- Run the fixed 100-CVE validation set. Permit at most two documented rounds of general method/prompt correction; prohibit CVE-specific rules.
- After validation, write a separate final-test freeze amendment that names the exact held-out CVEs, code/contracts/prompts, model configuration, tag universe, evaluator, and allowed rerun policy. The current plan does not freeze the remaining CVEs.
- Run the final held-out benchmark exactly once after that amendment is reviewed. Report the independent held-out result and the final full-dataset aggregate separately.
- Generate the final Table III-compatible comparison with all historical tool rows plus `VulnGraph`, and separate RQ2/RQ3/RQ4/RQ5 artifacts. Do not place accepted-only numbers in the headline comparison.
- Treat the published best historical results as the competitive floor: Exact Accuracy above 55.0% and micro F1 above 84.8%; report NMR against the strongest directly comparable published value and do not mix incompatible snapshots.
- Strong paper target: Exact Accuracy at least 65-70%, micro F1 at least 88-90%, and NMR at least 75%.
- Stretch/ultimate target: Exact Accuracy above 80.0%, version-level micro F1 above 90.8%, and NMR at least 80.8%. These are research objectives, not assumptions or release gates; failure to reach them triggers stage-wise error attribution rather than test-specific rules.

## Required Ablations and Paper Evidence

- Root Cause V2 vs Root Cause V3 attacker-perspective conditions.
- Direct blame vs adaptive history reconstruction.
- Heuristic/earliest candidate vs Commit Event Judge V1.
- Single-BIC direct reachability vs Git-DAG predicate-state propagation.
- State propagation alone vs boundary predicate verification.
- Non-adaptive pipeline vs graph-backed continual adaptation; repository/CWE/root-cause/patch/attack-pattern priors separately ablated under chronological evaluation.
- Strong candidates vs fallback candidates; single-branch vs multi-branch; add-only/del-only/mixed; single-function/multi-function/multi-file.
- Report Exact Accuracy, NMR, micro P/R/F1, diagnostic macro metrics, unresolved rate, candidate recall, model stability, model calls, tokens, runtime, and failure taxonomy.

## RQ3 Patch-Type Sensitivity Protocol

- Reproduce the baseline paper's three primary dimensions exactly:
  - code-change type: `Add-only`, `Del-only`, `Mixed`;
  - modification scope: `single-function`, `multi-function-single-file`, `multi-file`;
  - branch context: `single-branch`, `multi-branch`.
- Freeze deterministic classifiers for each dimension before validation/test evaluation. Ambiguous cases receive explicit `unknown` values and are reported rather than silently reassigned.
- For every stratum report case count, affected-label count, Exact Accuracy, NM/NMR, pooled TP/FP/FN, micro Precision/Recall/F1, unresolved rate, and bootstrap confidence intervals.
- Produce figures directly comparable to the baseline paper's Accuracy/F1 plots and tables containing the full metric set. Show VulnGraph beside the strongest historical tool per stratum where the published value is recoverable.
- Secondary VulnGraph-only slices may analyze attack-condition completeness, strong/fallback candidates, single/multiple prerequisite events, fix-family cardinality, merge-fix, and graph-prior availability. Keep these separate from the primary p01-compatible RQ3 results.
- Interpret gains through the three contributions: attacker conditions should primarily improve noisy/add-only anchor selection; branch-specific state reconstruction should improve multi-step/multi-file/multi-branch cases; continual adaptation should improve later similar cases without harming rare or dissimilar cases.

## Test and Review Protocol

- Unit tests cover dataset equivalence, paper evaluator, tag normalization, GT isolation, whitespace-sensitive blame, rename/copy, merge parents, add-only, multi-fix, event contracts, DAG state propagation, and fingerprint equivalence.
- Fixed regression cases include `CVE-2020-8231` for multi-component store/use boundaries, `CVE-2020-27814` for merge fixes, `CVE-2020-14212` for multi-fix coverage, and Linux history cases.
- Every phase handoff must include changed files, exact commands, artifact manifest, all-case/accepted-only metrics, failure taxonomy, model/session manifest, GT forbidden scan, pytest, and compileall.
- The planning/review agent reviews every phase before the main agent proceeds. A failed gate blocks the next phase and all larger model runs.
- Existing Root Cause/SZZ/Judge/probe outputs are frozen and must not be overwritten. New contracts and artifacts use new version identifiers.

## Deferred Work

- Migration of bulky raw prompts, complete Git traces, and every intermediate audit artifact into Neo4j. The stable semantic graph and graph-backed adaptation required by Phase 6 are not deferred.
- Online learning from unreviewed predictions. The paper experiment permits only chronology-safe adaptation from provenance-tracked evidence and reviewed outcomes.

