# VulnGraph Current-State Novelty Audit v1

Date: 2026-06-29

Scope: static audit only. I read current source, tests, design documents, paper draft, local batch artifacts, and the local reference corpus. I did not run new experiments, invoke models, modify source code, modify paper files, or change existing artifacts.

Verdict vocabulary:

- `IMPLEMENTED_AND_EVIDENCED`: implemented and supported by source plus frozen artifact/test evidence, but not necessarily a research contribution.
- `IMPLEMENTED_BUT_UNVALIDATED`: implemented enough to run or produce artifacts, but missing semantic/manual/baseline validation.
- `PLANNED_ONLY`: appears in design/paper plan, not implemented in the current executable path.
- `UNSUPPORTED_OR_OVERCLAIMED`: stronger than current evidence allows, or directly contradicted by source/artifacts.

## Executive Verdict

Current paper decision: `Reject` if submitted as a novelty paper today.

Potential if narrowed: `Borderline` only if the paper abandons A/C as headline claims and turns B into one rigorously validated contribution: evidence-constrained, branch-specific vulnerability-state reconstruction for affected-version identification.

Most important judgment: VulnGraph is currently an engineering-heavy root-cause/SZZ/Judge pipeline with a deterministic affected-version converter attached at the end. It is not yet an experimentally validated affected-version method.

Current implementation novelty:

- Strong infrastructure novelty: Git DAG index, evidence-gated packet contracts, forbidden-field hygiene, deterministic ledgers.
- Weak scientific novelty today: no manual true-introduction-event labels, no validated branch-state labels, no ablation against direct affected-version baselines, and high unknown rates in the converter route.
- Highest risk: confusing contract correctness with semantic correctness. Many artifacts prove that JSON is well-shaped and leakage is blocked; they do not prove that selected history events are true vulnerability-introducing events or that tag-level affected states are correct.

One-sentence survival path:

> Drop the self-evolution story, demote attacker-condition guidance to an ablation, and make the paper about whether branch-specific predicate/fix-state reconstruction can beat BIC-to-tag reachability and patch-signature baselines on affected-version labels.

## Evidence Scope

Read evidence categories:

- Source: `VulnGraph/src/vulngraph/**`
- Tests: selected semantic-state, tri-state, converter, history-event tests under `VulnGraph/tests/**`
- Artifacts: frozen batch summaries under `VulnGraph/runs/batches/**`
- Design docs: `VulnGraph/docs/superpowers/plans/**`, `VulnGraph/docs/architecture/git-dag-and-release-projection.md`
- Paper draft: `Paper/Paper/main.tex`, `Paper/Paper/Sections/{01_Introduction,04_Approach,06_Evaluation,08_Related_Work}.tex`
- Reference corpus: `Paper/reference/**`, especially affected-version, SZZ/Agent-SZZ, and security-KG papers.

Not performed:

- No new model calls.
- No benchmark reruns.
- No baseline reproduction.
- No manual CVE relabeling.
- No source or paper edits except this review document.

Evidence quality notes:

- The local reference corpus has many `[NEEDS TABLE REPAIR]`, `[NEEDS CITATION VERIFICATION]`, and `[EXECUTION NOT REQUESTED]` gates. Therefore this audit uses it to judge overlap/threat structure, not to quote exact leaderboard claims unless the local analysis itself already marks them as usable.
- Artifact metrics are from frozen local JSON files, not newly executed measurements.

## Current System Truth Map

| Component | Current state | What is actually evidenced | What is not evidenced | Claim status |
|---|---:|---|---|---|
| Git Graph Index | `IMPLEMENTED_AND_EVIDENCED` | 9 repos indexed; summary reports 2,044,845 commits, 2,180,982 parent edges, 4,287 raw tags, 2,400 release tags, 1346/1346 fix SHAs resolved, fully frozen. Architecture explicitly states this is a read-only fact layer. | It does not infer root causes, vulnerability state, BICs, or affected versions. | Infrastructure, not a standalone research contribution. |
| Root Cause V2 | `IMPLEMENTED_AND_EVIDENCED` for contract-gated extraction | Source imports `RootCauseAgentOutputV2` and renders `root_cause_v2` prompt. Prompt hard-bounds evidence to wrapper-owned `EVIDENCE_INVENTORY` and patch-bound anchors. | No implemented Root Cause V3 attacker-condition theorem. No evidence that extracted predicates are semantically correct across labels. | Engineering evidence gate; not attacker-condition novelty. |
| SZZ anchor audit + fallback | `IMPLEMENTED_AND_EVIDENCED` for raw candidates; `IMPLEMENTED_BUT_UNVALIDATED` for true BIC | Final fallback artifact covers 30 cases; 29 judge-input-ready cases; 37 strong raw candidate commits and 42 fallback raw candidate commits. | No true-BIC manual labels. Fallback candidates are heuristic. | Useful candidate generator, not final novelty. |
| History event reconstruction v1 | `IMPLEMENTED_AND_EVIDENCED` for evidence packets; `IMPLEMENTED_BUT_UNVALIDATED` for event reconstruction | 61 packets, 37 strong and 24 fallback candidate packets; `normal/-w/-M/-C` blame variants, `log -L/-S/-G`, `log --follow`, per-parent diffs. | `recursive_blame` is only a trigger flag with empty chain in source, not implemented recursive traversal. `before_code` and `after_code` are both diff excerpts, not materialized before/after states. | Do not claim true event-chain reconstruction. |
| History event judge readiness v1/v1.1 | `IMPLEMENTED_AND_EVIDENCED` as audit; evidence quality weak | v1 found 61 blind/audit packets but many P0 manual-review cases. v1.1 anchor relocation blocks false same-line accept but reports 71 old-context false accepts and 59/61 P0 cases. | No downstream semantic judge validation. | Strong negative evidence: earlier packets were not semantically reliable. |
| Judge v0 / boundary v1.x | `IMPLEMENTED_BUT_UNVALIDATED` | Judge v0 full stress: 40 rows over 30 unique CVEs, parse OK 40, contract OK 39, 84 ranked candidates, attacker context unavailable in all cases. Boundary v1.2 dev30: 30 cases, 102 candidates, contract OK 30, model invocation count 41. | No manual correctness labels. `judge_boundary_v1_2.py` sets `attacker_context` to unavailable because module is not implemented. | Raw ranking / boundary selection only. |
| Affected-version converter v1.2.1 | `IMPLEMENTED_BUT_UNVALIDATED` | Deterministic semantic-state reconstruction; 30 cases, 6 converted, 20 unknown_state, 4 unresolved_boundary; micro-F1 0.64149, exact accuracy 0.3667, NMR 0.6333. Fix-universe coverage 49/49. | High unknown rate; no proof boundary events are true; no baseline ablation; no manual semantic labels. | Preliminary diagnostic result only. |
| Affected-version converter v1.2.2 | `IMPLEMENTED_BUT_UNVALIDATED` | Function-scope verifier and fix-state policy; 2 converted, 21 converted_with_unknowns, 3 unknown_state, 4 unresolved_boundary; micro-F1 0.2939, exact accuracy 0.0333. | Unknowns dominate. Metric policy includes optimistic unknown activation/fix-absent treatment. | Conservative route weakens result claims. |
| Tri-state policy v1.2.2.1 | `IMPLEMENTED_AND_EVIDENCED` for gate logic; `IMPLEMENTED_BUT_UNVALIDATED` for science | 7,866 tag states; 838 confirmed affected, 2,744 confirmed unaffected, 4,284 unknown; unknown rate 54.46%; gate OK; no unknown in primary prediction; no weak fingerprint confirmed. | `independent_fix_predicate_evidence_count = 0`; fix absence mostly reachability proxy; no manual tag-state labels. | Good audit ledger; not yet a validated state model. |
| State audit v1.2.2 | `IMPLEMENTED_AND_EVIDENCED` as diagnostic | 21 audited cases, 20 unknown_state cases; `path_unavailable` 2364; function_missing 21; FP contribution 643, FN contribution 317. | Does not repair errors. | Evidence of remaining failure modes. |
| KG / self-evolution | `PLANNED_ONLY` / partial skeleton | JSONL append-only graph store; optional Neo4j materialization; candidate memories from failures are `learning_candidate` with 0.25 confidence and candidate lifecycle. | No retrieval-to-decision loop, no chronology split, no promotion experiment, no negative-transfer study. | Do not claim continual adaptation. |
| Current paper draft | `PLANNED_ONLY` for final method/results | Introduction says final algorithm details are structured placeholders; approach marks `NEEDS METHOD DETAIL`; evaluation states no final results and many `NEEDS EXPERIMENT`. | It does not yet describe current RootCause V2/SZZ/Judge/tri-state pipeline as a completed method. | Paper story is behind implementation and results. |

Key line-level evidence:

- `VulnGraph/src/vulngraph/workflows/root_cause.py:14,40-43`: current root-cause workflow uses V2 schema and `render_root_cause_prompt_v2`.
- `VulnGraph/src/vulngraph/prompts/root_cause_v2.md:5-13,23-32,43-53`: wrapper-owned evidence, patch-bound anchors, no affected-version/BIC judgment.
- `VulnGraph/src/vulngraph/workflows/judge_boundary_v1_2.py:85-95`: boundary input sets `attacker_context` unavailable with reason `module_not_implemented`, and forbids ground-truth/affected-version fields.
- `VulnGraph/src/vulngraph/workflows/history_event_reconstruction_v1.py:27-32,145-154,222-235`: blame variants and Git history evidence are collected, but `recursive_blame` has empty chain.
- `VulnGraph/docs/architecture/git-dag-and-release-projection.md:5-8`: Git Graph Index explicitly does not infer root causes, vulnerability state, BICs, or affected versions.
- `VulnGraph/src/vulngraph/workflows/semantic_state_v1_2_2.py:104-135,138-155`: semantic verifier is lexical/function-scope fingerprinting, not AST/CFG/dataflow equivalence.
- `VulnGraph/src/vulngraph/workflows/tri_state_policy_v1_2_2_1.py:16-47`: tag/context tri-state policy is deterministic, with unknown as a first-class outcome.
- `VulnGraph/src/vulngraph/evolution/rules.py:8-54`: failure-derived memories are candidate-only learning hints.
- `VulnGraph/src/vulngraph/services/graph_client.py:16-21`: JSONL is the audit source; Neo4j is optional materialization.
- `Paper/Paper/Sections/01_Introduction.tex:13-20`, `04_Approach.tex:4,43,49-51`, `06_Evaluation.tex:4,35-47`: paper draft explicitly marks method/results as planned.

## Baseline Threat Matrix

| Baseline | Local corpus evidence | Task overlap | Threat to VulnGraph claims | Required response |
|---|---|---:|---:|---|
| p01 How Far Are We? | Defines affected-version task, tracing/matching taxonomy, exact/NMR/version-F1 metrics, failure taxonomy. | Very high | Very high | Use as primary dataset/metric anchor; do not claim task novelty. |
| p09 V-SZZ | SZZ-based version-range inference, duplicate fixing/inducing changes, version tags from inducing/fixing commits. | Very high | High | Must beat or explain beyond BIC-to-version inference. |
| p20 CaVulner | Context-aware vulnerable-version identification; compares V-SZZ/VERJava/LLM4SZZ/CaVulner on Java version corpus. | High | High | Cannot claim "LLM + patch context for vulnerable versions" as new. |
| p32 TDSC affected versions | Version tree, patches, developer logs, repatch/unpatch handling, Linux kernel scale. | High | High | Branch/repatch handling must be explicitly compared. |
| p33 VERCATION | Static analysis + LLM for vulnerable OSS version identification; statement-level vulnerability-related code. | Very high | Very high | If VulnGraph uses LLM semantic matching, this is a direct modern threat. |
| p04 LLM4SZZ | LLM-enhanced SZZ, context-enhanced candidate assessment, deleted/non-deleted path split. | Medium-high | High for SZZ part | Treat as BIC/candidate baseline, not affected-version baseline. |
| p06 SEM-SZZ | Fine-grained semantic analysis for BIC, added/deleted-line and CFG/dataflow-style evidence. | Medium-high | High for "semantic SZZ" | VulnGraph cannot call lexical fingerprinting fine-grained semantic equivalence without evidence. |
| p16 AgentSZZ | LLM agent with git_blame/git_show/git_log_s/git_grep/git_log_func, scoped search, compression. | Medium-high | High for agentic history search | Root-cause-guided agent search is not unique. |
| p19 Beyond Blame / AgenticSZZ | Temporal KG of commit history + agentic BIC search; ablation on TKG and agent. | Medium-high | High for graph-backed BIC search | Graph + agent for history search is covered. Need affected-version state contribution. |
| p25 How and Why Agents Identify BICs | Simple agentic workflow derives greppable patterns from fix diff/message; strong BIC claims. | Medium-high | High for agentic BIC novelty | Do not claim agent search itself; focus on version-state reasoning. |
| p35 MAS-SZZ | Multi-agent root-cause, anchor selection, context retrieval, BIC backtracking; output is VIC/BIC. | Medium-high | Very high for RootCause+SZZ pipeline | Must distinguish affected-version from VIC/BIC. |
| p34 ATT&CK-to-CVE KG | CVE/CWE/CAPEC/ATT&CK KG, multi-hop traversal, Neo4j-style CTI graph. | Low for affected-version, high for attacker-KG | Medium for A/C | Attacker/CTI graph is not new; only task-specific integration may be new. |
| p36 D3FEND KG | Cybersecurity countermeasure ontology, typed artifacts, attack-defense mapping. | Low direct | Medium for graph ontology | KG evidence normalization is prior art. |
| p37 KRYSTAL | RDF/provenance KG, SPARQL rules, attack reconstruction from audit data. | Low direct | Medium for graph-backed reasoning | Declarative graph reasoning in security is not new. |
| p38 NEXUS | CVE-to-TTP mapping, structured chains, LLM label repair, classifier, analyst feedback adaptation. | Low direct, high adaptation analogy | High for C as adaptation story | Feedback adaptation is prior-art-shaped; VulnGraph has no implemented analogue yet. |

Conclusion from baselines:

- SZZ/Agent/KG pieces are heavily covered.
- Affected-version identification itself is heavily covered.
- The only defensible gap is the middle: turning root-cause-bound history evidence into branch-specific tag-level vulnerability state under strict evidence constraints.

## Novelty A Harsh Review: Attacker-Condition-Guided Affected-Version Reasoning

Proposed novelty:

> Use attacker conditions, exploit preconditions, and threat context to guide affected-version reasoning.

Current classification: `UNSUPPORTED_OR_OVERCLAIMED`.

What is implemented:

- Root Cause V2 extracts vulnerable/fix/guard/negative predicates from wrapper evidence.
- Boundary input v1.2 contains an `attacker_context` field.

What current evidence contradicts:

- `judge_boundary_v1_2.py` sets `attacker_context` to `{"available": false, "reason": "module_not_implemented"}`.
- Judge v0 stress artifact reports attacker context unavailable for all cases.
- Root Cause V2 prompt explicitly says use CVE/CWE/CAPEC only as context, never as proof; it is not an attacker-condition theorem generator.

Baseline coverage:

- ATT&CK-to-CVE and NEXUS cover CVE-to-attack-technique / adversarial behavior mapping.
- D3FEND and KRYSTAL cover typed security KG reasoning.
- AgentSZZ/MAS-SZZ already use CVE descriptions and root-cause style evidence to guide history search.

What would make A publishable:

- A typed attacker-condition representation that is not merely a CVE/CWE text summary.
- A deterministic admission rule: when can an attacker condition affect tag-level vulnerability state?
- Ablation: same candidate/history budget with and without attacker-condition guidance.
- Gold labels: cases where affectedness depends on applicability conditions, not only code presence.

Current paper action:

- Delete as a headline novelty.
- Keep only as planned ablation or future extension.
- Safe rewrite: "The current design can carry applicability constraints, but attacker-condition-guided reasoning is not yet implemented or evaluated."

## Novelty B Harsh Review: Evidence-Constrained Branch-Specific Vulnerability-State Reconstruction

Proposed novelty:

> Reconstruct vulnerability state over branches/releases using evidence-constrained history events, judge decisions, and deterministic predicate/fix-state propagation.

Current classification:

- Infrastructure and converter: `IMPLEMENTED_BUT_UNVALIDATED`.
- Scientific contribution: `PLANNED_ONLY` until manual semantic labels and baseline ablations exist.

What is genuinely promising:

- The pipeline distinguishes patch-bound root-cause evidence from raw touched lines.
- Git Graph Index is a strong fact layer and avoids per-tag Git process explosion.
- History-event packets aggregate multiple Git evidence families.
- Boundary input forbids ground truth and affected-version leakage.
- Tri-state policy refuses to include unknowns in primary prediction and blocks weak fingerprint confirmations.
- Converter/tri-state route actually outputs affected-version predictions, not just BICs.

Hard blockers:

- Candidate event truth is unvalidated. Raw candidates are not true introduction events until labeled.
- History reconstruction still has empty recursive blame chains.
- Judge boundary output is contract-validated but not semantically validated.
- v1.2.1 has decent diagnostic micro-F1, but 20/30 cases are unknown_state.
- v1.2.2/tri-state become more honest and more conservative; unknown remains very high.
- Tri-state audit explicitly reports no independent fix predicate evidence; fix absence is mostly reachability proxy.
- State audit shows path/function missing dominates many unknown cases.

Baseline coverage:

- V-SZZ and TDSC cover commit/release range inference and branch/repatch issues.
- LLM4SZZ, AgentSZZ, MAS-SZZ, Beyond Blame cover semantic/agentic BIC candidate generation and history traversal.
- VERCATION covers LLM/static vulnerable-version identification.

What remains potentially novel:

> Not "we use SZZ and an LLM." The possible contribution is a state machine that treats affectedness as a branch-local predicate/fix condition over release tags, with explicit unknowns and evidence ledgers.

Minimum publishable version of B:

- Formalize states: `active vulnerable predicate`, `complete prerequisite`, `fix completion present/absent`, `branch membership`, and `unknown`.
- Prove or empirically show that the state model catches failures of direct BIC-to-tag reachability.
- Provide manual labels for true history event and tag-level state on a dev/test subset.
- Compare against direct BIC-to-tag, raw top-1 candidate, V-SZZ-like range inference, and signature matching.

Current paper action:

- Make B the only core novelty.
- But title/abstract must say "prototype" or "evidence-constrained state reconstruction" only after labels and ablations exist.

## Novelty C Harsh Review: Graph-Backed Continual Adaptation for Affected-Version Identification

Proposed novelty:

> Store cross-case graph memories and improve future affected-version reasoning through continual adaptation.

Current classification: `PLANNED_ONLY`, with current claims likely `UNSUPPORTED_OR_OVERCLAIMED`.

What exists:

- JSONL graph store.
- Optional Neo4j materialization.
- Ontology node/edge types including memory nodes.
- Failure-to-candidate-memory rule.
- Policy layer that blocks `learning_candidate` and `offline_eval_only` from production packets.

What is missing:

- No retrieval stage that injects validated memories into root-cause/Judge/converter inputs.
- No promotion rule beyond generic lifecycle transition helper.
- No human-review or verifier-gated adaptation loop.
- No chronological train/test split.
- No negative-transfer audit.
- No comparison against no-memory baseline.

Baseline coverage:

- NEXUS already has analyst feedback adaptation for CVE-to-TTP.
- D3FEND/KRYSTAL/ATT&CK-to-CVE show graph-backed security reasoning.
- AgenticSZZ/Beyond Blame covers graph + agent in BIC history search.

Current paper action:

- Delete from main contributions.
- Put in future work only.
- Do not use "continual", "self-evolving", "adaptive learning", or "graph-backed memory improves accuracy" unless an actual adaptation experiment exists.

## Contribution Structure Recommendation

Recommended paper structure:

1. Core problem: affected-version identification is a tag-level vulnerability-state problem, not merely BIC localization.
2. Core method: evidence-constrained branch-state reconstruction.
3. Infrastructure: Git DAG index and evidence contracts enable reproducible state reconstruction.
4. Secondary component: root-cause/SZZ/Judge are candidate-generation and boundary-selection stages.
5. Evaluation: compare affected-version outputs against direct baselines and stage ablations.

Recommended contribution list after validation:

- C1: A formal branch-local vulnerability-state model for affected-version identification.
- C2: A reproducible pipeline that converts patch-bound root-cause evidence and history-event candidates into tag-level tri-state ledgers.
- C3: An evaluation showing when the state model improves over BIC-to-tag reachability and patch-signature baselines, plus failure-mode analysis of unknowns.

Contributions to avoid:

- "First agentic affected-version system" - too broad and likely false.
- "Attacker-condition-guided" - unimplemented.
- "Graph-backed continual adaptation" - unimplemented.
- "Semantic equivalence" - current v1.2.2 is token/fingerprint/function-scope heuristic, not semantic equivalence in the AST/CFG/dataflow sense.
- "Recursive blame reconstruction" - current packet records empty recursive chains.

## Claim Rewrite

Unsafe:

> VulnGraph uses attacker-conditioned graph reasoning and continual self-evolution to identify affected versions.

Safe current-state rewrite:

> VulnGraph is an experimental pipeline for affected-version identification that combines evidence-gated root-cause extraction, SZZ-derived history-event candidates, branch-aware Git DAG facts, and deterministic tri-state tag ledgers. Current artifacts demonstrate engineering feasibility and leakage controls, but semantic correctness and baseline improvements remain unvalidated.

Unsafe:

> Our Judge identifies vulnerability-introducing boundaries.

Safe:

> The current Judge ranks or selects raw branch-boundary candidates under a schema contract. Its outputs require manual or benchmark validation before they can be treated as true introduction boundaries.

Unsafe:

> The Git graph enables affected-version inference.

Safe:

> The Git graph is a read-only fact layer for commits, refs, tags, ancestry, release projection, and cached Git evidence. A separate state-reconstruction algorithm is required to infer affected versions.

Unsafe:

> The tri-state policy solves false positives by semantic verification.

Safe:

> The tri-state policy prevents unknown and weak fingerprint evidence from entering the primary prediction, but current artifacts show high unknown rates and no independent fix-predicate evidence.

Unsafe:

> Our graph memory continually improves future runs.

Safe:

> The current graph schema contains candidate memory hooks; no validated continual adaptation loop has been implemented or evaluated.

## Minimal Falsification Experiments

These are the smallest experiments that can kill or rescue the paper. They should be run before adding more features.

### E0: Event Candidate Recall Gate

Hypothesis:

> Root-cause-guided SZZ/history-event reconstruction produces a candidate set that contains the true vulnerability-introducing event more often than raw blame/fallback baselines.

Dataset:

- Dev30 plus a held-out validation subset.
- Manual true-event labels for each CVE, including "no single true event" when appropriate.

Baselines:

- Raw normal blame.
- `-w/-M/-C` blame union.
- deterministic fallback.
- LLM4SZZ/MAS-SZZ-style candidate where locally available or paper-reported baseline if not runnable.

Metrics:

- Recall@1/@3/@5 of true event.
- Candidate set size.
- No-candidate rate.
- Add-only, multi-file, branch/backport stratification.

Kill criterion:

- If true-event Recall@k is not materially better than blame union, B is not a history-reconstruction contribution.

### E1: Boundary Judge Validation

Hypothesis:

> Judge boundary selection improves true boundary top-1 over deterministic ranking features.

Dataset:

- Same manually labeled event subset.

Baselines:

- deterministic ranking from `deterministic_ranking_features`;
- raw top-1;
- random within candidate group as sanity lower bound.

Metrics:

- top-1 accuracy;
- MRR;
- abstention/uncertain rate;
- repair retry rate;
- correctness by strong vs fallback lane.

Kill criterion:

- If Judge top-1 is not better than deterministic ranking, the Judge should be removed or demoted to optional explanation.

### E2: Branch-State Affected-Version Validation

Hypothesis:

> Branch-local predicate/fix-state reconstruction improves affected-version exact accuracy and version-level F1 over BIC-to-tag reachability.

Dataset:

- Manually audited affected/unaffected/unknown tag states for a small but representative subset, or benchmark labels with manual spot checks for ambiguous cases.

Baselines:

- direct BIC-to-release reachability;
- raw top-1 diagnostic converter;
- V-SZZ-like range inference;
- signature matching if available.

Metrics:

- exact accuracy;
- NMR;
- micro precision/recall/F1;
- unknown rate;
- confirmed-only precision;
- unknown-to-error attribution.

Kill criterion:

- If branch-state reconstruction only increases unknowns without improving confirmed precision or end-to-end F1, B is an engineering ledger, not a paper-level contribution.

### E3: Attacker-Condition Ablation

Hypothesis:

> Explicit attacker/applicability conditions improve affected-version decisions in cases where code presence alone is insufficient.

Required implementation before running:

- Real `attacker_context` module.
- Typed condition schema.
- Admission rule tying conditions to tag verdicts.

Baselines:

- same pipeline without attacker conditions.

Metrics:

- delta in false positives/false negatives on applicability-sensitive cases;
- evidence-citation correctness;
- abstention rate.

Kill criterion:

- If no applicability-sensitive subset exists or the delta is negligible, delete Novelty A.

### E4: Continual Adaptation Chronological Split

Hypothesis:

> Validated graph memories improve future affected-version predictions without leaking labels or causing negative transfer.

Required implementation before running:

- Memory retrieval;
- promotion gate;
- chronology split by disclosure/fix date;
- no access to future labels.

Metrics:

- performance delta over no-memory pipeline;
- number of promoted memories;
- reviewer rejection rate;
- negative-transfer cases.

Kill criterion:

- If no statistically meaningful improvement or leakage-safe split cannot be built, delete Novelty C.

## Paper Evidence Ledger

| Claim type | Current evidence | Allowed in paper now? | Required before strong claim |
|---|---|---:|---|
| We define affected-version identification as tag-level state, distinct from BIC. | Paper draft and p01 reference support framing. | Yes | Cite and formalize cleanly. |
| Git DAG index supports release projection and evidence caching. | Implemented and artifact summary strong. | Yes, as infrastructure | Keep non-novel; no inference claim. |
| Root Cause V2 is evidence-gated and patch-bound. | Source/prompt/contracts support. | Yes, as engineering mechanism | Semantic label audit for root-cause correctness. |
| SZZ anchor/fallback produces candidate events for Judge. | Batch artifacts support. | Yes, as pipeline stage | True-event Recall@k labels. |
| History event reconstruction is branch-aware and evidence-constrained. | Partly true for evidence packets. | Qualified only | Implement real recursion/materialized before/after state or avoid claim. |
| Judge identifies true branch boundaries. | Contract artifacts only. | No | Manual labels + deterministic baseline comparison. |
| Converter identifies affected versions. | It outputs predictions, but v1.2.1 high unknown; v1.2.2 weak F1; tri-state high unknown. | Pilot only | Baseline comparison and manual state validation. |
| Attacker-condition-guided reasoning. | Module explicitly not implemented. | No | Implement and ablate. |
| Graph-backed continual adaptation. | Candidate memory skeleton only. | No | Retrieval/promotion/chronological evaluation. |
| Self-evolving KG improves performance. | No evidence. | No | Full adaptation experiment. |

## Reviewer Attack Letter

As a strict ICSE/FSE/ASE reviewer, I would reject the current paper for the following reasons.

1. The claimed novelty is unstable. The submission appears to combine root-cause extraction, SZZ-like blame, LLM Judge ranking, a Git DAG, and a graph store. Each ingredient has close prior work. The paper does not isolate the one mechanism that is new for affected-version identification.

2. The system currently proves contract compliance, not semantic correctness. JSON parse success, forbidden-field checks, and schema gates are good engineering, but they do not show that selected candidates are true vulnerability-introducing events or that release tags are correctly classified.

3. The affected-version component arrives too late in the pipeline. Most current artifacts are about root cause, candidate commits, history packets, and boundary ranking. The affected-version converter exists, but its conservative variants produce high unknown rates and poor or preliminary F1.

4. The attacker-condition claim is unsupported. The current boundary input explicitly says the attacker-context module is not implemented.

5. The continual-adaptation claim is unsupported. The graph store and candidate-memory hooks do not constitute a learning system. There is no retrieval, promotion, chronology split, or negative-transfer evaluation.

6. The baseline story is dangerous. Direct affected-version baselines, LLM/static vulnerable-version tools, agentic SZZ, temporal KG SZZ, and CTI KGs all overlap with parts of the story. Without ablations, the paper reads as a system integration project.

7. The paper draft itself admits that method details and evaluation results are placeholders. That honesty is good for internal planning, but it is not submission-ready.

Likely reviewer question:

> What exactly is the scientific hypothesis, and what result would falsify it?

If the answer is not B, the paper is not yet ready.

## Survival Decision

Current decision:

- Overall: `Reject`.
- A: delete as main novelty.
- B: keep as the single core novelty candidate.
- C: delete or future work.

Best next scientific decision:

> Falsify this one hypothesis before doing anything else: evidence-constrained, root-cause-guided history-event selection plus branch-local predicate/fix-state reconstruction improves affected-version identification over direct BIC-to-tag reachability and patch-signature baselines on manually audited cases.

Operational priority:

1. Label true event candidates and tag states on Dev30.
2. Compare deterministic BIC-to-tag reachability, raw top-1, v1.2.1, v1.2.2, and tri-state v1.2.2.1.
3. Decide whether B survives.
4. Only after B survives, consider adding attacker-condition or memory mechanisms.

Stop doing for now:

- Building more KG/self-evolution infrastructure.
- Writing stronger paper claims.
- Adding attacker-condition narrative before implementation.
- Treating model contract success as scientific validation.

## Evidence Paths

Source and docs:

- `VulnGraph/src/vulngraph/workflows/root_cause.py`
- `VulnGraph/src/vulngraph/prompts/root_cause_v2.md`
- `VulnGraph/src/vulngraph/workflows/szz_anchor_audit.py`
- `VulnGraph/src/vulngraph/workflows/szz_fallback_candidates.py`
- `VulnGraph/src/vulngraph/services/pre_fix_candidates.py`
- `VulnGraph/src/vulngraph/services/blame_runner.py`
- `VulnGraph/src/vulngraph/workflows/history_event_reconstruction_v1.py`
- `VulnGraph/src/vulngraph/workflows/history_event_judge_readiness_v1.py`
- `VulnGraph/src/vulngraph/workflows/judge_v0.py`
- `VulnGraph/src/vulngraph/workflows/judge_boundary_v1_2.py`
- `VulnGraph/src/vulngraph/workflows/affected_version_converter_v1_2_1.py`
- `VulnGraph/src/vulngraph/workflows/affected_version_converter_v1_2_2.py`
- `VulnGraph/src/vulngraph/workflows/semantic_state_v1_2_1.py`
- `VulnGraph/src/vulngraph/workflows/semantic_state_v1_2_2.py`
- `VulnGraph/src/vulngraph/workflows/tri_state_policy_v1_2_2_1.py`
- `VulnGraph/src/vulngraph/evolution/rules.py`
- `VulnGraph/src/vulngraph/ontology/policy.py`
- `VulnGraph/src/vulngraph/services/graph_client.py`
- `VulnGraph/docs/architecture/git-dag-and-release-projection.md`
- `VulnGraph/docs/superpowers/plans/2026-06-18-vulngraph-paper-benchmark-end-to-end.md`
- `VulnGraph/docs/superpowers/plans/2026-06-20-git-dag-index-implementation.md`

Tests:

- `VulnGraph/tests/test_history_event_reconstruction_v1.py`
- `VulnGraph/tests/test_semantic_state_v1_2_2.py`
- `VulnGraph/tests/test_affected_version_converter_v1_2_2.py`
- `VulnGraph/tests/test_tri_state_policy_v1_2_2_1.py`

Artifacts:

- `VulnGraph/runs/batches/vulngraph-git-graph-index-v1/summary.json`
- `VulnGraph/runs/batches/root-cause-v2-optimized-contract-30-deepseek/summary.json`
- `VulnGraph/runs/batches/root-cause-v2-szz-anchor-audit-engineering-deepseek-30-final-fallback/summary.json`
- `VulnGraph/runs/batches/vulngraph-history-event-reconstruction-v1-dev30/summary.json`
- `VulnGraph/runs/batches/vulngraph-history-event-judge-readiness-v1-dev30/summary.json`
- `VulnGraph/runs/batches/vulngraph-history-event-judge-readiness-v1-1-anchor-relocation-dev30/summary.json`
- `VulnGraph/runs/batches/vulngraph-judge-v0-full-stress-10plus30/summary.json`
- `VulnGraph/runs/batches/vulngraph-judge-boundary-v1-2-dev30/summary.json`
- `VulnGraph/runs/batches/vulngraph-affected-version-converter-v1-2-1-dev30/{summary.json,paper_metrics.json,stage_error_attribution.json}`
- `VulnGraph/runs/batches/vulngraph-affected-version-converter-v1-2-2-dev30/{summary.json,paper_metrics.json,stage_error_attribution.json}`
- `VulnGraph/runs/batches/vulngraph-tri-state-policy-v1-2-2-1-dev30/summary.json`
- `VulnGraph/runs/batches/vulngraph-v1-2-2-state-audit-dev30/summary.json`

Paper draft:

- `Paper/Paper/main.tex`
- `Paper/Paper/Sections/01_Introduction.tex`
- `Paper/Paper/Sections/04_Approach.tex`
- `Paper/Paper/Sections/06_Evaluation.tex`
- `Paper/Paper/Sections/08_Related_Work.tex`

Reference corpus:

- `Paper/reference/p01_vulnerability_affected_versions_how_far_are_we`
- `Paper/reference/p09_v_szz_automatic_identification_version_ranges_2022`
- `Paper/reference/p20_cavulner_automated_context_aware_identification_of_vulnerable_versions`
- `Paper/reference/p32_tdsc_automatically_identifying_cve_affected_versions_with_patches_and_developer_logs`
- `Paper/reference/p33_vercation_precise_vulnerable_open_source_software_version_identification_based_on_static_a`
- `Paper/reference/p04_llm4szz_2025`
- `Paper/reference/p06_enhancing_bug_inducing_commit_identification_a_fine_grained_semantic_analysis_approach_2024`
- `Paper/reference/p16_agentszz_teaching_the_llm_agent_to_play_detective_with_bug_inducing_commits`
- `Paper/reference/p19_beyond_blame_rethinking_szz_with_knowledge_graph_search`
- `Paper/reference/p25_how_and_why_agents_can_identify_bug_introducing_commits`
- `Paper/reference/p35_mas_szz_multi_agentic_szz_algorithm_for_vulnerability_inducing_commit_identification`
- `Paper/reference/p34_attack_to_cve_large_scale_automated_knowledge_graph_for_threat_intelligence`
- `Paper/reference/p36_toward_a_knowledge_graph_of_cybersecurity_countermeasures`
- `Paper/reference/p37_krystal_knowledge_graph_based_framework_for_tactical_attack_discovery_in_audit_data`
- `Paper/reference/p38_nexus_towards_accurate_and_scalable_mapping_between_vulnerabilities_and_attack_techniques`

## Known Unknowns

- Official citation metadata for several 2025/2026 papers still needs verification.
- Several reference tables/figures need repair before exact numeric citation.
- No current artifact proves manual true-BIC or true-boundary correctness.
- No current artifact proves tag-level semantic-state correctness independent of benchmark affected-version labels.
- No current artifact compares v1.2.1/v1.2.2/tri-state against all direct affected-version baselines.
- No current artifact implements attacker-context extraction.
- No current artifact implements graph-memory retrieval/promotion/adaptation.
- No current artifact proves semantic equivalence beyond lexical/function-scope token fingerprinting.
- No current artifact proves complete branch/backport semantics beyond fix-universe coverage and reachability/proxy checks.

Final audit position:

> The project has enough engineering substance to become a strong paper, but only if it stops marketing three novelties and falsifies one: branch-specific evidence-constrained affected-version state reconstruction.
