# Transferable Method Patterns

## Pattern A: Deterministic Pruning Before Expensive Reasoning

Sources: p02, p05, p07, p10, p12, p13.

Transfer:
- In VulnVersion, deterministic repository analysis should shrink the candidate tag/line space before any agent call.
- Method language should emphasize "cheap evidence first, semantic verdict later".
- This supports Step3's boundary: the agent is not the planner; it judges selected tags.

Draft insertion:
- Section `03_approach_placeholder.tex`, Step3 overview.

Evidence caveat:
- These papers are mostly recurring-vulnerability or clone-detection systems, not affected-version systems. Use as method inspiration, not direct claims.

## Pattern B: Patch-Family and Patch-Type Semantics

Sources: p01, p05, p06, p09, p14, p20, p33.

Transfer:
- Step1 should be written as a semantic filter over fix families, not a diff extractor.
- Add-only, delete-only, mixed, multi-file, and multi-branch cases should become explicit evaluation subsets.
- Patch signatures should be paired with fix evidence and vulnerable evidence to avoid confusing patched and vulnerable states.

Draft insertion:
- Background failure modes.
- Method Step1.
- RQ2 robustness.

Evidence caveat:
- Exact patch-type counts from p01 and p14 need [NEEDS TABLE REPAIR].

## Pattern C: Root-Cause Evidence Before Version Verdicts

Sources: p01, p04, p06, p14, p20, p33.

Transfer:
- Step2 should be framed as root-cause-level evidence extraction, not touched-line summarization.
- VET should distinguish vulnerable sequence, fix guard, scope, and certificate policy.
- LLM use should come after static extraction to reduce hallucinated or unconstrained judgments.

Draft insertion:
- Method Step2 and threat/internal validity.

Evidence caveat:
- VET is a VulnVersion design placeholder; method details are [NEEDS METHOD DETAIL].

## Pattern D: Repository/Version Graphs

Sources: p03, p08, p19, p32.

Transfer:
- VulnVersion should make release-line/version-tree construction a core method component.
- The paper should contrast commit history, temporal graph, release tags, and branch-specific vulnerability state.
- Lower-bound recall and manual workload can be used if complete verification is expensive.

Draft insertion:
- Background distinction between commit localization and per-tag state.
- Method Step3.
- Evaluation RQ4.

Evidence caveat:
- p19 table values and p32 figures need repair; use qualitative graph/tree concept only.

## Pattern E: Agent Tooling and Behavior Analysis

Sources: p16, p25, p04, p20, p33.

Transfer:
- Define a narrow agent API: read selected tag evidence, inspect scoped code snippets, return verdict and evidence references.
- Report cost/time/tokens/tool calls as first-class metrics.
- Add ablations: no agent, no Step1 filtering, no Step2 VET, no release-line planning, different model/backbone.

Draft insertion:
- Method agent boundary.
- Evaluation RQ3/RQ4.

Evidence caveat:
- AgentSZZ and p25 are BIC tasks; use their behavior-analysis design, not their performance claims.
