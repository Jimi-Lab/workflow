# VulnVersion Overall Architecture Figures

This directory contains architecture figures for VulnVersion.

Files:

- `vulnversion_overall_architecture.mmd`: Mermaid source with the most detailed architecture.
- `vulnversion_overall_architecture.svg`: directly viewable SVG summary for documents or slides.
- `vulnversion_final_paper_architecture.mmd`: Mermaid source for the final target paper architecture.
- `vulnversion_final_paper_architecture.svg`: directly viewable SVG for the final target paper architecture.

Current-state figure scope:

- The solid data path reflects the current source-code pipeline: `semantic-aggregate -> rci-extract -> verify-tags`.
- The Step3 block reflects the current planned main path from `step3.md`: VulnTree planning, family-local release lines, ASBS boundary search, runtime graph closure, artifact bucket separation, and evaluation.
- The dashed/planned blocks reflect `Agent-Enhance.md`: backend-agnostic runtime, typed VulnMem memory, verifier-gated self-evolution, SkillMemory, and ArtifactMemory.

Final target paper figure scope:

- The final figure is `vulnversion_final_paper_architecture.*`.
- It integrates the implemented three-stage source pipeline with the final target architecture described by `Agent-Enhance.md` and `step3.md`.
- Source-code-backed current path: Step1 semantic patch aggregation, Step2 RCI extraction, current OpenCode-backed agent calls, VulnTree planning, ASBS verification, runtime closure, artifact buckets, and `eval.json`.
- Planning-backed final target path: backend-agnostic `AgentRuntime`, `OpenCodeRuntime`, `ClaudeCodeRuntime`, `CodexRuntime`, `ReplayRuntime`, typed VulnMem memory, verifier-gated self-evolution, BAPEE admission, ASBS precision guard, SkillMemory, ArtifactMemory, and 1128 CVE / 9 repo evaluation.

Line semantics:

- Solid edges in `vulnversion_final_paper_architecture.mmd` show the final target main data flow: Inputs -> Step1 -> Step2 -> Step3 Planning -> Step3 Verification -> Artifacts and Evaluation.
- Dotted edges show cross-cutting support and feedback: runtime backends, trace capture, memory injection, self-evolution, and ArtifactMemory feeding deterministic logic.

Design boundaries:

- Agent is a vulnerability-version evidence navigator and verdict generator, not the tag planner.
- Step3 planning, line ordering, FIC/VIC cluster logic, and ASBS remain deterministic.
- Memory is typed and verifier-gated. It is not represented as a generic vector-store/RAG layer.
- Skills are not the whole memory layer. SkillMemory is only verified prompt-level procedural knowledge.
- ArtifactMemory is the highest promotion level and should compile stable experience into deterministic artifacts such as repo adapters, predicate repair rules, anchor relocation policy, and verdict calibration rules.
