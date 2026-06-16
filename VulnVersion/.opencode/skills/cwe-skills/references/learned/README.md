# CWE Learned Overlay

This directory is the VulnVersion self-evolution overlay for the OpenCode-native `cwe-skills` skill.

## Layers

- `references/by-id/`: static base knowledge generated from official CWE data. It is rebuildable and must not be overwritten by learning.
- `references/learned/candidates/`: candidate overlay records generated from case packs. Candidates are not injectable.
- `references/learned/by-id/CWE-XXX/`: verified overlay files that may be routed by OpenCode after all gates pass.

## Admission Gates

A learned rule can be promoted only when all gates pass:

1. It comes from a VulnVersion case pack.
2. ReplayRuntime validation is complete and not `not_run`.
3. Small-sample OpenCode validation is complete and reports improved, regression, and unchanged cases.
4. Leakage gate confirms the rule contains no GT affected tags, affected range, neighbor verdict, tag plan, scan order, early stop, or planner state.
5. The rule improves judge capability rather than planner behavior.

## Non-injectable Content

Candidate or verified overlay must not contain:

- GT affected tags
- affected range
- neighbor verdict
- planner state
- tag plan
- scan order
- early stop decisions

## Promotion Target

If a learned rule can be implemented deterministically in Python, promote it to ArtifactMemory instead of keeping it as prompt-level CWE guidance.
