# stage3_agent_judge_failures_v0

Status: hypothesis

This case pack was generated from existing VulnVersion result artifacts.
It is evidence for analysis only and does not enable memory, skill, or prompt injection.

- total cases: 20
- agent judge relevant cases: 20
- non-agent planner/artifact cases: 0

Admission gates before promotion:

1. ReplayRuntime must replay the relevant prompt/artifact records without unexplained miss.
2. Small-sample OpenCode validation must report improved, regression, and unchanged cases.
3. Leakage gate must confirm no GT affected tags, affected range, neighbor verdicts, or planner state enter prompts, memory content, or skill content.
