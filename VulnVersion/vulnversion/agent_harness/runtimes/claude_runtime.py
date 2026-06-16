from __future__ import annotations

from vulnversion.agent_harness.base import ReservedAgentRuntime


class ClaudeRuntime(ReservedAgentRuntime):
  backend_name = "claude"

  def __init__(self) -> None:
    super().__init__(
      reason=(
        "ClaudeRuntime is reserved for backend comparison but is not wired in the "
        "current OpenCode-first refactor. Claude Code has its own skill/plugin "
        "mechanism and does not automatically load VulnVersion/.opencode/skills."
      )
    )
