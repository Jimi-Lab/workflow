from __future__ import annotations

from vulnversion.agent_harness.base import ReservedAgentRuntime


class CodexRuntime(ReservedAgentRuntime):
  backend_name = "codex"

  def __init__(self) -> None:
    super().__init__(
      reason=(
        "CodexRuntime is reserved for backend comparison but is not wired in the "
        "current OpenCode-first refactor. Codex does not automatically load "
        "VulnVersion/.opencode/skills."
      )
    )
