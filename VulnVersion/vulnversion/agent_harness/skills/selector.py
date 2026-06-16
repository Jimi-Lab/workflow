from __future__ import annotations

from vulnversion.agent_harness.skills.schema import SkillRecord


class SkillSelector:
  """No-op selector for the OpenCode-first harness phase."""

  def select(self, *, stage: str, backend: str) -> list[SkillRecord]:
    return []
