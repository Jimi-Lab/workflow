from __future__ import annotations

from vulnversion.agent_harness.memory.schema import MemoryRecord


class MemoryManager:
  """No-op manager for the OpenCode-first harness phase."""

  def retrieve(self, *, stage: str, scope: str) -> list[MemoryRecord]:
    return []

  def update(self, record: MemoryRecord) -> None:
    return None
