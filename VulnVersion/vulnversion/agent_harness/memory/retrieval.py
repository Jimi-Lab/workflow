from __future__ import annotations

from vulnversion.agent_harness.memory.schema import MemoryRecord


def filter_by_scope(records: list[MemoryRecord], *, scope_prefix: str) -> list[MemoryRecord]:
  return [r for r in records if r.scope.startswith(scope_prefix)]
