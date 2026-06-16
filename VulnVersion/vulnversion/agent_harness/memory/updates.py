from __future__ import annotations

from vulnversion.agent_harness.memory.schema import MemoryRecord


def promote(record: MemoryRecord, *, lifecycle: str) -> MemoryRecord:
  return MemoryRecord(
    memory_id=record.memory_id,
    memory_type=record.memory_type,
    scope=record.scope,
    content=dict(record.content),
    evidence=list(record.evidence),
    reliability=record.reliability,
    lifecycle=lifecycle,
  )
