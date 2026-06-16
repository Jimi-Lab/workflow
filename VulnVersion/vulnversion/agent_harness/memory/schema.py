from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MemoryRecord:
  memory_id: str
  memory_type: str
  scope: str
  content: dict[str, Any]
  evidence: list[dict[str, Any]] = field(default_factory=list)
  reliability: float = 0.0
  lifecycle: str = "candidate"
