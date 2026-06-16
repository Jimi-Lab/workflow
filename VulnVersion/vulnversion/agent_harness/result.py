from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AgentResult:
  backend: str
  parsed: dict[str, Any]
  session_id: str
  metadata: dict[str, Any] = field(default_factory=dict)
