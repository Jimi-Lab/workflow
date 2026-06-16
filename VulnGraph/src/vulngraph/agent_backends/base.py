from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


BackendStatus = Literal["ok", "empty", "failed"]


@dataclass(frozen=True)
class AgentResponse:
  raw_text: str
  status: BackendStatus
  backend_name: str
  backend_type: str
  usage: dict[str, Any] = field(default_factory=dict)
  error: str | None = None


class RootCauseBackend(Protocol):
  backend_name: str
  backend_type: str

  def generate(self, prompt: str, context: dict[str, Any]) -> AgentResponse:
    ...
