from __future__ import annotations

from typing import Any, Protocol


class RootCauseAgentBackend(Protocol):
  def health(self) -> dict[str, Any]: ...

  def create_readonly_session(self, *, title: str) -> str: ...

  def run_json(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str,
    timeout_s: float | None = None,
  ) -> dict[str, Any]: ...
