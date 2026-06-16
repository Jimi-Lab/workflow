from __future__ import annotations

from typing import Any

from vulngraph.agent_backend import OpenCodeBackend, OpenCodeBackendConfig

from .base import AgentResponse


class OpenCodeGenerateBackend:
  backend_name = "opencode"
  backend_type = "opencode"

  def __init__(
    self,
    config: OpenCodeBackendConfig | None = None,
    *,
    timeout_s: float | None = None,
    backend: Any | None = None,
  ) -> None:
    self.backend = backend or OpenCodeBackend(config)
    self.timeout_s = timeout_s

  def generate(self, prompt: str, context: dict[str, Any]) -> AgentResponse:
    try:
      self.backend.health()
      session_id = self.backend.create_readonly_session(title=f"VulnGraph root cause v2 {context.get('cve_id', '')}")
      raw_text = self.backend.run_text(
        session_id=session_id,
        prompt=prompt,
        system=str(context.get("system_prompt") or ""),
        timeout_s=self.timeout_s,
      )
      if not raw_text.strip():
        return AgentResponse(
          raw_text="",
          status="empty",
          backend_name=self.backend_name,
          backend_type=self.backend_type,
          usage={"session_id": session_id},
          error="empty assistant message",
        )
      return AgentResponse(
        raw_text=raw_text,
        status="ok",
        backend_name=self.backend_name,
        backend_type=self.backend_type,
        usage={"session_id": session_id},
      )
    except Exception as error:
      return AgentResponse(
        raw_text="",
        status="failed",
        backend_name=self.backend_name,
        backend_type=self.backend_type,
        error=str(error),
      )
