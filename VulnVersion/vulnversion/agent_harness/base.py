from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class AgentCapabilities:
  backend: str
  supports_bash: bool = False
  supports_git_tools: bool = False
  supports_skills: bool = False
  supports_readonly_permissions: bool = False
  supports_system_prompt: bool = False
  supports_session_reuse: bool = False
  supports_json_schema: bool = False
  skill_source: str | None = None
  max_context_tokens: int | None = None
  json_reliability: str = "unknown"
  notes: list[str] = field(default_factory=list)

  def model_dump(self) -> dict[str, Any]:
    return {
      "backend": self.backend,
      "supports_bash": self.supports_bash,
      "supports_git_tools": self.supports_git_tools,
      "supports_skills": self.supports_skills,
      "supports_readonly_permissions": self.supports_readonly_permissions,
      "supports_system_prompt": self.supports_system_prompt,
      "supports_session_reuse": self.supports_session_reuse,
      "supports_json_schema": self.supports_json_schema,
      "skill_source": self.skill_source,
      "max_context_tokens": self.max_context_tokens,
      "json_reliability": self.json_reliability,
      "notes": list(self.notes),
    }


class AgentRuntimeError(RuntimeError):
  pass


class ReservedBackendError(AgentRuntimeError):
  pass


@runtime_checkable
class AgentRuntime(Protocol):
  @property
  def backend(self) -> str: ...

  def capabilities(self) -> AgentCapabilities: ...

  def create_readonly_session(self, *, title: str | None = None) -> str: ...

  def run_json(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str | None = None,
    tools: dict[str, bool] | None = None,
    timeout_s: float | None = None,
    metadata: dict[str, Any] | None = None,
  ) -> dict[str, Any]: ...


class ReservedAgentRuntime:
  """Placeholder for backends that are designed but not wired into this run."""

  backend_name = "reserved"

  def __init__(self, *, reason: str) -> None:
    self._reason = reason

  @property
  def backend(self) -> str:
    return self.backend_name

  def capabilities(self) -> AgentCapabilities:
    return AgentCapabilities(
      backend=self.backend,
      notes=[self._reason, "Reserved runtime does not load OpenCode .opencode skills."],
    )

  def create_readonly_session(self, *, title: str | None = None) -> str:
    raise ReservedBackendError(self._reason)

  def run_json(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str | None = None,
    tools: dict[str, bool] | None = None,
    timeout_s: float | None = None,
    metadata: dict[str, Any] | None = None,
  ) -> dict[str, Any]:
    raise ReservedBackendError(self._reason)
