from __future__ import annotations

import os
from dataclasses import dataclass
from typing import ClassVar


def default_agent_backend() -> str:
  return os.getenv("VV_AGENT_BACKEND", "opencode").strip().lower() or "opencode"


MEMORY_MODES = frozenset({"off", "read_only", "write_candidate", "full"})
SKILL_MODES = frozenset({"off", "backend_native", "canonical_verified"})
REPLAY_MODES = frozenset({"off", "strict", "permissive"})


def _env_mode(name: str, default: str, allowed: frozenset[str]) -> str:
  return normalize_mode(os.getenv(name, default), default=default, allowed=allowed, field_name=name)


def default_memory_mode() -> str:
  return _env_mode("VV_MEMORY_MODE", "off", MEMORY_MODES)


def default_skill_mode() -> str:
  return _env_mode("VV_SKILL_MODE", "backend_native", SKILL_MODES)


def default_replay_mode() -> str:
  return _env_mode("VV_REPLAY_MODE", "off", REPLAY_MODES)


def normalize_mode(value: str | None, *, default: str, allowed: frozenset[str], field_name: str) -> str:
  normalized = (value or default).strip().lower()
  if normalized not in allowed:
    raise ValueError(f"invalid {field_name}: {value!r}; expected one of {sorted(allowed)}")
  return normalized


@dataclass(frozen=True)
class AgentHarnessConfig:
  MEMORY_MODES: ClassVar[frozenset[str]] = MEMORY_MODES
  SKILL_MODES: ClassVar[frozenset[str]] = SKILL_MODES
  REPLAY_MODES: ClassVar[frozenset[str]] = REPLAY_MODES

  backend: str = "opencode"
  memory_mode: str = "off"
  skill_mode: str = "backend_native"
  replay_mode: str = "off"
  trace_enabled: bool = True

  def __post_init__(self) -> None:
    object.__setattr__(self, "backend", (self.backend or "opencode").strip().lower())
    object.__setattr__(
      self,
      "memory_mode",
      normalize_mode(self.memory_mode, default="off", allowed=MEMORY_MODES, field_name="memory_mode"),
    )
    object.__setattr__(
      self,
      "skill_mode",
      normalize_mode(self.skill_mode, default="backend_native", allowed=SKILL_MODES, field_name="skill_mode"),
    )
    object.__setattr__(
      self,
      "replay_mode",
      normalize_mode(self.replay_mode, default="off", allowed=REPLAY_MODES, field_name="replay_mode"),
    )

  @classmethod
  def from_env(cls) -> "AgentHarnessConfig":
    return cls(
      backend=default_agent_backend(),
      memory_mode=default_memory_mode(),
      skill_mode=default_skill_mode(),
      replay_mode=default_replay_mode(),
    )

  def model_dump(self) -> dict[str, object]:
    return {
      "backend": self.backend,
      "memory_mode": self.memory_mode,
      "skill_mode": self.skill_mode,
      "replay_mode": self.replay_mode,
      "trace_enabled": self.trace_enabled,
    }
