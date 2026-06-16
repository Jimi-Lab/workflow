from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AgentTask:
  stage: str
  task_type: str
  cve_id: str
  repo_path: str
  prompt: str
  session_id: str
  system: str | None = None
  timeout_s: float | None = None
  tools: dict[str, bool] | None = None
  prompt_name: str | None = None
  prompt_version: str | None = None
  schema_name: str | None = None
  prompt_builder: str | None = None
  metadata: dict[str, Any] = field(default_factory=dict)
  judgement_only: bool = True
  forbidden_context: list[str] = field(default_factory=list)
