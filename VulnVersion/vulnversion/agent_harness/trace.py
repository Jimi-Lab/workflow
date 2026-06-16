from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def stable_text_hash(text: str | None) -> str | None:
  if text is None:
    return None
  return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class AgentTraceEvent:
  trace_id: str
  backend: str
  stage: str
  task_type: str
  cve_id: str | None = None
  repo: str | None = None
  repo_path: str | None = None
  session_id: str | None = None
  prompt_name: str | None = None
  prompt_version: str | None = None
  prompt_builder: str | None = None
  schema_name: str | None = None
  prompt_hash: str | None = None
  system_hash: str | None = None
  parsed_output_path: str | None = None
  prompt_path: str | None = None
  system_path: str | None = None
  prompt_chars: int | None = None
  system_chars: int | None = None
  timeout_s: float | None = None
  latency_s: float | None = None
  status: str = "ok"
  error: str | None = None
  parsed_keys: list[str] = field(default_factory=list)
  metadata: dict[str, Any] = field(default_factory=dict)

  def model_dump(self) -> dict[str, Any]:
    return {
      "trace_id": self.trace_id,
      "time": time.time(),
      "backend": self.backend,
      "stage": self.stage,
      "task_type": self.task_type,
      "cve_id": self.cve_id,
      "repo": self.repo,
      "repo_path": self.repo_path,
      "session_id": self.session_id,
      "prompt_name": self.prompt_name,
      "prompt_version": self.prompt_version,
      "prompt_builder": self.prompt_builder,
      "schema_name": self.schema_name,
      "prompt_hash": self.prompt_hash,
      "system_hash": self.system_hash,
      "parsed_output_path": self.parsed_output_path,
      "prompt_path": self.prompt_path,
      "system_path": self.system_path,
      "prompt_chars": self.prompt_chars,
      "system_chars": self.system_chars,
      "timeout_s": self.timeout_s,
      "latency_s": self.latency_s,
      "status": self.status,
      "error": self.error,
      "parsed_keys": list(self.parsed_keys),
      "metadata": dict(self.metadata),
    }


def new_trace_id() -> str:
  return uuid.uuid4().hex


class JsonlTraceWriter:
  def __init__(self, path: str | Path) -> None:
    self.path = Path(path)

  def append(self, event: AgentTraceEvent) -> None:
    self.path.parent.mkdir(parents=True, exist_ok=True)
    with self.path.open("a", encoding="utf-8") as f:
      f.write(json.dumps(event.model_dump(), ensure_ascii=False) + "\n")
