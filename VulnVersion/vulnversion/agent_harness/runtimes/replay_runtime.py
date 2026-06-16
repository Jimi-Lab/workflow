from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnversion.agent_harness.base import AgentCapabilities
from vulnversion.agent_harness.trace import stable_text_hash


MATCH_FIELDS = [
  "stage",
  "task_type",
  "prompt_name",
  "prompt_version",
  "schema_name",
  "prompt_hash",
]


class ReplayMissError(RuntimeError):
  pass


@dataclass(frozen=True)
class ReplayRuntimePlan:
  """Replay v1 contract for trace-linked parsed outputs."""

  trace_path: str | None = None
  source_format: str = "agent_calls/index.jsonl"
  required_future_fields: list[str] = field(
    default_factory=lambda: [
      "trace_id",
      "stage",
      "task_type",
      "prompt_name",
      "prompt_version",
      "schema_name",
      "prompt_hash",
      "parsed_output_path",
    ]
  )
  match_fields: list[str] = field(
    default_factory=lambda: list(MATCH_FIELDS)
  )

  def model_dump(self) -> dict[str, Any]:
    return {
      "trace_path": self.trace_path,
      "source_format": self.source_format,
      "required_future_fields": list(self.required_future_fields),
      "match_fields": list(self.match_fields),
    }


class ReplayRuntime:
  """Minimal local replay runtime.

  Replay v1 reads parsed outputs from agent_calls/index.jsonl. It is local
  replay capable only; it does not validate batch experiments and never calls a
  model backend.
  """

  def __init__(
    self,
    *,
    trace_path: str | Path | None = None,
    calls_index_path: str | Path | None = None,
  ) -> None:
    self.trace_path = Path(trace_path) if trace_path is not None else None
    self.calls_index_path = self._resolve_index_path(trace_path=self.trace_path, calls_index_path=calls_index_path)
    self.plan = ReplayRuntimePlan(trace_path=str(self.trace_path) if self.trace_path is not None else None)
    self._entries = self._load_entries()

  @property
  def backend(self) -> str:
    return "replay"

  def capabilities(self) -> AgentCapabilities:
    return AgentCapabilities(
      backend=self.backend,
      supports_session_reuse=True,
      json_reliability="recorded",
      notes=[
        "ReplayRuntime v1 is local replay capable from agent_calls/index.jsonl.",
        "ReplayRuntime does not call OpenCode, Codex, Claude, or any model backend.",
        "Do not treat this as batch validated until replay coverage is evaluated.",
      ],
    )

  def diagnostics(self) -> dict[str, Any]:
    return {
      "backend": self.backend,
      "status": "local_replay_capable" if self.calls_index_path.exists() else "empty_index",
      "plan": self.plan.model_dump(),
      "source_path": str(self.calls_index_path),
      "loaded_entries": len(self._entries),
      "match_fields": list(MATCH_FIELDS),
    }

  def create_readonly_session(self, *, title: str | None = None) -> str:
    return title or "replay-session"

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
    query = self._query(prompt=prompt, metadata=metadata)
    for entry in self._entries:
      if self._matches(entry, query):
        parsed_path = _entry_path(entry.get("parsed_output_path"), self.calls_index_path.parent)
        if parsed_path is None or not parsed_path.exists():
          raise ReplayMissError(
            f"Replay hit trace_id={entry.get('trace_id')} but parsed_output_path is missing: {entry.get('parsed_output_path')}"
          )
        return json.loads(parsed_path.read_text(encoding="utf-8"))
    raise ReplayMissError(
      "Replay miss for "
      + ", ".join(f"{field}={query.get(field)!r}" for field in MATCH_FIELDS)
      + f" in {self.calls_index_path}"
    )

  @staticmethod
  def _resolve_index_path(
    *,
    trace_path: Path | None,
    calls_index_path: str | Path | None,
  ) -> Path:
    if calls_index_path is not None:
      return Path(calls_index_path)
    if trace_path is not None:
      return trace_path.parent / "agent_calls" / "index.jsonl"
    return Path("agent_calls") / "index.jsonl"

  def _load_entries(self) -> list[dict[str, Any]]:
    if not self.calls_index_path.exists():
      return []
    entries: list[dict[str, Any]] = []
    for line in self.calls_index_path.read_text(encoding="utf-8").splitlines():
      if not line.strip():
        continue
      try:
        record = json.loads(line)
      except json.JSONDecodeError:
        continue
      if isinstance(record, dict):
        entries.append(record)
    return entries

  def _query(self, *, prompt: str, metadata: dict[str, Any] | None) -> dict[str, Any]:
    md = dict(metadata or {})
    return {
      "stage": _optional_str(md.get("stage") or "unknown"),
      "task_type": _optional_str(md.get("task_type") or "unknown"),
      "prompt_name": _optional_str(md.get("prompt_name")),
      "prompt_version": _optional_str(md.get("prompt_version")),
      "schema_name": _optional_str(md.get("schema_name")),
      "prompt_hash": stable_text_hash(prompt),
    }

  @staticmethod
  def _matches(entry: dict[str, Any], query: dict[str, Any]) -> bool:
    return all(_optional_str(entry.get(field)) == _optional_str(query.get(field)) for field in MATCH_FIELDS)


def _optional_str(value: Any) -> str | None:
  if value is None:
    return None
  text = str(value)
  return text if text else None


def _entry_path(value: Any, base_dir: Path) -> Path | None:
  text = _optional_str(value)
  if text is None:
    return None
  path = Path(text)
  if path.is_absolute():
    return path
  return base_dir / path
