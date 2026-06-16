from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from vulnversion.agent_harness.base import AgentCapabilities
from vulnversion.agent_harness.base import AgentRuntime
from vulnversion.agent_harness.config import AgentHarnessConfig
from vulnversion.agent_harness.result import AgentResult
from vulnversion.agent_harness.task import AgentTask
from vulnversion.agent_harness.trace import AgentTraceEvent, JsonlTraceWriter, new_trace_id, stable_text_hash


class AgentService:
  """Transparent agent facade for tracing and future memory/skill injection."""

  def __init__(
    self,
    *,
    runtime: AgentRuntime,
    trace_writer: JsonlTraceWriter | None = None,
    default_metadata: dict[str, Any] | None = None,
    harness_config: AgentHarnessConfig | None = None,
  ) -> None:
    self.runtime = runtime
    self.trace_writer = trace_writer
    self.default_metadata = dict(default_metadata or {})
    self.harness_config = harness_config or AgentHarnessConfig.from_env()
    self._sessions: dict[str, dict[str, Any]] = {}

  @property
  def backend(self) -> str:
    return self.runtime.backend

  def capabilities(self) -> AgentCapabilities:
    return self.runtime.capabilities()

  def create_readonly_session(self, *, title: str | None = None) -> str:
    session_id = self.runtime.create_readonly_session(title=title)
    self.register_session(session_id=session_id, title=title, role="readonly")
    return session_id

  def register_session(
    self,
    *,
    session_id: str | None,
    title: str | None = None,
    role: str | None = None,
    metadata: dict[str, Any] | None = None,
  ) -> None:
    if not session_id:
      return
    existing = dict(self._sessions.get(session_id) or {})
    merged = {
      **existing,
      **dict(metadata or {}),
      "session_id": session_id,
      "backend": self.backend,
    }
    if title is not None:
      merged["title"] = title
    if role is not None:
      merged["role"] = role
    self._sessions[session_id] = merged

  def known_sessions(self) -> list[dict[str, Any]]:
    return [dict(v) for v in self._sessions.values()]

  def export_session_messages(self, *, session_id: str) -> list[dict[str, Any]]:
    export = getattr(self.runtime, "export_session_messages", None)
    if callable(export):
      return list(export(session_id=session_id))
    return []

  def export_known_session_messages(self) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for session in self.known_sessions():
      session_id = str(session.get("session_id") or "")
      if not session_id:
        continue
      messages = self.export_session_messages(session_id=session_id)
      out.append(
        {
          "session": session,
          "messages_count": len(messages),
          "messages": messages,
        }
      )
    return out

  def runtime_manifest(self) -> dict[str, Any]:
    diagnostics_fn = getattr(self.runtime, "diagnostics", None)
    diagnostics: dict[str, Any] | None = None
    if callable(diagnostics_fn):
      try:
        raw = diagnostics_fn()
        diagnostics = dict(raw) if isinstance(raw, dict) else {"value": raw}
      except Exception as e:
        diagnostics = {"status": "error", "error": f"{type(e).__name__}: {e}"}
    return {
      "backend": self.backend,
      "capabilities": self.capabilities().model_dump(),
      "harness_config": self.harness_config.model_dump(),
      "default_metadata": dict(self.default_metadata),
      "known_sessions": self.known_sessions(),
      "runtime_diagnostics": diagnostics,
    }

  def write_runtime_manifest(self, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(self.runtime_manifest(), ensure_ascii=False, indent=2), encoding="utf-8")

  def run_json(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str | None = None,
    tools: dict[str, bool] | None = None,
    timeout_s: float | None = None,
    metadata: dict[str, Any] | None = None,
    prompt_name: str | None = None,
    prompt_version: str | None = None,
    schema_name: str | None = None,
    prompt_builder: str | None = None,
  ) -> dict[str, Any]:
    merged_metadata = {**self.default_metadata, **dict(metadata or {})}
    _put_if_not_none(merged_metadata, "prompt_name", prompt_name)
    _put_if_not_none(merged_metadata, "prompt_version", prompt_version)
    _put_if_not_none(merged_metadata, "schema_name", schema_name)
    _put_if_not_none(merged_metadata, "prompt_builder", prompt_builder)
    self._apply_injection_audit_defaults(merged_metadata)
    stage = str(merged_metadata.get("stage") or "unknown")
    task_type = str(merged_metadata.get("task_type") or "unknown")
    trace_id = str(merged_metadata.get("trace_id") or new_trace_id())
    prompt_hash = stable_text_hash(prompt)
    system_hash = stable_text_hash(system)
    self.register_session(
      session_id=session_id,
      role=f"{stage}:{task_type}",
      metadata={
        "last_stage": stage,
        "last_task_type": task_type,
        "last_trace_id": trace_id,
      },
    )
    started = time.monotonic()
    try:
      parsed = self.runtime.run_json(
        session_id=session_id,
        prompt=prompt,
        system=system,
        tools=tools,
        timeout_s=timeout_s,
        metadata=merged_metadata,
      )
      latency = time.monotonic() - started
      artifact_paths = self._try_write_call_artifacts(
        trace_id=trace_id,
        session_id=session_id,
        stage=stage,
        task_type=task_type,
        prompt=prompt,
        system=system,
        parsed=parsed,
        prompt_hash=prompt_hash,
        system_hash=system_hash,
        metadata=merged_metadata,
      )
      self._append_trace(
        AgentTraceEvent(
          trace_id=trace_id,
          backend=self.backend,
          stage=stage,
          task_type=task_type,
          cve_id=_as_optional_str(merged_metadata.get("cve_id")),
          repo=_as_optional_str(merged_metadata.get("repo")),
          repo_path=_as_optional_str(merged_metadata.get("repo_path")),
          session_id=session_id,
          prompt_name=_as_optional_str(merged_metadata.get("prompt_name")),
          prompt_version=_as_optional_str(merged_metadata.get("prompt_version")),
          prompt_builder=_as_optional_str(merged_metadata.get("prompt_builder")),
          schema_name=_as_optional_str(merged_metadata.get("schema_name")),
          prompt_hash=prompt_hash,
          system_hash=system_hash,
          parsed_output_path=artifact_paths.get("parsed_output_path"),
          prompt_path=artifact_paths.get("prompt_path"),
          system_path=artifact_paths.get("system_path"),
          prompt_chars=len(prompt),
          system_chars=len(system) if system is not None else None,
          timeout_s=timeout_s,
          latency_s=latency,
          status="ok",
          parsed_keys=sorted(str(k) for k in parsed.keys()),
          metadata=merged_metadata,
        )
      )
      return parsed
    except BaseException as e:
      latency = time.monotonic() - started
      artifact_paths = self._try_write_call_artifacts(
        trace_id=trace_id,
        session_id=session_id,
        stage=stage,
        task_type=task_type,
        prompt=prompt,
        system=system,
        parsed=None,
        prompt_hash=prompt_hash,
        system_hash=system_hash,
        metadata=merged_metadata,
      )
      self._append_trace(
        AgentTraceEvent(
          trace_id=trace_id,
          backend=self.backend,
          stage=stage,
          task_type=task_type,
          cve_id=_as_optional_str(merged_metadata.get("cve_id")),
          repo=_as_optional_str(merged_metadata.get("repo")),
          repo_path=_as_optional_str(merged_metadata.get("repo_path")),
          session_id=session_id,
          prompt_name=_as_optional_str(merged_metadata.get("prompt_name")),
          prompt_version=_as_optional_str(merged_metadata.get("prompt_version")),
          prompt_builder=_as_optional_str(merged_metadata.get("prompt_builder")),
          schema_name=_as_optional_str(merged_metadata.get("schema_name")),
          prompt_hash=prompt_hash,
          system_hash=system_hash,
          parsed_output_path=artifact_paths.get("parsed_output_path"),
          prompt_path=artifact_paths.get("prompt_path"),
          system_path=artifact_paths.get("system_path"),
          prompt_chars=len(prompt),
          system_chars=len(system) if system is not None else None,
          timeout_s=timeout_s,
          latency_s=latency,
          status="error",
          error=f"{type(e).__name__}: {e}",
          metadata=merged_metadata,
        )
      )
      raise

  def run_task(self, task: AgentTask) -> AgentResult:
    parsed = self.run_json(
      session_id=task.session_id,
      prompt=task.prompt,
      system=task.system,
      tools=task.tools,
      timeout_s=task.timeout_s,
      prompt_name=task.prompt_name,
      prompt_version=task.prompt_version,
      schema_name=task.schema_name,
      prompt_builder=task.prompt_builder,
      metadata={
        "stage": task.stage,
        "task_type": task.task_type,
        "cve_id": task.cve_id,
        "repo_path": task.repo_path,
        "judgement_only": task.judgement_only,
        "forbidden_context": list(task.forbidden_context),
        **task.metadata,
      },
    )
    return AgentResult(
      backend=self.backend,
      parsed=parsed,
      session_id=task.session_id,
      metadata=task.metadata,
    )

  def _append_trace(self, event: AgentTraceEvent) -> None:
    if self.trace_writer is None:
      return
    try:
      self.trace_writer.append(event)
    except Exception:
      # Trace must never change agent behavior.
      return

  def _apply_injection_audit_defaults(self, metadata: dict[str, Any]) -> None:
    metadata.setdefault("memory_mode", self.harness_config.memory_mode)
    metadata.setdefault("skill_mode", self.harness_config.skill_mode)
    metadata.setdefault("replay_mode", self.harness_config.replay_mode)
    metadata.setdefault("retrieved_memory_ids", [])
    metadata.setdefault("selected_skills", [])
    metadata.setdefault("suppressed_skills", [])
    metadata.setdefault("injection_policy", "off")

  def _try_write_call_artifacts(
    self,
    *,
    trace_id: str,
    session_id: str,
    stage: str,
    task_type: str,
    prompt: str,
    system: str | None,
    parsed: dict[str, Any] | None,
    prompt_hash: str | None,
    system_hash: str | None,
    metadata: dict[str, Any],
  ) -> dict[str, str | None]:
    try:
      return self._write_call_artifacts(
        trace_id=trace_id,
        session_id=session_id,
        stage=stage,
        task_type=task_type,
        prompt=prompt,
        system=system,
        parsed=parsed,
        prompt_hash=prompt_hash,
        system_hash=system_hash,
        metadata=metadata,
      )
    except Exception as e:
      metadata["artifact_write_error"] = f"{type(e).__name__}: {e}"
      return {}

  def _write_call_artifacts(
    self,
    *,
    trace_id: str,
    session_id: str,
    stage: str,
    task_type: str,
    prompt: str,
    system: str | None,
    parsed: dict[str, Any] | None,
    prompt_hash: str | None,
    system_hash: str | None,
    metadata: dict[str, Any],
  ) -> dict[str, str | None]:
    if self.trace_writer is None:
      return {}
    call_dir = self.trace_writer.path.parent / "agent_calls"
    call_dir.mkdir(parents=True, exist_ok=True)

    prompt_path = call_dir / f"{trace_id}.prompt.txt"
    prompt_path.write_text(prompt, encoding="utf-8")

    system_path: Path | None = None
    if system:
      system_path = call_dir / f"{trace_id}.system.txt"
      system_path.write_text(system, encoding="utf-8")

    parsed_path: Path | None = None
    if parsed is not None:
      parsed_path = call_dir / f"{trace_id}.parsed.json"
      parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2, default=_json_default), encoding="utf-8")

    paths = {
      "parsed_output_path": _path_str(parsed_path),
      "prompt_path": _path_str(prompt_path),
      "system_path": _path_str(system_path),
    }
    index_record = {
      "trace_id": trace_id,
      "backend": self.backend,
      "stage": stage,
      "task_type": task_type,
      "cve_id": _as_optional_str(metadata.get("cve_id")),
      "repo": _as_optional_str(metadata.get("repo")),
      "repo_path": _as_optional_str(metadata.get("repo_path")),
      "session_id": session_id,
      "prompt_name": _as_optional_str(metadata.get("prompt_name")),
      "prompt_version": _as_optional_str(metadata.get("prompt_version")),
      "prompt_builder": _as_optional_str(metadata.get("prompt_builder")),
      "schema_name": _as_optional_str(metadata.get("schema_name")),
      "prompt_hash": prompt_hash,
      "system_hash": system_hash,
      **paths,
      "metadata": _jsonable(metadata),
    }
    with (call_dir / "index.jsonl").open("a", encoding="utf-8") as f:
      f.write(json.dumps(index_record, ensure_ascii=False, default=_json_default) + "\n")
    return paths


def _as_optional_str(value: Any) -> str | None:
  if value is None:
    return None
  text = str(value)
  return text if text else None


def _put_if_not_none(target: dict[str, Any], key: str, value: Any) -> None:
  if value is not None:
    target[key] = value


def _path_str(path: Path | None) -> str | None:
  if path is None:
    return None
  return str(path.resolve())


def _json_default(value: Any) -> str:
  return str(value)


def _jsonable(value: Any) -> Any:
  try:
    json.dumps(value, ensure_ascii=False, default=_json_default)
    return value
  except Exception:
    return str(value)
