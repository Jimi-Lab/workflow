from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from vulngraph.agent_backend import RootCauseAgentBackend
from vulngraph.store import JsonlGraphStore

from .context import RootCauseContextConfig, build_root_cause_context
from .events import root_cause_output_to_events
from .models import RootCauseAgentOutput
from .prompt import render_root_cause_prompt


class RootCauseRunResult(BaseModel):
  run_id: str
  session_id: str
  hypothesis_count: int
  event_count: int
  run_dir: str


class RootCauseAgentService:
  def __init__(
    self,
    *,
    backend: RootCauseAgentBackend,
    store: JsonlGraphStore,
    runs_root: str | Path,
    context_config: RootCauseContextConfig | None = None,
  ) -> None:
    self.backend = backend
    self.store = store
    self.runs_root = Path(runs_root)
    self.context_config = context_config or RootCauseContextConfig()

  def run(
    self,
    *,
    cve_id: str,
    repo: str,
    repo_path: str,
    timeout_s: float | None = None,
  ) -> RootCauseRunResult:
    packet = build_root_cause_context(
      self.store.materialize(),
      cve_id=cve_id,
      repo=repo,
      repo_path=repo_path,
      config=self.context_config,
    )
    prompt = render_root_cause_prompt(packet)
    self.backend.health()
    session_id = self.backend.create_readonly_session(title=f"VulnGraph root cause {cve_id}")
    raw = self.backend.run_json(
      session_id=session_id,
      prompt=prompt.user,
      system=prompt.system,
      timeout_s=timeout_s,
    )
    raw_attempts = [raw]
    try:
      output = RootCauseAgentOutput.model_validate(raw)
    except ValidationError as error:
      repaired = self.backend.run_json(
        session_id=session_id,
        prompt=self._repair_prompt(raw, error),
        system=prompt.system,
        timeout_s=timeout_s,
      )
      self._validate_evidence_unchanged(raw, repaired)
      raw_attempts.append(repaired)
      output = RootCauseAgentOutput.model_validate(repaired)
    self._validate_identity(output, cve_id=cve_id, repo=repo, repo_path=repo_path)

    events = root_cause_output_to_events(output)
    self.store.append_events(events)
    graph = self.store.materialize()
    self.store.write_snapshot(graph)

    run_dir = self.runs_root / cve_id / output.agent_run.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "prompt.json").write_text(
      json.dumps(
        {
          "system": prompt.system,
          "user": prompt.user,
          "packet": packet.model_dump(mode="json"),
          "session_id": session_id,
          "schema_repair_count": len(raw_attempts) - 1,
        },
        ensure_ascii=False,
        indent=2,
      ),
      encoding="utf-8",
    )
    (run_dir / "raw_output.json").write_text(json.dumps(raw_attempts, ensure_ascii=False, indent=2), encoding="utf-8")
    (run_dir / "output.json").write_text(
      json.dumps(output.model_dump(mode="json"), ensure_ascii=False, indent=2),
      encoding="utf-8",
    )
    return RootCauseRunResult(
      run_id=output.agent_run.run_id,
      session_id=session_id,
      hypothesis_count=len(output.root_cause_hypotheses),
      event_count=len(events),
      run_dir=str(run_dir),
    )

  @staticmethod
  def _validate_identity(output: RootCauseAgentOutput, *, cve_id: str, repo: str, repo_path: str) -> None:
    identity = output.agent_run
    mismatches = []
    if identity.cve_id != cve_id:
      mismatches.append(f"cve_id={identity.cve_id!r}")
    if identity.repo != repo:
      mismatches.append(f"repo={identity.repo!r}")
    if Path(identity.repo_path).resolve() != Path(repo_path).resolve():
      mismatches.append(f"repo_path={identity.repo_path!r}")
    if mismatches:
      raise ValueError("agent output identity mismatch: " + ", ".join(mismatches))

  @staticmethod
  def _repair_prompt(raw: dict, error: ValidationError) -> str:
    return f"""Repair the previous JSON so it validates against the required RootCauseAgentOutput schema.
Do not call tools. Do not add, remove, or change command_invocations or their outputs. Do not invent evidence.
Only correct schema fields, ID placement, missing required fields, or invalid references.
Return one corrected JSON object only.

Validation error:
{error}

Previous JSON:
{json.dumps(raw, ensure_ascii=False, indent=2)}"""

  @staticmethod
  def _validate_evidence_unchanged(original: dict, repaired: dict) -> None:
    original_commands = original.get("command_invocations", [])
    repaired_commands = repaired.get("command_invocations", [])
    if repaired_commands != original_commands:
      raise ValueError("schema repair changed command_invocations; refusing repaired output")
