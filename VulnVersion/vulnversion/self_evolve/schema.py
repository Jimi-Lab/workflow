from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


STAGE3_AGENT_SOURCES = frozenset({"agent", "agent_error"})


@dataclass(frozen=True)
class SourcePaths:
  result_dir: str
  eval_path: str | None = None
  per_tag_verdict_path: str | None = None
  rci_path: str | None = None
  rci_self_check_path: str | None = None
  agent_trace_path: str | None = None
  calls_index_path: str | None = None

  @classmethod
  def from_result_dir(cls, result_dir: Path) -> "SourcePaths":
    def maybe(name: str) -> str | None:
      p = result_dir / name
      return str(p.resolve()) if p.exists() else None

    return cls(
      result_dir=str(result_dir.resolve()),
      eval_path=maybe("eval.json"),
      per_tag_verdict_path=maybe("per_tag_verdict.jsonl"),
      rci_path=maybe("rci.json"),
      rci_self_check_path=maybe("rci_self_check.json"),
      agent_trace_path=maybe("agent_trace.jsonl"),
      calls_index_path=maybe("agent_calls/index.jsonl"),
    )


@dataclass(frozen=True)
class FailureAttribution:
  category: str
  stage: str
  agent_judge_relevant: bool
  reason: str
  blocked_from_injection: bool = True
  suggested_next_step: str = "inspect_case_pack"


@dataclass(frozen=True)
class AgentEnhanceCase:
  case_id: str
  enhancement_id: str
  repo: str
  cve_id: str
  stage: str
  task_type: str
  failure_type: str
  attribution: FailureAttribution
  source_paths: SourcePaths
  tag: str | None = None
  line: str | None = None
  verdict: str | None = None
  run_status: str | None = None
  verdict_source: str | None = None
  confidence: float | None = None
  prompt_name: str | None = None
  prompt_version: str | None = None
  schema_name: str | None = None
  prompt_hash: str | None = None
  evidence_summary: dict[str, Any] = field(default_factory=dict)
  offline_oracle: dict[str, Any] = field(default_factory=dict)
  leakage_policy: dict[str, Any] = field(default_factory=dict)

  def model_dump(self) -> dict[str, Any]:
    return asdict(self)


@dataclass(frozen=True)
class CasePackManifest:
  enhancement_id: str
  status: str
  result_root: str
  output_dir: str
  total_cases: int
  agent_judge_relevant_cases: int
  non_agent_cases: int
  failure_type_counts: dict[str, int]
  attribution_counts: dict[str, int]
  replay_status: str
  small_sample_status: str
  notes: list[str] = field(default_factory=list)

  def model_dump(self) -> dict[str, Any]:
    return asdict(self)
