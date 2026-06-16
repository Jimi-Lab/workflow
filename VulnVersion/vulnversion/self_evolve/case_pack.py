from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnversion.self_evolve.hard_cases import iter_stage3_hard_cases
from vulnversion.self_evolve.schema import AgentEnhanceCase, CasePackManifest
from vulnversion.self_evolve.trace_loader import discover_result_dirs


def build_case_pack(
  *,
  result_root: str | Path,
  out_root: str | Path,
  enhancement_id: str,
  limit: int | None = None,
  include_non_agent: bool = True,
) -> CasePackManifest:
  result_root_p = Path(result_root)
  out_dir = Path(out_root) / enhancement_id
  out_dir.mkdir(parents=True, exist_ok=True)

  cases: list[AgentEnhanceCase] = []
  for result_dir in discover_result_dirs(result_root_p):
    cases.extend(
      iter_stage3_hard_cases(
        result_dir=result_dir,
        enhancement_id=enhancement_id,
        include_non_agent=include_non_agent,
      )
    )
    if limit is not None and len(cases) >= limit:
      cases = cases[:limit]
      break

  _write_jsonl(out_dir / "case_index.jsonl", [case.model_dump() for case in cases])
  _write_per_case_files(out_dir, cases)
  _write_hypothesis(out_dir / "hypothesis.md", enhancement_id=enhancement_id, cases=cases)
  _write_json(out_dir / "replay_summary.json", _replay_summary(cases))
  _write_json(out_dir / "small_sample_summary.json", _small_sample_summary())
  _touch_jsonl(out_dir / "improved_cases.jsonl")
  _touch_jsonl(out_dir / "regression_cases.jsonl")
  _touch_jsonl(out_dir / "unchanged_failure_cases.jsonl")

  failure_counts = _count(case.failure_type for case in cases)
  attribution_counts = _count(case.attribution.category for case in cases)
  agent_cases = sum(1 for case in cases if case.attribution.agent_judge_relevant)
  manifest = CasePackManifest(
    enhancement_id=enhancement_id,
    status="hypothesis",
    result_root=str(result_root_p.resolve()),
    output_dir=str(out_dir.resolve()),
    total_cases=len(cases),
    agent_judge_relevant_cases=agent_cases,
    non_agent_cases=len(cases) - agent_cases,
    failure_type_counts=failure_counts,
    attribution_counts=attribution_counts,
    replay_status="not_run",
    small_sample_status="not_run",
    notes=[
      "Offline case pack only; it does not call OpenCode/Codex/Claude.",
      "GT-derived oracle labels are allowed only as offline evaluation signal and are marked non-injectable.",
      "This case pack does not enable read_only memory injection.",
    ],
  )
  _write_json(out_dir / "manifest.json", manifest.model_dump())
  _write_json(out_dir / "case_pack_summary.json", manifest.model_dump())
  return manifest


def _write_per_case_files(out_dir: Path, cases: list[AgentEnhanceCase]) -> None:
  cases_dir = out_dir / "cases"
  cases_dir.mkdir(parents=True, exist_ok=True)
  for case in cases:
    case_dir = cases_dir / case.case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    _write_json(case_dir / "case.json", case.model_dump())
    _write_json(
      case_dir / "source_manifest.json",
      {
        "case_id": case.case_id,
        "source_paths": case.source_paths.__dict__,
        "prompt_replay": {
          "available": bool(case.source_paths.calls_index_path and case.prompt_hash),
          "calls_index_path": case.source_paths.calls_index_path,
          "prompt_hash": case.prompt_hash,
        },
      },
    )


def _replay_summary(cases: list[AgentEnhanceCase]) -> dict[str, Any]:
  calls_index_cases = [case for case in cases if case.source_paths.calls_index_path]
  prompt_hash_cases = [case for case in calls_index_cases if case.prompt_hash]
  return {
    "status": "not_run",
    "loaded_case_count": len(cases),
    "cases_with_calls_index": len(calls_index_cases),
    "cases_with_prompt_hash": len(prompt_hash_cases),
    "reason": "ReplayRuntime validation is a separate gate and has not been executed for this case pack.",
    "read_only_memory_injection_allowed": False,
  }


def _small_sample_summary() -> dict[str, Any]:
  return {
    "status": "not_run",
    "reason": "No small-sample OpenCode validation has been executed for this case pack.",
    "default_enable_allowed": False,
  }


def _write_hypothesis(path: Path, *, enhancement_id: str, cases: list[AgentEnhanceCase]) -> None:
  agent_cases = sum(1 for case in cases if case.attribution.agent_judge_relevant)
  text = "\n".join(
    [
      f"# {enhancement_id}",
      "",
      "Status: hypothesis",
      "",
      "This case pack was generated from existing VulnVersion result artifacts.",
      "It is evidence for analysis only and does not enable memory, skill, or prompt injection.",
      "",
      f"- total cases: {len(cases)}",
      f"- agent judge relevant cases: {agent_cases}",
      f"- non-agent planner/artifact cases: {len(cases) - agent_cases}",
      "",
      "Admission gates before promotion:",
      "",
      "1. ReplayRuntime must replay the relevant prompt/artifact records without unexplained miss.",
      "2. Small-sample OpenCode validation must report improved, regression, and unchanged cases.",
      "3. Leakage gate must confirm no GT affected tags, affected range, neighbor verdicts, or planner state enter prompts, memory content, or skill content.",
    ]
  )
  path.write_text(text + "\n", encoding="utf-8")


def _write_json(path: Path, value: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", encoding="utf-8") as f:
    for row in rows:
      f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _touch_jsonl(path: Path) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text("", encoding="utf-8")


def _count(values: Any) -> dict[str, int]:
  out: dict[str, int] = {}
  for value in values:
    key = str(value)
    out[key] = out.get(key, 0) + 1
  return dict(sorted(out.items()))
