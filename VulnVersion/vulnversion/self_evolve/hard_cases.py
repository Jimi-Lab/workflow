from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from vulnversion.self_evolve.failure_attributor import attribute_stage3_row, classify_stage3_row
from vulnversion.self_evolve.schema import AgentEnhanceCase, SourcePaths
from vulnversion.self_evolve.trace_loader import iter_jsonl, read_json


def iter_stage3_hard_cases(
  *,
  result_dir: Path,
  enhancement_id: str,
  include_non_agent: bool = True,
) -> list[AgentEnhanceCase]:
  source_paths = SourcePaths.from_result_dir(result_dir)
  eval_data = read_json(Path(source_paths.eval_path)) if source_paths.eval_path else {}
  affected_tags = set(_as_str_list(eval_data.get("gt_affected_tags"))) | set(_as_str_list(eval_data.get("mapped_gt_tags")))
  repo = result_dir.parent.name
  cve_id = result_dir.name
  verdict_path = result_dir / "per_tag_verdict.jsonl"
  cases: list[AgentEnhanceCase] = []

  for row in iter_jsonl(verdict_path):
    if row.get("_json_error"):
      failure_type = "JSON_ERROR"
      tag = None
    else:
      failure_type = classify_stage3_row(row, affected_tags=affected_tags)
      tag = _as_optional_str(row.get("tag"))
    if failure_type is None:
      continue

    attribution = attribute_stage3_row(row, failure_type=failure_type)
    if not include_non_agent and not attribution.agent_judge_relevant:
      continue

    case_id = _case_id(repo, cve_id, tag or f"line-{row.get('line_no', 'unknown')}", failure_type)
    cases.append(
      AgentEnhanceCase(
        case_id=case_id,
        enhancement_id=enhancement_id,
        repo=repo,
        cve_id=cve_id,
        stage="stage3",
        task_type="tag_verdict",
        failure_type=failure_type,
        attribution=attribution,
        source_paths=source_paths,
        tag=tag,
        line=_as_optional_str(row.get("line")),
        verdict=_as_optional_str(row.get("verdict")),
        run_status=_as_optional_str(row.get("run_status")),
        verdict_source=_as_optional_str(row.get("verdict_source")),
        confidence=_as_optional_float(row.get("confidence")),
        evidence_summary=_evidence_summary(row),
        offline_oracle={
          "offline_only": True,
          "oracle_label": "AFFECTED" if tag in affected_tags else "NOT_AFFECTED",
          "gt_value_not_injectable": True,
        },
        leakage_policy={
          "may_enter_prompt": False,
          "may_enter_memory_content": False,
          "may_enter_skill_content": False,
          "reason": "case pack may use offline oracle for evaluation only; GT labels are not verdict evidence",
        },
      )
    )
  return cases


def _evidence_summary(row: dict[str, Any]) -> dict[str, Any]:
  snippets = row.get("evidence_snippets")
  return {
    "matched_predicates": _as_str_list(row.get("matched_predicates")),
    "failed_predicates": _as_str_list(row.get("failed_predicates")),
    "triggered_guards": _as_str_list(row.get("triggered_guards")),
    "evidence_snippet_count": len(snippets) if isinstance(snippets, list) else 0,
    "has_reasoning_summary": bool(row.get("reasoning_summary")),
  }


def _case_id(repo: str, cve_id: str, tag: str, failure_type: str) -> str:
  raw = f"{repo}|{cve_id}|{tag}|{failure_type}"
  suffix = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
  safe_tag = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in tag)[:60]
  return f"{repo}__{cve_id}__{safe_tag}__{failure_type.lower()}__{suffix}"


def _as_optional_str(value: Any) -> str | None:
  if value is None:
    return None
  text = str(value)
  return text if text else None


def _as_str_list(value: Any) -> list[str]:
  if not isinstance(value, list):
    return []
  return [str(v) for v in value if v is not None]


def _as_optional_float(value: Any) -> float | None:
  if value is None:
    return None
  try:
    return float(value)
  except (TypeError, ValueError):
    return None
