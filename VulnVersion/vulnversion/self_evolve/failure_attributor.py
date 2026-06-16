from __future__ import annotations

from typing import Any

from vulnversion.self_evolve.schema import FailureAttribution, STAGE3_AGENT_SOURCES


ERROR_RUN_STATUS = frozenset({"TIMEOUT", "AGENT_ERROR", "PARSE_ERROR", "JSON_ERROR", "UNKNOWN"})


def classify_stage3_row(row: dict[str, Any], *, affected_tags: set[str]) -> str | None:
  tag = str(row.get("tag") or "")
  verdict = row.get("verdict")
  run_status = str(row.get("run_status") or "").upper()
  is_affected = tag in affected_tags

  if run_status == "TIMEOUT":
    return "TIMEOUT"
  if run_status in {"AGENT_ERROR"}:
    return "AGENT_ERROR"
  if run_status in {"PARSE_ERROR", "JSON_ERROR"}:
    return "JSON_ERROR"
  if verdict is None or run_status in {"UNKNOWN"}:
    return "UNKNOWN"
  if verdict == "AFFECTED" and not is_affected:
    return "FP"
  if verdict != "AFFECTED" and is_affected:
    return "FN"
  return None


def attribute_stage3_row(row: dict[str, Any], *, failure_type: str) -> FailureAttribution:
  verdict_source = str(row.get("verdict_source") or "")
  run_status = str(row.get("run_status") or "").upper()

  if verdict_source in STAGE3_AGENT_SOURCES:
    if failure_type in {"TIMEOUT", "AGENT_ERROR", "JSON_ERROR", "UNKNOWN"} or run_status in ERROR_RUN_STATUS:
      return FailureAttribution(
        category="stage3_agent_runtime_or_schema",
        stage="stage3",
        agent_judge_relevant=True,
        reason=f"agent-sourced verdict failed with run_status={run_status or 'missing'}",
        suggested_next_step="inspect_trace_and_prompt_artifacts",
      )
    return FailureAttribution(
      category="stage3_agent_judge",
      stage="stage3",
      agent_judge_relevant=True,
      reason=f"agent-sourced single-tag verdict produced {failure_type}",
      suggested_next_step="inspect_evidence_predicates_and_guard_alignment",
    )

  if not verdict_source and run_status in {"OK", "PARTIAL_PARSE"} and _has_agent_evidence_shape(row):
    return FailureAttribution(
      category="stage3_legacy_agent_judge",
      stage="stage3",
      agent_judge_relevant=True,
      reason="legacy verdict row has no verdict_source but has agent-style evidence/predicate fields",
      suggested_next_step="inspect_evidence_predicates_and_guard_alignment",
    )

  if not verdict_source and run_status in {"PREFILTER", "BISECT_INFER", "INFERRED"}:
    return FailureAttribution(
      category="deterministic_stage3_legacy_non_agent",
      stage="stage3",
      agent_judge_relevant=False,
      reason=f"legacy row has run_status={run_status}, which belongs to deterministic prefilter/inference rather than direct agent judgement",
      suggested_next_step="inspect_planner_or_artifact_rule",
    )

  if verdict_source in {"prefilter", "fixed_segment_clear", "inferred_interval", "inferred_no_affected", "inferred_full_line_affected"}:
    return FailureAttribution(
      category="deterministic_stage3_non_agent",
      stage="stage3",
      agent_judge_relevant=False,
      reason=f"verdict_source={verdict_source} is deterministic planner/artifact output, not direct agent judgement",
      suggested_next_step="inspect_planner_or_artifact_rule",
    )

  return FailureAttribution(
    category="stage3_unknown_source",
    stage="stage3",
    agent_judge_relevant=False,
    reason=f"verdict_source={verdict_source or 'missing'} is not currently attributable to agent judge",
    suggested_next_step="inspect_verdict_source_taxonomy",
  )


def _has_agent_evidence_shape(row: dict[str, Any]) -> bool:
  for key in ("evidence_snippets", "matched_predicates", "failed_predicates", "triggered_guards"):
    value = row.get(key)
    if isinstance(value, list) and value:
      return True
  return bool(row.get("reasoning_summary"))
