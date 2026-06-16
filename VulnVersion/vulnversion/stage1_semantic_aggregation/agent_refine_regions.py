from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnversion.agent_harness.base import AgentRuntime
from vulnversion.opencode.agent import OpenCodeJSONParseError
from vulnversion.stage1_semantic_aggregation.artifacts import _append_trace, _jsonl_write, step1_paths
from vulnversion.stage1_semantic_aggregation.schema import (
  AgentRegionRefinementResponse,
  RegionRefinementResult,
  SemanticRegion,
)


PROMPT_NAME = "stage1_region_refinement"
PROMPT_VERSION = "v1"
MAX_SOURCE_REFS_PER_REGION = 5
MAX_SNIPPET_CHARS = 220


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
  if not path.exists() or not path.read_text(encoding="utf-8").strip():
    return []
  return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _safe_name(text: str) -> str:
  return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in text)


def _packet_id(cve_id: str) -> str:
  return "packet_0001"


def _trace_id(cve_id: str, packet_id: str) -> str:
  return f"{PROMPT_NAME}_{_safe_name(cve_id)}_{packet_id}"


def _system_prompt(*, enable_git_tools: bool = False) -> str:
  lines = [
    "You are a VulnVersion Step1 region-level patch semantic refinement agent.",
    "You must use the provided packet and the listed local fix evidence files.",
    "Do not infer affected versions. Do not create a tag plan.",
    "Output one strict JSON object only. No markdown. No code fences. The first character must be { and the last character must be }.",
  ]
  if enable_git_tools:
    lines.extend([
      "Read-only git and bash tools are enabled for evidence inspection.",
      "Allowed shell/git actions: git show, git diff, git log, git grep, git blame, git annotate, git cat-file, git ls-tree, git rev-parse, dir/ls/type/Get-Content/Select-String on listed artifact paths.",
      "Forbidden actions: editing files, deleting files, moving files, changing branches, checkout/reset/clean, package install, network fetch, broad repository exploration, affected-version search, release-tag planning.",
      "If source_refs are sampled or incomplete, inspect the listed fix_evidence files or run read-only git commands before classifying the region.",
      "Any extra git evidence you use must be reflected in evidence_refs_used or reasoning_summary.",
    ])
  return "\n".join(lines)


def _read_fix_evidence_manifest(path: Path) -> dict[str, Any]:
  if not path.exists():
    return {
      "available": False,
      "manifest_path": str(path),
      "reason": "fix_evidence_manifest_missing",
    }
  try:
    data = json.loads(path.read_text(encoding="utf-8"))
  except Exception as exc:
    return {
      "available": False,
      "manifest_path": str(path),
      "reason": f"fix_evidence_manifest_unreadable:{type(exc).__name__}",
    }
  if not isinstance(data, dict):
    return {
      "available": False,
      "manifest_path": str(path),
      "reason": "fix_evidence_manifest_not_object",
    }
  out = dict(data)
  out["available"] = True
  out["manifest_path"] = str(path)
  return out


def _source_ref_sample(region: SemanticRegion) -> list[dict[str, Any]]:
  refs = list(region.source_refs)
  if len(refs) > MAX_SOURCE_REFS_PER_REGION:
    head = refs[:3]
    tail = refs[-2:]
    refs = head + tail
  out: list[dict[str, Any]] = []
  for ref in refs:
    out.append({
      "ref_id": ref.ref_id,
      "kind": ref.kind,
      "change_type": ref.change_type,
      "file_path": ref.file_path,
      "function_context": ref.function_context,
      "hunk_header": ref.hunk_header,
      "old_line_no": ref.old_line_no,
      "new_line_no": ref.new_line_no,
      "snippet": ref.snippet[:MAX_SNIPPET_CHARS],
      "strength_hint": ref.strength_hint,
    })
  return out


def _region_for_packet(region: SemanticRegion) -> dict[str, Any]:
  return {
    "region_id": region.region_id,
    "commits": region.commits,
    "file_path": region.file_path,
    "function_context": region.function_context,
    "line_start": region.line_start,
    "line_end": region.line_end,
    "chunk_ids": region.chunk_ids,
    "compression_input_chunks": region.compression_input_chunks,
    "compression_ratio": region.compression_ratio,
    "patch_type": region.patch_type,
    "file_role": region.file_role,
    "removed_critical_sequence": region.removed_critical_sequence[:8],
    "added_guard_sequence": region.added_guard_sequence[:8],
    "nearby_dangerous_operation": region.nearby_dangerous_operation[:8],
    "root_cause_score": region.root_cause_score,
    "score_reasons": region.score_reasons,
    "evidence_strength": region.evidence_strength,
    "allowed_downstream_use": region.allowed_downstream_use,
    "risk_flags": region.risk_flags,
    "source_refs_sample": _source_ref_sample(region),
    "source_refs_total": len(region.source_refs),
  }


def _region_packet(
  *,
  cve_id: str,
  repo: str,
  cve_context: dict[str, Any],
  regions: list[SemanticRegion],
  fix_evidence: dict[str, Any],
) -> dict[str, Any]:
  return {
    "task": "step1_region_semantic_refinement",
    "schema_version": "step1_agent_region_refinement.v1",
    "cve_context": {"cve_id": cve_id, "repo": repo, **cve_context},
    "fix_commit_evidence": fix_evidence,
    "semantic_regions": [_region_for_packet(r) for r in regions],
    "strict_rules": [
      "Do not use affected versions or ground truth.",
      "Do not infer affected versions.",
      "Do not create a Step3 tag plan.",
      "Do not invent files, functions, tokens, or code not present in source_refs, fix_evidence files, or read-only git inspection.",
      "If source_refs_sample is incomplete, inspect fix_commit_evidence before deciding root-cause semantics.",
      "If evidence is insufficient, output unknown_region.",
    ],
    "required_output": {
      "schema_version": "step1_agent_region_refinement.v1",
      "cve_id": cve_id,
      "repo": repo,
      "region_results": [
        {
          "region_id": "<input region_id>",
          "region_role": "primary_root_cause_region|supporting_fix_region|context_region|noise_region|unknown_region|unknown_agent_failed",
          "evidence_strength": "weak|medium|strong",
          "allowed_downstream_use": ["prompt_context"],
          "root_cause_relation": "missing_guard|unsafe_operation|bounds_check|null_check|state_validation|type_confusion|integer_overflow|parser_state|memory_lifetime|permission_check|component_exposure|unknown",
          "root_cause_likelihood": 0.0,
          "fix_guard_likelihood": 0.0,
          "vulnerable_sequence_likelihood": 0.0,
          "vulnerable_sequence": [],
          "fix_guard_sequence": [],
          "evidence_refs_used": [],
          "reasoning_summary": "",
          "risk_flags": [],
        }
      ],
      "global_risk_flags": [],
    },
  }


def _prompt(packet: dict[str, Any]) -> str:
  return "\n".join([
    "Classify the semantic regions for Step1 root-cause-level VET preparation.",
    "Return strict JSON matching required_output. Do not output prose, markdown, or tool calls.",
    "",
    json.dumps(packet, ensure_ascii=False, indent=2),
  ])


def _normalize_allowed_downstream_use(values: Any) -> list[str]:
  mapping = {
    "context": "prompt_context",
    "prompt": "prompt_context",
    "prompt_context": "prompt_context",
    "priority": "priority_signal",
    "priority_signal": "priority_signal",
    "scheduling_priority": "priority_signal",
    "vet": "vet_candidate",
    "vet_candidate": "vet_candidate",
    "step2_direct_input": "vet_candidate",
    "root_cause_vet": "vet_candidate",
    "certificate": "certificate_candidate",
    "certificate_candidate": "certificate_candidate",
  }
  if isinstance(values, str):
    raw_values = [values]
  elif isinstance(values, list):
    raw_values = [str(v) for v in values if str(v).strip()]
  else:
    raw_values = []
  out: list[str] = []
  for raw in raw_values:
    normalized = mapping.get(raw.strip())
    if normalized and normalized not in out:
      out.append(normalized)
  return out or ["prompt_context"]


def _normalize_literal(value: Any, *, allowed: set[str], default: str) -> str:
  text = str(value or "").strip()
  return text if text in allowed else default


def _normalize_region_result(raw: dict[str, Any]) -> dict[str, Any]:
  result = dict(raw)
  result["region_role"] = _normalize_literal(
    result.get("region_role"),
    allowed={"primary_root_cause_region", "supporting_fix_region", "context_region", "noise_region", "unknown_region", "unknown_agent_failed"},
    default="unknown_region",
  )
  result["evidence_strength"] = _normalize_literal(
    result.get("evidence_strength"),
    allowed={"weak", "medium", "strong"},
    default="weak",
  )
  result["root_cause_relation"] = _normalize_literal(
    result.get("root_cause_relation"),
    allowed={
      "missing_guard",
      "unsafe_operation",
      "bounds_check",
      "null_check",
      "state_validation",
      "type_confusion",
      "integer_overflow",
      "parser_state",
      "memory_lifetime",
      "permission_check",
      "component_exposure",
      "unknown",
    },
    default="unknown",
  )
  result["allowed_downstream_use"] = _normalize_allowed_downstream_use(result.get("allowed_downstream_use"))
  return result


def _result_from_agent(
  *,
  cve_id: str,
  repo: str,
  packet_id: str,
  session_id: str | None,
  region: SemanticRegion,
  raw_result: dict[str, Any],
) -> RegionRefinementResult:
  return RegionRefinementResult(
    cve_id=cve_id,
    repo=repo,
    packet_id=packet_id,
    session_id=session_id,
    region_id=region.region_id,
    region_role=_normalize_region_result(raw_result).get("region_role") or "unknown_region",
    evidence_strength=_normalize_region_result(raw_result).get("evidence_strength") or "weak",
    allowed_downstream_use=list(_normalize_region_result(raw_result).get("allowed_downstream_use") or []),
    root_cause_relation=_normalize_region_result(raw_result).get("root_cause_relation") or "unknown",
    root_cause_likelihood=float(raw_result.get("root_cause_likelihood") or 0.0),
    fix_guard_likelihood=float(raw_result.get("fix_guard_likelihood") or 0.0),
    vulnerable_sequence_likelihood=float(raw_result.get("vulnerable_sequence_likelihood") or 0.0),
    vulnerable_sequence=list(raw_result.get("vulnerable_sequence") or []),
    fix_guard_sequence=list(raw_result.get("fix_guard_sequence") or []),
    evidence_refs_used=list(raw_result.get("evidence_refs_used") or []),
    reasoning_summary=str(raw_result.get("reasoning_summary") or ""),
    risk_flags=list(raw_result.get("risk_flags") or []),
  )


def _failure_results(
  *,
  cve_id: str,
  repo: str,
  packet_id: str,
  session_id: str | None,
  regions: list[SemanticRegion],
  error: str,
) -> list[RegionRefinementResult]:
  return [
    RegionRefinementResult(
      cve_id=cve_id,
      repo=repo,
      packet_id=packet_id,
      session_id=session_id,
      region_id=region.region_id,
      region_role="unknown_agent_failed",
      evidence_strength="weak",
      allowed_downstream_use=["prompt_context"],
      root_cause_relation="unknown",
      reasoning_summary=error,
      risk_flags=["agent_error"],
    )
    for region in regions
  ]


def refine_regions_with_agent(
  *,
  result_root: str | Path,
  repo: str,
  cve_id: str,
  cve_context: dict[str, Any],
  agent: AgentRuntime,
  resume: bool = True,
  timeout_s: float | None = None,
  enable_git_tools: bool = False,
) -> dict[str, str]:
  paths = step1_paths(result_root=result_root, repo=repo, cve_id=cve_id)
  regions = [SemanticRegion.model_validate(row) for row in _read_jsonl(paths["semantic_regions"])]
  paths["agent_calls_dir"].mkdir(parents=True, exist_ok=True)
  paths["output_dir"].mkdir(parents=True, exist_ok=True)
  packet_id = _packet_id(cve_id)
  trace_id = _trace_id(cve_id, packet_id)
  parsed_path = paths["agent_calls_dir"] / f"{trace_id}.parsed.json"
  response_path = paths["agent_calls_dir"] / f"{trace_id}.response.json"
  prompt_path = paths["agent_calls_dir"] / f"{trace_id}.prompt.txt"
  system_path = paths["agent_calls_dir"] / f"{trace_id}.system.txt"

  if resume and parsed_path.exists():
    parsed = json.loads(parsed_path.read_text(encoding="utf-8"))
    response = AgentRegionRefinementResponse.model_validate(parsed)
    rows = []
    by_region = {str(r.get("region_id")): r for r in response.region_results}
    for region in regions:
      rows.append(_result_from_agent(
        cve_id=cve_id,
        repo=repo,
        packet_id=packet_id,
        session_id=None,
        region=region,
        raw_result=by_region.get(region.region_id, {"region_role": "unknown_region"}),
      ))
    _jsonl_write(paths["region_refinements"], [r.model_dump() for r in rows])
    _append_trace(paths["trace"], "packet_resumed", {"repo": repo, "cve_id": cve_id, "packet_id": packet_id})
    return {name: str(path) for name, path in paths.items()}

  system = _system_prompt(enable_git_tools=enable_git_tools)
  fix_evidence = _read_fix_evidence_manifest(paths["fix_evidence_manifest"])
  packet = _region_packet(cve_id=cve_id, repo=repo, cve_context=cve_context, regions=regions, fix_evidence=fix_evidence)
  prompt = _prompt(packet)
  system_path.write_text(system, encoding="utf-8")
  prompt_path.write_text(prompt, encoding="utf-8")
  _append_trace(paths["trace"], "packet_started", {"repo": repo, "cve_id": cve_id, "packet_id": packet_id, "trace_id": trace_id})

  session_id: str | None = None
  try:
    session_id = agent.create_readonly_session(title=f"Step1 {repo} {cve_id}")
    raw = agent.run_json(
      session_id=session_id,
      prompt=prompt,
      system=system,
      tools={
        "git_show": bool(enable_git_tools),
        "git_grep": bool(enable_git_tools),
        "git_log": bool(enable_git_tools),
        "git_diff": bool(enable_git_tools),
        "bash": bool(enable_git_tools),
      },
      timeout_s=timeout_s,
      metadata={
        "stage": "stage1",
        "task_type": "region_refinement",
        "prompt_name": PROMPT_NAME,
        "prompt_version": PROMPT_VERSION,
        "enable_git_tools": enable_git_tools,
        "cve_id": cve_id,
        "repo": repo,
        "packet_id": packet_id,
      },
    )
    response_path.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
    response = AgentRegionRefinementResponse.model_validate(raw)
    parsed_path.write_text(json.dumps(response.model_dump(), ensure_ascii=False, indent=2), encoding="utf-8")
    by_region = {str(r.get("region_id")): r for r in response.region_results}
    rows = [
      _result_from_agent(
        cve_id=cve_id,
        repo=repo,
        packet_id=packet_id,
        session_id=session_id,
        region=region,
        raw_result=by_region.get(region.region_id, {"region_role": "unknown_region"}),
      )
      for region in regions
    ]
    _jsonl_write(paths["region_refinements"], [r.model_dump() for r in rows])
    _append_trace(paths["trace"], "packet_succeeded", {"repo": repo, "cve_id": cve_id, "packet_id": packet_id, "trace_id": trace_id})
  except Exception as exc:
    error = f"{type(exc).__name__}: {exc}"
    payload: dict[str, Any] = {"error": error}
    if isinstance(exc, OpenCodeJSONParseError) and exc.raw_text:
      payload["raw_text"] = exc.raw_text
    response_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    rows = _failure_results(cve_id=cve_id, repo=repo, packet_id=packet_id, session_id=session_id, regions=regions, error=error)
    _jsonl_write(paths["region_refinements"], [r.model_dump() for r in rows])
    _append_trace(paths["trace"], "packet_failed", {"repo": repo, "cve_id": cve_id, "packet_id": packet_id, "trace_id": trace_id, "error": error})

  return {name: str(path) for name, path in paths.items()}
