from __future__ import annotations

import csv
import json
import shutil
import time
from pathlib import Path
from typing import Any

from vulngraph.agent_backends.base import AgentResponse
from vulngraph.agent_io.judge_contract import (
  lint_judge_output_v0,
  scan_forbidden_judge_fields,
  scan_forbidden_judge_output_dir,
)
from vulngraph.agent_io.judge_schema import parse_judge_output_v0


DEFAULT_JUDGE_V0_CVES = ["CVE-2020-1967", "CVE-2020-8231", "CVE-2020-11984"]
PROMPT_PATH = Path(__file__).resolve().parents[1] / "prompts" / "judge_v0.md"
SUMMARY_COLUMNS = [
  "cve_id",
  "backend_type",
  "parse_status",
  "contract_ok",
  "case_disposition",
  "candidate_count",
  "judged_count",
  "excluded_count",
  "prompt_bytes",
  "raw_response_bytes",
  "session_id",
  "taxonomy",
]


class FixtureJudgeBackend:
  backend_name = "fixture-judge-v0"
  backend_type = "fixture"

  def generate(self, prompt: str, context: dict[str, Any]) -> AgentResponse:
    judge_input = context.get("judge_input") if isinstance(context.get("judge_input"), dict) else {}
    candidates = list(judge_input.get("candidate_set") or [])
    attacker_available = bool((judge_input.get("cve_context") or {}).get("attacker_perspective_available"))
    judgments = []
    for index, candidate in enumerate(candidates, start=1):
      candidate_id = str(candidate.get("candidate_id") or "")
      candidate_source = str(candidate.get("candidate_source") or "")
      confidence = "low" if candidate_source == "fallback" else "medium"
      judgment = "uncertain_boundary" if candidate_source == "fallback" else "plausible_introduction_boundary"
      evidence_refs = list(candidate.get("evidence_refs") or [])[:2]
      judgments.append(
        {
          "candidate_id": candidate_id,
          "candidate_commit_sha": str(candidate.get("candidate_commit_sha") or ""),
          "rank": index,
          "judgment": judgment,
          "confidence": confidence,
          "evidence_refs_used": evidence_refs,
          "supporting_factors": ["root cause binding and SZZ evidence were provided by VulnGraph"],
          "contradicting_factors": list(candidate.get("risk_flags") or []),
          "risk_flags_considered": list(candidate.get("risk_flags") or []),
          "uncertainty_reasons": [] if candidate_source != "fallback" else ["fallback candidate requires later Judge review"],
        }
      )
    payload = {
      "schema_version": "judge_output_v0",
      "cve_id": str(judge_input.get("cve_id") or context.get("cve_id") or ""),
      "case_disposition": "ranked" if judgments else "insufficient_evidence",
      "candidate_judgments": judgments,
      "excluded_candidates": [],
      "judge_notes": {
        "attack_perspective_used": attacker_available,
        "root_cause_binding_used": True,
        "szz_evidence_used": True,
        "version_conversion_not_performed": True,
      },
    }
    return AgentResponse(
      raw_text=json.dumps(payload, ensure_ascii=False, indent=2),
      status="ok",
      backend_name=self.backend_name,
      backend_type=self.backend_type,
      usage={"prompt_chars": len(prompt), "session_id": f"fixture-{payload['cve_id']}"},
    )


def build_judge_input_v0(
  *,
  cve_id: str,
  judge_packet_root: str | Path,
  detailed_evidence_root: str | Path,
  slimming_root: str | Path,
  dataset: str | Path,
) -> dict[str, Any]:
  judge_case = Path(judge_packet_root) / cve_id / "judge_blind_input_packet.json"
  evidence_case = Path(detailed_evidence_root) / cve_id / "judge_szz_evidence_packet.json"
  audit_evidence_case = Path(detailed_evidence_root) / cve_id / "szz_evidence_audit_packet.json"
  blind = _read_json(judge_case)
  evidence = _read_json(evidence_case)
  audit_evidence = _read_json_default(audit_evidence_case, {})
  dataset_record = _dataset_record(_read_json_default(Path(dataset), {}), cve_id)
  repo = str(blind.get("repo") or dataset_record.get("repo") or "")
  candidates = [_candidate_model_view(item, evidence, audit_evidence) for item in blind.get("candidates", []) or []]
  root_material = _root_cause_material(Path(slimming_root), cve_id)
  attacker_perspective = _attacker_perspective(root_material)
  attacker_available = any(str(value).strip() for value in attacker_perspective.values())
  root_digest = root_material["digest"]
  input_packet = {
    "schema_version": "judge_input_v0",
    "cve_id": cve_id,
    "cve_context": {
      "cve_id": cve_id,
      "repo": repo,
      "cwe": str(dataset_record.get("CWE") or dataset_record.get("cwe") or ""),
      "description": _compact_text(_description(dataset_record), 700),
      "fix_commit_ids": sorted({str(item.get("fix_commit_id") or "") for item in candidates if item.get("fix_commit_id")}),
      "attacker_perspective": attacker_perspective,
      "attacker_perspective_available": attacker_available,
      "attacker_perspective_unavailable_reason": "" if attacker_available else "no_structured_attacker_perspective_fields",
    },
    "root_cause_context": {
      "hypothesis_id": sorted({ref for item in candidates for ref in item.get("root_cause_binding_refs", [])}),
      "root_cause_summary": root_digest["root_cause_summary"],
      "root_cause_digest": root_digest["root_cause_digest"],
      "predicate_digest": root_digest["predicate_digest"],
      "fix_digest": root_digest["fix_digest"],
      "code_anchor_summaries": root_digest["code_anchor_summaries"],
      "vulnerable_predicates": sorted({ref for item in candidates for ref in item.get("vulnerable_predicate_refs", [])}),
      "fix_predicates": sorted({ref for item in candidates for ref in item.get("fix_predicate_refs", [])}),
      "evidence_refs": sorted({ref for item in candidates for ref in item.get("evidence_refs", []) if ref.startswith("root_cause:")}),
      "patch_hunk_refs": sorted({str(item.get("patch_family_id") or "") for item in candidates if item.get("patch_family_id")}),
    },
    "candidate_set": candidates,
    "szz_evidence_cards": [_szz_card(item, evidence, audit_evidence) for item in candidates],
    "forbidden": [
      "validated_bic",
      "correct_bic",
      "affected_versions",
      "bic",
      "ground_truth",
      "gt_release_tags",
      "overlap_release_tags",
      "release_metrics",
      "precision",
      "recall",
      "f1",
      "exact_match",
    ],
    "lifecycle": "raw_candidate",
  }
  scan = scan_forbidden_judge_fields(input_packet)
  if not scan["ok"]:
    raise ValueError(f"judge input contains forbidden keys: {scan['violations']}")
  return input_packet


def run_judge_v0_batch(
  *,
  cve_ids: list[str],
  judge_packet_root: str | Path,
  detailed_evidence_root: str | Path,
  slimming_root: str | Path,
  dataset: str | Path,
  out_dir: str | Path,
  backend: Any,
  repair_retries: int = 1,
  reset: bool = False,
) -> dict[str, Any]:
  output_root = Path(out_dir)
  if reset and output_root.exists():
    shutil.rmtree(output_root)
  output_root.mkdir(parents=True, exist_ok=True)
  started = time.monotonic()
  rows: list[dict[str, Any]] = []
  results: list[dict[str, Any]] = []
  for cve_id in cve_ids:
    result = run_judge_v0_for_cve(
      cve_id=cve_id,
      judge_packet_root=judge_packet_root,
      detailed_evidence_root=detailed_evidence_root,
      slimming_root=slimming_root,
      dataset=dataset,
      out_dir=output_root / cve_id,
      backend=backend,
      repair_retries=repair_retries,
    )
    results.append(result)
    rows.append(_summary_row(result))
  _write_csv(output_root / "per_cve_judge_summary.csv", rows, SUMMARY_COLUMNS)
  forbidden_scan = scan_forbidden_judge_output_dir(output_root)
  _write_json(output_root / "forbidden_field_scan.json", forbidden_scan)
  summary = _batch_summary(results, forbidden_scan, duration_s=time.monotonic() - started)
  _write_json(output_root / "summary.json", summary)
  (output_root / "judge_v0_report.md").write_text(_render_report(summary, results), encoding="utf-8")
  return summary


def run_judge_v0_for_cve(
  *,
  cve_id: str,
  judge_packet_root: str | Path,
  detailed_evidence_root: str | Path,
  slimming_root: str | Path,
  dataset: str | Path,
  out_dir: str | Path,
  backend: Any,
  repair_retries: int = 1,
) -> dict[str, Any]:
  out_path = Path(out_dir)
  out_path.mkdir(parents=True, exist_ok=True)
  judge_input = build_judge_input_v0(
    cve_id=cve_id,
    judge_packet_root=judge_packet_root,
    detailed_evidence_root=detailed_evidence_root,
    slimming_root=slimming_root,
    dataset=dataset,
  )
  prompt = render_judge_prompt(judge_input)
  _write_json(out_path / "judge_input_v0.json", judge_input)
  (out_path / "judge_prompt.txt").write_text(prompt, encoding="utf-8")
  response = backend.generate(
    prompt,
    {
      "cve_id": cve_id,
      "judge_input": judge_input,
      "system_prompt": "You are VulnGraph Judge Agent v0. Return strict JSON only.",
    },
  )
  raw_text = response.raw_text
  initial_raw_text = raw_text
  initial_session_id = (response.usage or {}).get("session_id", "")
  parse_result = parse_judge_output_v0(raw_text) if response.status == "ok" else None
  contract = lint_judge_output_v0(parse_result.data, judge_input) if parse_result and parse_result.ok and parse_result.data else None
  retry_used = False
  if response.status == "ok" and (not parse_result or not parse_result.ok or not contract or not contract.ok) and repair_retries > 0:
    retry_used = True
    repair_prompt = _repair_prompt(raw_text, parse_result.error if parse_result else response.error, contract.to_dict() if contract else {}, judge_input)
    (out_path / "raw_response.initial.txt").write_text(initial_raw_text, encoding="utf-8")
    (out_path / "repair_prompt.txt").write_text(repair_prompt, encoding="utf-8")
    response = backend.generate(
      repair_prompt,
      {
        "cve_id": cve_id,
        "judge_input": {"cve_id": cve_id, "candidate_ids": [item["candidate_id"] for item in judge_input.get("candidate_set", [])]},
        "system_prompt": "Repair the previous Judge v0 JSON only. Do not add new evidence.",
      },
    )
    raw_text = response.raw_text
    (out_path / "raw_response.repair.txt").write_text(raw_text, encoding="utf-8")
    parse_result = parse_judge_output_v0(raw_text) if response.status == "ok" else None
    contract = lint_judge_output_v0(parse_result.data, judge_input) if parse_result and parse_result.ok and parse_result.data else None

  (out_path / "raw_response.txt").write_text(raw_text, encoding="utf-8")
  if parse_result and parse_result.ok and parse_result.data:
    _write_json(out_path / "parsed_judge_output.json", parse_result.data)
  else:
    _write_json(
      out_path / "parse_error.json",
      {
        "status": response.status,
        "error": response.error or (parse_result.error if parse_result else "backend_failed"),
        "empty": bool(parse_result.empty if parse_result else response.status == "empty"),
      },
    )
  contract_dict = contract.to_dict() if contract else {"ok": False, "errors": [response.error or "parse_failed"], "taxonomy": {"parse_failed": 1}}
  _write_json(out_path / "judge_contract_lint.json", contract_dict)
  judge_result = _judge_result(cve_id, judge_input, response, parse_result, contract_dict, retry_used, initial_session_id)
  _write_json(out_path / "judge_result.json", judge_result)
  return judge_result


def render_judge_prompt(judge_input: dict[str, Any]) -> str:
  template = PROMPT_PATH.read_text(encoding="utf-8")
  return template + "\n" + json.dumps(judge_input, ensure_ascii=False, indent=2)


def _candidate_model_view(candidate: dict[str, Any], evidence_packet: dict[str, Any], audit_evidence: dict[str, Any]) -> dict[str, Any]:
  candidate_id = _candidate_id(candidate)
  evidence = _match_evidence(candidate, evidence_packet, audit_evidence)
  first_provenance = _first_provenance(candidate)
  candidate_role = str(first_provenance.get("role") or "")
  confidence_features = [str(item) for item in evidence.get("confidence_features") or []]
  related_role_features, evidence_confidence_features = _split_confidence_features(confidence_features, candidate_role)
  evidence_refs = [f"candidate:{candidate_id}", f"szz:{candidate_id}"]
  if candidate.get("root_cause_hypothesis_bindings"):
    evidence_refs.append(f"root_cause:{candidate_id}")
  return {
    "candidate_id": candidate_id,
    "candidate_commit_sha": str(candidate.get("candidate_commit_sha") or ""),
    "candidate_source": str(candidate.get("candidate_source") or ""),
    "evidence_level": str(candidate.get("evidence_level") or ""),
    "lifecycle": "raw_candidate",
    "candidate_anchor_role": candidate_role,
    "candidate_selection_mode": str(first_provenance.get("selection_mode") or ""),
    "related_role_features": related_role_features,
    "evidence_confidence_features": evidence_confidence_features,
    "function_id": str(candidate.get("function_id") or ""),
    "function_name": str(candidate.get("function_name") or ""),
    "path_before": str(candidate.get("path_before") or ""),
    "old_line_start": int(candidate.get("old_line_start") or 0),
    "old_line_end": int(candidate.get("old_line_end") or 0),
    "old_line_text": _compact_text(str(candidate.get("old_line_text") or ""), 160),
    "line_text_hash": str(candidate.get("old_line_text_hash") or ""),
    "fix_commit_id": str(candidate.get("fix_commit_id") or ""),
    "patch_family_id": str(candidate.get("patch_family_id") or ""),
    "root_cause_binding_refs": [str(item) for item in candidate.get("root_cause_hypothesis_bindings") or []],
    "vulnerable_predicate_refs": [str(item) for item in candidate.get("vulnerable_predicate_bindings") or []],
    "fix_predicate_refs": [str(item) for item in candidate.get("fix_predicate_bindings") or []],
    "risk_flags": sorted(set(str(item) for item in (candidate.get("risk_flags") or []) + (evidence.get("risk_flags") or []))),
    "evidence_refs": evidence_refs,
  }


def _szz_card(candidate: dict[str, Any], evidence_packet: dict[str, Any], audit_evidence: dict[str, Any]) -> dict[str, Any]:
  evidence = _match_evidence(candidate, evidence_packet, audit_evidence)
  variants = _variant_map(evidence)
  candidate_id = str(candidate.get("candidate_id") or "")
  release_summary = evidence.get("release_reachability_summary") if isinstance(evidence.get("release_reachability_summary"), dict) else {}
  return {
    "candidate_id": candidate_id,
    "candidate_commit_sha": candidate.get("candidate_commit_sha"),
    "variant_agreement": (evidence.get("blame_variants") or {}).get("variant_agreement", ""),
    "canonical_blame_commit_sha": (evidence.get("blame_variants") or {}).get("canonical_blame_commit_sha", ""),
    "normal_blame_sha": variants.get("normal", ""),
    "ignore_whitespace_blame_sha": variants.get("w", ""),
    "move_copy_blame_sha": variants.get("w_M_C") or variants.get("M") or variants.get("C") or "",
    "line_survival_status": (evidence.get("line_survival_evidence") or {}).get("line_survival_status", ""),
    "candidate_is_ancestor_of_fix": (evidence.get("commit_relation_evidence") or {}).get("candidate_is_ancestor_of_fix"),
    "candidate_in_fix_series_hint": (evidence.get("commit_relation_evidence") or {}).get("candidate_in_fix_series_hint"),
    "boundary_marker": "boundary_candidate_commit" in set(evidence.get("risk_flags") or []),
    "merge_candidate": (evidence.get("commit_relation_evidence") or {}).get("candidate_is_merge_commit"),
    "release_reachability_summary": {
      "reachable_release_tag_count": release_summary.get("reachable_release_tag_count", 0),
      "release_line_count_estimate": release_summary.get("release_line_count_estimate", 0),
      "too_broad": bool(release_summary.get("release_reachability_too_broad")),
      "artifact_ref": release_summary.get("release_reachability_artifact_ref", ""),
    },
    "evidence_refs": [f"szz:{candidate_id}", f"candidate:{candidate_id}"],
  }


def _match_evidence(candidate: dict[str, Any], evidence_packet: dict[str, Any], audit_evidence: dict[str, Any]) -> dict[str, Any]:
  sha = str(candidate.get("candidate_commit_sha") or "")
  candidate_id = _candidate_id(candidate)
  for packet in (audit_evidence, evidence_packet):
    for item in packet.get("candidates", []) or []:
      identity = item.get("candidate_identity") if isinstance(item.get("candidate_identity"), dict) else {}
      if str(identity.get("candidate_commit_sha") or "") == sha and (
        not candidate_id or candidate_id in {str(identity.get("candidate_id") or ""), *_list(identity.get("candidate_ids"))}
      ):
        return item
  return {}


def _variant_map(evidence: dict[str, Any]) -> dict[str, str]:
  variants = ((evidence.get("blame_variants") or {}).get("variants") or []) if isinstance(evidence.get("blame_variants"), dict) else []
  return {str(item.get("variant") or ""): str(item.get("blamed_commit_sha") or "") for item in variants if isinstance(item, dict)}


def _judge_result(
  cve_id: str,
  judge_input: dict[str, Any],
  response: AgentResponse,
  parse_result: Any,
  contract: dict[str, Any],
  retry_used: bool,
  initial_session_id: str,
) -> dict[str, Any]:
  parsed = parse_result.data if parse_result and parse_result.ok else {}
  judgments = parsed.get("candidate_judgments", []) if isinstance(parsed, dict) else []
  excluded = parsed.get("excluded_candidates", []) if isinstance(parsed, dict) else []
  cve_context = judge_input.get("cve_context") if isinstance(judge_input.get("cve_context"), dict) else {}
  return {
    "cve_id": cve_id,
    "backend_name": response.backend_name,
    "backend_type": response.backend_type,
    "status": response.status,
    "parse_status": parse_result.format if parse_result and parse_result.ok else ("empty" if parse_result and parse_result.empty else "parse_error" if response.status == "ok" else response.status),
    "contract_ok": bool(contract.get("ok")),
    "case_disposition": parsed.get("case_disposition", "") if isinstance(parsed, dict) else "",
    "candidate_count": len(judge_input.get("candidate_set", []) or []),
    "candidate_rankings": [
      {
        "candidate_id": item.get("candidate_id"),
        "candidate_commit_sha": item.get("candidate_commit_sha"),
        "rank": item.get("rank"),
        "judgment": item.get("judgment"),
        "confidence": item.get("confidence"),
      }
      for item in judgments
    ],
    "excluded_count": len(excluded),
    "attacker_context_available": bool(cve_context.get("attacker_perspective_available")),
    "attacker_context_unavailable_reason": str(cve_context.get("attacker_perspective_unavailable_reason") or ""),
    "attack_perspective_used": bool((parsed.get("judge_notes") or {}).get("attack_perspective_used")) if isinstance(parsed, dict) else False,
    "prompt_bytes": len(json.dumps(judge_input, ensure_ascii=False).encode("utf-8")),
    "raw_response_bytes": len(response.raw_text.encode("utf-8")),
    "session_id": (response.usage or {}).get("session_id", ""),
    "initial_session_id": initial_session_id,
    "retry_used": retry_used,
    "contract_taxonomy": contract.get("taxonomy", {}),
    "lifecycle": "raw_candidate_judged" if contract.get("ok") else "raw_candidate_judge_rejected",
    "forbidden_keys_present": not scan_forbidden_judge_fields(parsed or contract).get("ok", True),
  }


def _batch_summary(results: list[dict[str, Any]], forbidden_scan: dict[str, Any], *, duration_s: float) -> dict[str, Any]:
  return {
    "cases_total": len(results),
    "parse_ok_count": sum(1 for item in results if item.get("parse_status") in {"json", "fenced_json"}),
    "contract_ok_count": sum(1 for item in results if item.get("contract_ok")),
    "backend_failed_count": sum(1 for item in results if item.get("status") == "failed"),
    "empty_message_count": sum(1 for item in results if item.get("parse_status") == "empty"),
    "forbidden_field_scan_ok": bool(forbidden_scan.get("ok")),
    "forbidden_violation_count": int(forbidden_scan.get("violation_count") or 0),
    "attacker_context_available_count": sum(1 for item in results if item.get("attacker_context_available")),
    "attacker_context_unavailable_count": sum(1 for item in results if not item.get("attacker_context_available")),
    "attacker_unavailable_but_used_count": sum(1 for item in results if not item.get("attacker_context_available") and item.get("attack_perspective_used")),
    "model_invocation_count": sum(1 for item in results if item.get("backend_type") != "fixture"),
    "judge_invocation_count": sum(1 for item in results if item.get("backend_type") != "fixture"),
    "lifecycle": "raw_candidate_judged",
    "duration_s": round(duration_s, 6),
    "results": results,
  }


def _summary_row(result: dict[str, Any]) -> dict[str, Any]:
  return {
    "cve_id": result.get("cve_id", ""),
    "backend_type": result.get("backend_type", ""),
    "parse_status": result.get("parse_status", ""),
    "contract_ok": result.get("contract_ok", False),
    "case_disposition": result.get("case_disposition", ""),
    "candidate_count": result.get("candidate_count", 0),
    "judged_count": len(result.get("candidate_rankings") or []),
    "excluded_count": int(result.get("excluded_count") or 0),
    "prompt_bytes": result.get("prompt_bytes", 0),
    "raw_response_bytes": result.get("raw_response_bytes", 0),
    "session_id": result.get("session_id", ""),
    "taxonomy": json.dumps(result.get("contract_taxonomy", {}), ensure_ascii=False, sort_keys=True),
  }


def _render_report(summary: dict[str, Any], results: list[dict[str, Any]]) -> str:
  lines = [
    "# VulnGraph Judge Agent v0 Clean Smoke",
    "",
    "Judge v0 ranks evidence-backed raw candidates only. It does not output BICs and does not perform affected-version conversion.",
    "",
    f"- cases_total: {summary['cases_total']}",
    f"- parse_ok_count: {summary['parse_ok_count']}",
    f"- contract_ok_count: {summary['contract_ok_count']}",
    f"- backend_failed_count: {summary['backend_failed_count']}",
    f"- empty_message_count: {summary['empty_message_count']}",
    f"- forbidden_field_scan_ok: {summary['forbidden_field_scan_ok']}",
    f"- attacker_context_available_count: {summary.get('attacker_context_available_count', 0)}",
    f"- attacker_context_unavailable_count: {summary.get('attacker_context_unavailable_count', 0)}",
    f"- attacker_unavailable_but_used_count: {summary.get('attacker_unavailable_but_used_count', 0)}",
    f"- lifecycle: {summary['lifecycle']}",
    "",
    "| CVE | parse | contract | disposition | candidates | rankings |",
    "|---|---|---:|---|---:|---|",
  ]
  for item in results:
    lines.append(
      f"| {item['cve_id']} | {item['parse_status']} | {item['contract_ok']} | {item['case_disposition']} | {item['candidate_count']} | `{item['candidate_rankings']}` |"
    )
  return "\n".join(lines) + "\n"


def _repair_prompt(raw_text: str, parse_error: str | None, contract: dict[str, Any], judge_input: dict[str, Any]) -> str:
  allowed_candidates = [
    {
      "candidate_id": item.get("candidate_id"),
      "candidate_commit_sha": item.get("candidate_commit_sha"),
      "evidence_refs": item.get("evidence_refs", []),
      "risk_flags": item.get("risk_flags", []),
      "candidate_source": item.get("candidate_source", ""),
    }
    for item in judge_input.get("candidate_set", []) or []
  ]
  example_candidate = allowed_candidates[0] if allowed_candidates else {"candidate_id": "", "candidate_commit_sha": "", "evidence_refs": []}
  return "\n".join(
    [
      "Repair the previous Judge v0 JSON output. Return JSON only.",
      "Do not add new candidates, SHAs, paths, lines, version tags, BIC fields, or affected-version fields.",
      "Use only the allowed candidate IDs, commit SHAs, and evidence refs listed below.",
      "Allowed case_disposition values: ranked, uncertain, insufficient_evidence.",
      "Allowed judgment values: plausible_introduction_boundary, unlikely_boundary, uncertain_boundary.",
      "Do not use shorthand values such as uncertain; use uncertain_boundary.",
      "Allowed confidence values: high, medium, low.",
      "If a candidate has conflict risk flags such as move_copy_sensitive_blame, whitespace_sensitive_blame, boundary_candidate_commit, root_candidate_commit, merge_candidate, or candidate_not_ancestor_of_fix, set judgment=uncertain_boundary unless you explicitly include those flags in risk_flags_considered/contradicting_factors and explain with evidence refs why the candidate remains rankable.",
      "Required minimal JSON skeleton:",
      json.dumps(
        {
          "schema_version": "judge_output_v0",
          "cve_id": judge_input.get("cve_id", ""),
          "case_disposition": "ranked | uncertain | insufficient_evidence",
          "candidate_judgments": [
            {
              "candidate_id": example_candidate.get("candidate_id", ""),
              "candidate_commit_sha": example_candidate.get("candidate_commit_sha", ""),
              "rank": 1,
              "judgment": "plausible_introduction_boundary | unlikely_boundary | uncertain_boundary",
              "confidence": "high | medium | low",
              "evidence_refs_used": example_candidate.get("evidence_refs", []),
              "supporting_factors": [],
              "contradicting_factors": [],
              "risk_flags_considered": [],
              "uncertainty_reasons": [],
            }
          ],
          "excluded_candidates": [],
          "judge_notes": {
            "attack_perspective_used": bool((judge_input.get("cve_context") or {}).get("attacker_perspective_available")),
            "root_cause_binding_used": True,
            "szz_evidence_used": True,
            "version_conversion_not_performed": True,
          },
        },
        ensure_ascii=False,
        indent=2,
      ),
      "Allowed candidates:",
      json.dumps(allowed_candidates, ensure_ascii=False, indent=2),
      f"Parse error: {parse_error or ''}",
      "Contract errors:",
      json.dumps(contract, ensure_ascii=False, indent=2),
      "Previous output:",
      raw_text[:12000],
    ]
  )


def _root_cause_material(slimming_root: Path, cve_id: str) -> dict[str, Any]:
  parsed = _root_cause_parsed_output(slimming_root, cve_id)
  prompt_excerpt = _root_cause_excerpt(slimming_root, cve_id)
  if parsed:
    return {
      "source": "parsed_output",
      "digest": _digest_from_parsed_output(parsed),
      "attacker_text": prompt_excerpt,
    }
  model_view = _model_view_from_prompt(prompt_excerpt)
  if model_view:
    return {
      "source": "model_view",
      "digest": _digest_from_model_view(model_view),
      "attacker_text": json.dumps(model_view, ensure_ascii=False),
    }
  return {
    "source": "prompt_excerpt",
    "digest": _digest_from_text(prompt_excerpt),
    "attacker_text": prompt_excerpt,
  }


def _root_cause_excerpt(slimming_root: Path, cve_id: str) -> str:
  path = slimming_root / "shadow_model_views" / "root_cause" / f"{cve_id}.prompt.after.txt"
  if not path.exists():
    return ""
  text = path.read_text(encoding="utf-8", errors="ignore")
  marker = "ROOT_CAUSE_MODEL_VIEW:"
  if marker in text:
    return text.split(marker, 1)[-1][:12000]
  return text[:2500]


def _root_cause_parsed_output(slimming_root: Path, cve_id: str) -> dict[str, Any]:
  candidates = [
    slimming_root.parent / "root-cause-v2-optimized-contract-10" / cve_id / "parsed_output.json",
    slimming_root.parent / "root-cause-v2-semantic-baseline-10" / cve_id / "parsed_output.json",
  ]
  for path in candidates:
    if path.exists():
      return _read_json(path)
  return {}


def _digest_from_parsed_output(parsed: dict[str, Any]) -> dict[str, Any]:
  hypotheses = [
    _compact_text(" ".join(str(item.get(key) or "") for key in ("summary", "mechanism") if item.get(key)), 500)
    for item in parsed.get("root_cause_hypotheses", []) or []
    if isinstance(item, dict)
  ]
  vulnerable = [
    _compact_text(str(item.get("description") or item.get("statement") or ""), 320)
    for item in parsed.get("vulnerable_predicates", []) or []
    if isinstance(item, dict)
  ]
  fixes = [
    _compact_text(str(item.get("description") or item.get("statement") or ""), 320)
    for item in parsed.get("fix_predicates", []) or []
    if isinstance(item, dict)
  ]
  anchors = []
  for item in parsed.get("code_anchors", []) or []:
    if not isinstance(item, dict):
      continue
    anchors.append(
      _compact_text(
        f"{item.get('anchor_id') or ''} {item.get('path') or ''} {item.get('function') or item.get('function_name') or ''} {item.get('patch_hunk_id') or ''}",
        260,
      )
    )
  summary = hypotheses[0] if hypotheses else "No clean root cause hypothesis digest available."
  return _clean_digest(
    {
      "root_cause_summary": summary,
      "root_cause_digest": hypotheses[:5],
      "predicate_digest": vulnerable[:8],
      "fix_digest": fixes[:8],
      "code_anchor_summaries": anchors[:8],
    }
  )


def _digest_from_model_view(model_view: dict[str, Any]) -> dict[str, Any]:
  patch = model_view.get("patch_evidence") if isinstance(model_view.get("patch_evidence"), dict) else {}
  hunks = []
  for hunk in patch.get("patch_hunks", []) or []:
    if not isinstance(hunk, dict):
      continue
    hunks.append(
      _compact_text(
        f"{hunk.get('patch_hunk_id') or ''} {hunk.get('path') or ''} {hunk.get('function') or ''} old:{hunk.get('old_key_lines') or ''} new:{hunk.get('new_key_lines') or ''}",
        360,
      )
    )
  return _clean_digest(
    {
      "root_cause_summary": hunks[0] if hunks else "No clean root cause hypothesis digest available.",
      "root_cause_digest": hunks[:5],
      "predicate_digest": [],
      "fix_digest": [],
      "code_anchor_summaries": hunks[:8],
    }
  )


def _digest_from_text(text: str) -> dict[str, Any]:
  lines = [
    _compact_text(line, 240)
    for line in text.splitlines()
    if line.strip() and not _contains_pollution_token(line)
  ]
  return _clean_digest(
    {
      "root_cause_summary": lines[0] if lines else "No clean root cause hypothesis digest available.",
      "root_cause_digest": lines[:5],
      "predicate_digest": [],
      "fix_digest": [],
      "code_anchor_summaries": [],
    }
  )


def _model_view_from_prompt(text: str) -> dict[str, Any]:
  stripped = text.strip()
  if not stripped.startswith("{"):
    return {}
  try:
    parsed = json.loads(stripped)
  except json.JSONDecodeError:
    return {}
  return parsed if isinstance(parsed, dict) else {}


def _clean_digest(digest: dict[str, Any]) -> dict[str, Any]:
  output: dict[str, Any] = {}
  for key, value in digest.items():
    if isinstance(value, list):
      output[key] = [_strip_polluted_text(item) for item in value if _strip_polluted_text(item)]
    else:
      cleaned = _strip_polluted_text(str(value or ""))
      output[key] = cleaned or "No clean root cause hypothesis digest available."
  return output


def _strip_polluted_text(text: str) -> str:
  if _contains_pollution_token(text):
    return ""
  return _compact_text(text, 900)


def _contains_pollution_token(text: str) -> bool:
  lowered = str(text).lower()
  return any(
    token in lowered
    for token in (
      "schema_version",
      "ownership_contract",
      "wrapper_owned_facts",
      "model_owned_judgments",
      "raw_context_summary",
    )
  )


def _attacker_perspective(root_material: dict[str, Any]) -> dict[str, str]:
  text = str(root_material.get("attacker_text") or "")
  return {
    "trigger": _attacker_field(text, "trigger"),
    "exploit_precondition": _attacker_field(text, "exploit_precondition"),
    "sink": _attacker_field(text, "sink"),
    "impact_path": _attacker_field(text, "impact_path"),
    "attacker_controlled_input": _attacker_field(text, "attacker_controlled_input"),
  }


def _attacker_field(text: str, name: str) -> str:
  lowered = name.lower()
  for line in text.splitlines():
    clean = line.strip().strip('",')
    if clean.lower().startswith(lowered + ":"):
      return _compact_text(clean.split(":", 1)[-1], 260)
    json_prefix = f'"{lowered}"'
    if clean.lower().startswith(json_prefix) and ":" in clean:
      return _compact_text(clean.split(":", 1)[-1].strip().strip('",'), 260)
  return ""


def _split_confidence_features(features: list[str], candidate_role: str) -> tuple[list[str], list[str]]:
  related: list[str] = []
  evidence: list[str] = []
  own_role_feature = f"{candidate_role}_role" if candidate_role else ""
  for feature in features:
    if feature.endswith("_role"):
      if feature != own_role_feature:
        related.append(feature)
      continue
    evidence.append(feature)
  return related, evidence


def _first_provenance(candidate: dict[str, Any]) -> dict[str, Any]:
  trace = candidate.get("blame_trace") if isinstance(candidate.get("blame_trace"), dict) else {}
  values = trace.get("line_provenance") if isinstance(trace.get("line_provenance"), list) else []
  for item in values:
    if isinstance(item, dict):
      return item
  return {}


def _candidate_id(candidate: dict[str, Any]) -> str:
  values = candidate.get("candidate_ids")
  if isinstance(values, list) and values:
    return str(values[0])
  return str(candidate.get("candidate_id") or candidate.get("selected_anchor_id") or candidate.get("fallback_anchor_id") or "")


def _description(record: dict[str, Any]) -> str:
  for key in ("description", "Description", "cve_description", "summary"):
    if record.get(key):
      return str(record[key])
  return ""


def _dataset_record(records: dict[str, Any], cve_id: str) -> dict[str, Any]:
  record = records.get(cve_id, {}) if isinstance(records, dict) else {}
  return record if isinstance(record, dict) else {}


def _compact_text(value: str, limit: int) -> str:
  text = " ".join(str(value or "").split())
  return text if len(text) <= limit else text[: limit - 3] + "..."


def _list(value: Any) -> list[str]:
  if value is None:
    return []
  if isinstance(value, list):
    return [str(item) for item in value if item is not None]
  return [str(value)]


def _read_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"expected JSON object: {path}")
  return data


def _read_json_default(path: Path, default: dict[str, Any]) -> dict[str, Any]:
  if not path.exists():
    return default
  return _read_json(path)


def _write_json(path: Path, data: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    for row in rows:
      writer.writerow({column: _csv_value(row.get(column, "")) for column in columns})


def _csv_value(value: Any) -> Any:
  if isinstance(value, (list, dict)):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
  return value
