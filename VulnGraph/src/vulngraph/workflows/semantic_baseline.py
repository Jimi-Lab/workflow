from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.agent_backends import RootCauseBackend
from vulngraph.builder import build_dataset_graph, build_patch_graph_from_repo
from vulngraph.services import VulnGraphClient

from .root_cause import run_root_cause_batch


DEFAULT_SEMANTIC_BASELINE_CVES = [
  "CVE-2020-14212",
  "CVE-2020-19667",
  "CVE-2020-8231",
  "CVE-2020-11984",
  "CVE-2022-0171",
  "CVE-2022-0286",
  "CVE-2020-15389",
  "CVE-2020-1967",
  "CVE-2020-11869",
  "CVE-2020-13164",
]

FAILURE_CATEGORIES = [
  "data_import",
  "patch_extraction",
  "function_mapping",
  "evidence_collection",
  "packet_retrieval",
  "opencode_backend",
  "json_parse",
  "schema_contract",
  "structural_gate",
  "anchor_selection",
  "predicate_generation",
  "unsupported_inference",
  "multi_fix_coverage",
  "semantic_reasoning",
  "reporting",
  "other",
]

SEMANTIC_EVALUATION_COLUMNS = [
  "cve_id",
  "repo",
  "cwe",
  "fix_commit_count",
  "status",
  "json_parse_status",
  "contract_ok",
  "ingested_raw",
  "hypothesis_count",
  "evidence_backed_hypothesis_count",
  "mechanism_correct",
  "vulnerable_predicate_correct",
  "fix_predicate_correct",
  "anchor_file_correct",
  "anchor_function_correct",
  "anchor_hunk_correct",
  "evidence_link_precise",
  "unsupported_inference",
  "fix_set_complete",
  "minimality_correct",
  "overall_root_cause_correct",
  "severity",
  "reviewer_notes",
]


def seed_baseline_graph(
  client: VulnGraphClient,
  cve_ids: list[str],
  *,
  dataset: str | Path,
  repo_root: str | Path,
) -> dict[str, Any]:
  dataset_path = Path(dataset)
  repo_root_path = Path(repo_root)
  dataset_records = _load_dataset(dataset_path)
  missing_cves = [cve_id for cve_id in cve_ids if cve_id not in dataset_records]
  graph = build_dataset_graph(dataset_path, cve_ids=cve_ids, include_offline_eval=True)
  client.append_graph(graph, created_from="semantic_baseline_seed_dataset")

  selected = set(cve_ids)
  patch_results: list[dict[str, Any]] = []
  for node in graph.nodes:
    if node.type != "FixCommit":
      continue
    cve_id = str(node.content.get("cve_id") or "")
    if cve_id not in selected:
      continue
    repo = str(node.content.get("repo") or "")
    commit_sha = str(node.content.get("commit_sha") or "")
    repo_path = repo_root_path / repo
    item: dict[str, Any] = {"cve_id": cve_id, "repo": repo, "commit_sha": commit_sha, "status": "skipped"}
    if not repo or not commit_sha or not repo_path.exists():
      item["error"] = f"repo path not found: {repo_path}"
      patch_results.append(item)
      continue
    try:
      patch_graph = build_patch_graph_from_repo(
        cve_id=cve_id,
        repo=repo,
        repo_path=repo_path,
        commit_sha=commit_sha,
        fix_commit_content=dict(node.content),
      )
      client.append_graph(patch_graph, created_from="semantic_baseline_seed_patch")
      item.update({"status": "ok", "nodes": len(patch_graph.nodes), "edges": len(patch_graph.edges)})
    except Exception as error:
      item.update({"status": "failed", "error": str(error)})
    patch_results.append(item)
  return {
    "dataset": str(dataset_path),
    "repo_root": str(repo_root_path),
    "requested_cves": list(cve_ids),
    "missing_cves": missing_cves,
    "imported_cves": [cve_id for cve_id in cve_ids if cve_id not in missing_cves],
    "patch_results": patch_results,
  }


def run_semantic_baseline(
  cve_ids: list[str],
  *,
  dataset: str | Path,
  repo_root: str | Path,
  out_dir: str | Path,
  backend: RootCauseBackend,
  provider_id: str,
  model_id: str,
  command: str,
  timeout_s: float,
) -> dict[str, Any]:
  out_root = Path(out_dir)
  out_root.mkdir(parents=True, exist_ok=True)
  client = VulnGraphClient(out_root / "graph_store")
  seed_result = seed_baseline_graph(client, cve_ids, dataset=dataset, repo_root=repo_root)
  summary = run_root_cause_batch(
    cve_ids,
    client=client,
    backend=backend,
    repo_root=repo_root,
    out_dir=out_root,
    timeout_s=timeout_s,
  )
  summary.update(
    {
      "baseline": "root-cause-v2-semantic-baseline-10",
      "selected_cves": list(cve_ids),
      "seed_result": seed_result,
      "provider_id": provider_id,
      "model_id": model_id,
      "command": command,
    }
  )
  artifacts = ensure_semantic_artifacts(
    out_root,
    summary=summary,
    dataset=dataset,
    cve_ids=cve_ids,
    provider_id=provider_id,
    model_id=model_id,
    command=command,
    seed_result=seed_result,
  )
  summary["semantic_artifacts"] = {key: str(path) for key, path in artifacts.items()}
  (out_root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
  return summary


def ensure_semantic_artifacts(
  out_dir: str | Path,
  *,
  summary: dict[str, Any],
  dataset: str | Path,
  cve_ids: list[str],
  provider_id: str,
  model_id: str,
  command: str,
  seed_result: dict[str, Any],
) -> dict[str, Path]:
  out_root = Path(out_dir)
  out_root.mkdir(parents=True, exist_ok=True)
  dataset_records = _load_dataset(Path(dataset))
  results_by_cve = {str(item.get("cve_id")): item for item in summary.get("results", [])}
  _ensure_per_cve_artifacts(out_root, cve_ids, results_by_cve)

  evaluation_csv = out_root / "evaluation.csv"
  _write_evaluation_csv(evaluation_csv, cve_ids, dataset_records, results_by_cve)

  taxonomy = _failure_taxonomy(summary, seed_result)
  failure_taxonomy = out_root / "failure_taxonomy.json"
  failure_taxonomy.write_text(json.dumps(taxonomy, ensure_ascii=False, indent=2), encoding="utf-8")

  semantic_review_template = out_root / "semantic_review_template.md"
  semantic_review_template.write_text(
    _render_review_template(cve_ids, dataset_records, results_by_cve),
    encoding="utf-8",
  )

  report = out_root / "report.md"
  report.write_text(
    _render_semantic_report(
      summary,
      dataset=Path(dataset),
      cve_ids=cve_ids,
      provider_id=provider_id,
      model_id=model_id,
      command=command,
      seed_result=seed_result,
      taxonomy=taxonomy,
    ),
    encoding="utf-8",
  )
  return {
    "evaluation_csv": evaluation_csv,
    "semantic_review_template": semantic_review_template,
    "failure_taxonomy": failure_taxonomy,
    "report": report,
  }


def build_compact_review_packet(run_dir: str | Path) -> dict[str, Any]:
  run_root = Path(run_dir)
  summary = _read_json(run_root / "summary.json", default={})
  results_by_cve = {str(item.get("cve_id")): item for item in summary.get("results", []) or []}
  cve_ids = list(summary.get("selected_cves") or sorted(results_by_cve) or sorted(path.name for path in run_root.iterdir() if path.is_dir() and path.name.startswith("CVE-")))
  packet = {
    "run_dir": str(run_root),
    "source": "root-cause-v2-semantic-baseline-10",
    "manual_correctness_filled": False,
    "cves": [],
  }
  for cve_id in cve_ids:
    result = results_by_cve.get(cve_id, {})
    cve_dir = _resolve_cve_dir(run_root, cve_id, result)
    parsed = _read_json(cve_dir / "parsed_output.json", default={})
    parse_error = _read_json(cve_dir / "parse_error.json", default={})
    contract_lint = _read_json(cve_dir / "contract_lint.json", default={})
    structural_validation = _read_json(cve_dir / "structural_validation.json", default={})
    ingestion_result = _read_json(cve_dir / "ingestion_result.json", default={})
    evidence_trace = _read_json(cve_dir / "evidence_trace.json", default={})
    observations = {
      str(observation.get("id") or ""): observation
      for observation in evidence_trace.get("git_observations", []) or []
      if observation.get("id")
    }
    observation_refs = _collect_observation_refs(parsed)
    item = {
      "cve_id": cve_id,
      "run_dir": str(cve_dir),
      "status": result.get("status") or ingestion_result.get("status") or "unknown",
      "json_parse_status": result.get("json_parse_status", ""),
      "failure_class": _classify_review_failure(cve_id, result, parse_error, contract_lint, structural_validation),
      "agent_hypotheses": _compact_hypotheses(parsed),
      "vulnerable_predicates": _compact_predicates(parsed.get("vulnerable_predicates", []) or []),
      "fix_predicates": _compact_predicates(parsed.get("fix_predicates", []) or []),
      "anchors": _compact_anchors(parsed, structural_validation),
      "supporting_git_observation_refs": sorted(observation_refs),
      "supporting_git_observations": [_compact_observation(observations[ref]) for ref in sorted(observation_refs) if ref in observations],
      "gate": {
        "contract_ok": contract_lint.get("ok", result.get("contract_ok", False)),
        "contract_errors": contract_lint.get("errors", []),
        "contract_taxonomy": contract_lint.get("taxonomy", {}),
        "structural_ok": structural_validation.get("ok", False),
        "structural_errors": structural_validation.get("errors", []),
        "accepted_hypothesis_ids": structural_validation.get("accepted_hypothesis_ids", []),
        "rejected_hypothesis_ids": structural_validation.get("rejected_hypothesis_ids", []),
        "ingestion_status": ingestion_result.get("status", result.get("status")),
        "ingestion_errors": ingestion_result.get("errors", result.get("errors", [])),
      },
      "parse_error": parse_error,
      "manual_judgement_basis": _manual_judgement_basis(parsed, structural_validation, observations),
    }
    packet["cves"].append(item)
  return packet


def write_compact_review_packet(run_dir: str | Path) -> dict[str, Path]:
  run_root = Path(run_dir)
  packet = build_compact_review_packet(run_root)
  json_path = run_root / "compact_review_packet.json"
  md_path = run_root / "compact_review_packet.md"
  json_path.write_text(json.dumps(packet, ensure_ascii=False, indent=2), encoding="utf-8")
  md_path.write_text(render_compact_review_markdown(packet), encoding="utf-8")
  return {"json": json_path, "markdown": md_path}


def render_compact_review_markdown(packet: dict[str, Any]) -> str:
  lines = [
    "# Compact Root Cause Review Packet",
    "",
    "This packet summarizes agent output and evidence for manual labeling. Correctness fields are intentionally left blank.",
  ]
  for item in packet.get("cves", []) or []:
    lines.extend(
      [
        "",
        f"## {item.get('cve_id')}",
        "",
        f"- Status: `{item.get('status')}`",
        f"- Failure class: `{item.get('failure_class')}`",
        f"- Contract OK: `{item.get('gate', {}).get('contract_ok')}`",
        f"- Structural OK: `{item.get('gate', {}).get('structural_ok')}`",
        "",
        "### Hypothesis",
      ]
    )
    for hypothesis in item.get("agent_hypotheses", []) or []:
      lines.extend(
        [
          f"- `{hypothesis.get('hypothesis_id')}`: {hypothesis.get('summary', '')}",
          f"  - mechanism: {hypothesis.get('mechanism', '')}",
          f"  - observations: `{hypothesis.get('git_observation_refs', [])}`",
        ]
      )
    lines.append("")
    lines.append("### Anchors")
    for anchor in item.get("anchors", []) or []:
      lines.append(
        f"- `{anchor.get('anchor_id')}` file=`{anchor.get('path')}` function=`{anchor.get('function')}` "
        f"hunk=`{anchor.get('patch_hunk_id')}` gate=`{anchor.get('gate_valid')}`"
      )
    lines.append("")
    lines.append("### Gate Errors")
    for error in (item.get("gate", {}).get("contract_errors") or item.get("gate", {}).get("structural_errors") or []):
      lines.append(f"- {error}")
  return "\n".join(lines) + "\n"


def aggregate_evaluation_metrics(evaluation_csv: str | Path) -> dict[str, Any]:
  rows = _read_csv_rows(Path(evaluation_csv))
  total = len(rows)
  accepted_rows = [row for row in rows if _is_true(row.get("ingested_raw"))]
  accepted_count = len(accepted_rows)
  overall_labels = [row for row in rows if _label(row.get("overall_root_cause_correct")) is not None]
  accepted_overall_labels = [row for row in accepted_rows if _label(row.get("overall_root_cause_correct")) is not None]
  multi_fix_rows = [row for row in rows if _as_int(row.get("fix_commit_count")) > 1]
  return {
    "evaluation_csv": str(evaluation_csv),
    "total_cases": total,
    "accepted_cases": accepted_count,
    "reviewed_cases": len(overall_labels),
    "schema_acceptance_rate": _metric(accepted_count, total),
    "semantic_correct_rate_among_accepted_cases": _binary_label_metric(accepted_overall_labels, "overall_root_cause_correct"),
    "overall_correct_rate_among_all_cases": _overall_all_cases_metric(rows, "overall_root_cause_correct"),
    "anchor_hunk_precision": _binary_label_metric(rows, "anchor_hunk_correct"),
    "evidence_link_precision": _binary_label_metric(rows, "evidence_link_precise"),
    "unsupported_inference_rate": _binary_label_metric(rows, "unsupported_inference"),
    "multi_fix_semantic_coverage": _binary_label_metric(multi_fix_rows, "fix_set_complete"),
  }


def write_evaluation_metrics(evaluation_csv: str | Path, out_path: str | Path) -> dict[str, Any]:
  metrics = aggregate_evaluation_metrics(evaluation_csv)
  Path(out_path).write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
  return metrics


def _resolve_cve_dir(run_root: Path, cve_id: str, result: dict[str, Any]) -> Path:
  run_dir = str(result.get("run_dir") or "")
  if run_dir:
    candidate = Path(run_dir)
    if candidate.is_absolute() and candidate.exists():
      return candidate
    if candidate.exists():
      return candidate
  return run_root / cve_id


def _compact_hypotheses(parsed: dict[str, Any]) -> list[dict[str, Any]]:
  return [
    {
      "hypothesis_id": item.get("hypothesis_id") or item.get("id") or "",
      "summary": item.get("summary", ""),
      "mechanism": item.get("mechanism", ""),
      "vulnerable_predicate_ids": item.get("vulnerable_predicate_ids", []),
      "fix_predicate_ids": item.get("fix_predicate_ids", []),
      "guard_condition_ids": item.get("guard_condition_ids", []),
      "negative_condition_ids": item.get("negative_condition_ids", []),
      "anchor_ids": item.get("anchor_ids") or item.get("code_anchor_ids") or [],
      "fix_commit_ids": item.get("fix_commit_ids", []),
      "fix_set_ids": item.get("fix_set_ids", []),
      "git_observation_refs": item.get("git_observation_refs", []),
      "confidence": item.get("confidence"),
    }
    for item in parsed.get("root_cause_hypotheses", []) or []
  ]


def _compact_predicates(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
  return [
    {
      "predicate_id": item.get("predicate_id") or item.get("id") or "",
      "description": item.get("description") or item.get("statement") or "",
      "anchor_ids": item.get("anchor_ids") or item.get("code_anchor_ids") or [],
      "git_observation_refs": item.get("git_observation_refs", []),
      "confidence": item.get("confidence"),
    }
    for item in items
  ]


def _compact_anchors(parsed: dict[str, Any], structural_validation: dict[str, Any]) -> list[dict[str, Any]]:
  anchor_results = structural_validation.get("anchor_results", {}) or {}
  anchors = []
  for item in parsed.get("code_anchors", []) or []:
    anchor_id = item.get("anchor_id") or item.get("id") or ""
    gate = anchor_results.get(anchor_id, {}) or {}
    anchors.append(
      {
        "anchor_id": anchor_id,
        "fix_commit_id": item.get("fix_commit_id", ""),
        "patch_hunk_id": item.get("patch_hunk_id", ""),
        "file_id": item.get("file_id", ""),
        "path": item.get("path", ""),
        "function_id": item.get("function_id", ""),
        "function": item.get("function") or item.get("function_name") or "",
        "line_start": item.get("line_start"),
        "line_end": item.get("line_end"),
        "pattern": item.get("pattern", ""),
        "git_observation_refs": item.get("git_observation_refs", []),
        "gate_valid": gate.get("gate_valid"),
        "gate_errors": gate.get("gate_errors") or gate.get("errors") or [],
      }
    )
  return anchors


def _compact_observation(observation: dict[str, Any]) -> dict[str, Any]:
  return {
    "id": observation.get("id", ""),
    "observation_kind": observation.get("observation_kind", ""),
    "valid_evidence": observation.get("valid_evidence"),
    "command_ref": observation.get("command_ref", ""),
    "tool_output_ref": observation.get("tool_output_ref", ""),
    "claim": observation.get("claim", ""),
    "path": observation.get("path", ""),
    "fix_commit_ids": observation.get("fix_commit_ids", []),
    "patch_hunk_ids": observation.get("patch_hunk_ids", []),
    "file_ids": observation.get("file_ids", []),
    "function_ids": observation.get("function_ids", []),
    "snippet_excerpt": str(observation.get("snippet") or "")[:600],
  }


def _collect_observation_refs(parsed: dict[str, Any]) -> set[str]:
  refs: set[str] = set()
  for section in (
    "root_cause_hypotheses",
    "vulnerable_predicates",
    "fix_predicates",
    "guard_conditions",
    "negative_conditions",
    "negative_applicability_conditions",
    "code_anchors",
    "uncertainty_reasons",
  ):
    for item in parsed.get(section, []) or []:
      refs.update(str(ref) for ref in item.get("git_observation_refs", []) or [] if ref)
  refs.update(str(ref) for ref in parsed.get("git_observation_refs", []) or [] if ref)
  return refs


def _manual_judgement_basis(parsed: dict[str, Any], structural_validation: dict[str, Any], observations: dict[str, dict[str, Any]]) -> dict[str, Any]:
  hypotheses = _compact_hypotheses(parsed)
  anchors = _compact_anchors(parsed, structural_validation)
  observation_refs = sorted(_collect_observation_refs(parsed))
  observed_claims = [observations[ref].get("claim", "") for ref in observation_refs if ref in observations]
  return {
    "mechanism_correct": {"value": "", "basis": [item.get("mechanism", "") for item in hypotheses]},
    "vulnerable_predicate_correct": {"value": "", "basis": [item.get("description", "") for item in _compact_predicates(parsed.get("vulnerable_predicates", []) or [])]},
    "fix_predicate_correct": {"value": "", "basis": [item.get("description", "") for item in _compact_predicates(parsed.get("fix_predicates", []) or [])]},
    "anchor_file_correct": {"value": "", "basis": [item.get("path", "") for item in anchors]},
    "anchor_function_correct": {"value": "", "basis": [item.get("function", "") for item in anchors]},
    "anchor_hunk_correct": {"value": "", "basis": [item.get("patch_hunk_id", "") for item in anchors]},
    "evidence_link_precise": {"value": "", "basis": observed_claims},
    "unsupported_inference": {"value": "", "basis": [item.get("summary", "") for item in hypotheses]},
    "fix_set_complete": {"value": "", "basis": structural_validation.get("fix_set_results", {})},
    "minimality_correct": {"value": "", "basis": "Compare selected anchors against patch hunks and reject over-broad root-cause statements."},
    "overall_root_cause_correct": {"value": "", "basis": "Reviewer must combine mechanism, predicates, anchors, evidence links, and unsupported inference checks."},
  }


def _classify_review_failure(
  cve_id: str,
  result: dict[str, Any],
  parse_error: dict[str, Any],
  contract_lint: dict[str, Any],
  structural_validation: dict[str, Any],
) -> str:
  parse_text = str(parse_error.get("error") or "")
  errors = " ".join(str(error) for error in (
    contract_lint.get("errors", []) or structural_validation.get("errors", []) or result.get("errors", [])
  ))
  if cve_id == "CVE-2020-19667" and "function_id" in errors:
    return "structural_gate / function_binding failure"
  if cve_id == "CVE-2022-0171" and "code_anchors" in parse_text and ".path" in parse_text and "Field required" in parse_text:
    return "schema_validation_missing_path"
  status = result.get("status", "")
  if status == "ingested_raw":
    return "none"
  if status == "parse_error":
    return "schema_validation"
  if status == "rejected":
    return "structural_gate"
  if status == "failed":
    return "opencode_backend"
  return str(status or "unknown")


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
  with path.open(newline="", encoding="utf-8") as handle:
    return [dict(row) for row in csv.DictReader(handle)]


def _binary_label_metric(rows: list[dict[str, str]], column: str) -> dict[str, Any]:
  labeled = [_label(row.get(column)) for row in rows if _label(row.get(column)) is not None]
  return _metric(sum(1 for value in labeled if value == 1), len(labeled))


def _overall_all_cases_metric(rows: list[dict[str, str]], column: str) -> dict[str, Any]:
  labeled = [_label(row.get(column)) for row in rows]
  if any(value is None for value in labeled):
    metric = _metric(0, 0)
    metric["ready"] = False
    metric["reason"] = "not all cases have a filled overall_root_cause_correct label"
    return metric
  metric = _metric(sum(1 for value in labeled if value == 1), len(rows))
  metric["ready"] = True
  return metric


def _metric(numerator: int, denominator: int) -> dict[str, Any]:
  return {
    "value": (numerator / denominator) if denominator else None,
    "numerator": numerator,
    "denominator": denominator,
    "ready": denominator > 0,
  }


def _label(value: Any) -> int | None:
  text = str(value if value is not None else "").strip().upper()
  if text == "1":
    return 1
  if text == "0":
    return 0
  return None


def _is_true(value: Any) -> bool:
  return str(value if value is not None else "").strip().lower() in {"1", "true", "yes"}


def _as_int(value: Any) -> int:
  try:
    return int(str(value).strip())
  except Exception:
    return 0


def _ensure_per_cve_artifacts(out_root: Path, cve_ids: list[str], results_by_cve: dict[str, dict[str, Any]]) -> None:
  for cve_id in cve_ids:
    result = results_by_cve.get(cve_id, {})
    cve_dir = Path(str(result.get("run_dir") or out_root / cve_id))
    cve_dir.mkdir(parents=True, exist_ok=True)
    if not (cve_dir / "parsed_output.json").exists() and not (cve_dir / "parse_error.json").exists():
      _write_json(
        cve_dir / "parse_error.json",
        {
          "status": result.get("status", "not_run"),
          "json_parse_status": result.get("json_parse_status", "not_run"),
          "errors": result.get("errors", []),
        },
      )
    if not (cve_dir / "contract_lint.json").exists():
      _write_json(
        cve_dir / "contract_lint.json",
        {
          "ok": False,
          "status": "not_applicable",
          "reason": "No parsed agent output reached contract lint.",
          "errors": result.get("errors", []),
        },
      )
    if not (cve_dir / "structural_validation.json").exists():
      _write_json(
        cve_dir / "structural_validation.json",
        {
          "ok": False,
          "status": "not_applicable",
          "reason": "No parsed agent output reached structural validation.",
          "errors": result.get("errors", []),
        },
      )
    (cve_dir / "report.md").write_text(_render_per_cve_report(cve_id, result), encoding="utf-8")


def _write_evaluation_csv(
  path: Path,
  cve_ids: list[str],
  dataset_records: dict[str, Any],
  results_by_cve: dict[str, dict[str, Any]],
) -> None:
  with path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=SEMANTIC_EVALUATION_COLUMNS)
    writer.writeheader()
    for cve_id in cve_ids:
      record = dataset_records.get(cve_id, {})
      result = results_by_cve.get(cve_id, {})
      row = {key: "" for key in SEMANTIC_EVALUATION_COLUMNS}
      row.update(
        {
          "cve_id": cve_id,
          "repo": record.get("repo", ""),
          "cwe": ";".join(str(item) for item in record.get("CWE", []) or []),
          "fix_commit_count": result.get("fix_commit_count", _fix_commit_count(record.get("fixing_commits"))),
          "status": result.get("status", "not_run"),
          "json_parse_status": result.get("json_parse_status", ""),
          "contract_ok": result.get("contract_ok", ""),
          "ingested_raw": 1 if result.get("status") == "ingested_raw" else 0,
          "hypothesis_count": result.get("hypothesis_count", 0),
          "evidence_backed_hypothesis_count": result.get("evidence_backed_hypothesis_count", 0),
        }
      )
      writer.writerow(row)


def _failure_taxonomy(summary: dict[str, Any], seed_result: dict[str, Any]) -> dict[str, Any]:
  taxonomy: dict[str, Any] = {
    "categories": {category: {"count": 0, "cases": []} for category in FAILURE_CATEGORIES}
  }
  for item in seed_result.get("patch_results", []) or []:
    status = item.get("status")
    if status == "skipped":
      _add_failure(taxonomy, "data_import", item.get("cve_id"), item.get("error", "patch seed skipped"))
    elif status == "failed":
      _add_failure(taxonomy, "patch_extraction", item.get("cve_id"), item.get("error", "patch extraction failed"))
  for cve_id in seed_result.get("missing_cves", []) or []:
    _add_failure(taxonomy, "data_import", cve_id, "CVE missing from dataset")
  for result in summary.get("results", []) or []:
    cve_id = result.get("cve_id")
    status = result.get("status")
    if status == "failed" or result.get("json_parse_status") == "backend_failed":
      _add_failure(taxonomy, "opencode_backend", cve_id, "; ".join(result.get("errors", [])))
    elif status in {"parse_error", "empty"}:
      _add_failure(taxonomy, "json_parse", cve_id, "; ".join(result.get("errors", [])))
    elif status == "rejected":
      if result.get("contract_error_count"):
        _add_failure(taxonomy, "schema_contract", cve_id, "; ".join(result.get("errors", [])))
      else:
        _add_failure(taxonomy, "structural_gate", cve_id, "; ".join(result.get("errors", [])))
    if result.get("multi_fix_commit") and result.get("multi_fix_anchor_mapping_ok") is False:
      _add_failure(taxonomy, "multi_fix_coverage", cve_id, "accepted anchors did not cover the fix set")
  return taxonomy


def _add_failure(taxonomy: dict[str, Any], category: str, cve_id: Any, reason: str) -> None:
  bucket = taxonomy["categories"].setdefault(category, {"count": 0, "cases": []})
  bucket["count"] += 1
  bucket["cases"].append({"cve_id": str(cve_id or ""), "reason": reason})


def _render_semantic_report(
  summary: dict[str, Any],
  *,
  dataset: Path,
  cve_ids: list[str],
  provider_id: str,
  model_id: str,
  command: str,
  seed_result: dict[str, Any],
  taxonomy: dict[str, Any],
) -> str:
  multi_fix_cases = [item for item in summary.get("results", []) if item.get("multi_fix_commit")]
  covered_multi_fix = [item for item in multi_fix_cases if item.get("multi_fix_anchor_mapping_ok") is not False]
  lines = [
    "# Root Cause v2 Semantic Baseline 10-CVE Report",
    "",
    "## Scope",
    "",
    "This is a Root Cause Agent semantic baseline. It does not run Judge Agent, SZZ/BIC ranking, or affected-version conversion. Correctness columns are intentionally left for manual review.",
    "",
    "## Execution",
    "",
    f"- Dataset: `{dataset}`",
    f"- Provider/model: `{provider_id}/{model_id}`",
    f"- Command: `{command}`",
    f"- CVE list: `{cve_ids}`",
    "",
    "## Structural Metrics",
    "",
    f"- Real OpenCode invocation count: {summary.get('real_opencode_invocation_count', 0)}",
    f"- ingested_raw_count: {summary.get('ingested_raw_count', 0)}",
    f"- structurally_rejected_count: {summary.get('structurally_rejected_count', 0)}",
    f"- parse_error_count: {summary.get('parse_error_count', 0)}",
    f"- backend_failed_count: {summary.get('backend_failed_count', 0)}",
    f"- valid_json_count: {summary.get('valid_json_count', 0)}",
    f"- fenced_json_count: {summary.get('json_parse_status_counts', {}).get('fenced_json', 0)}",
    f"- empty_message_count: {summary.get('empty_message_count', 0)}",
    f"- evidence_backed_hypothesis_count: {summary.get('evidence_backed_hypothesis_count', 0)}",
    f"- invented_id_cases: `{summary.get('invented_id_cases', [])}`",
    f"- lint_ingestion_parity_count: {summary.get('lint_ingestion_parity_count', 0)}/{summary.get('total', 0)}",
    f"- multi_fix_gate_coverage: {len(covered_multi_fix)}/{len(multi_fix_cases)}",
    f"- average packet size: {float(summary.get('avg_packet_size_bytes') or 0):.1f} bytes",
    f"- average evidence trace size: {float(summary.get('avg_evidence_trace_size_bytes') or 0):.1f} bytes",
    f"- average raw response size: {float(summary.get('avg_raw_response_size_bytes') or 0):.1f} bytes",
    f"- total duration: {float(summary.get('total_duration_s') or 0):.3f} seconds",
    "",
    "## Seed Result",
    "",
    f"- Missing CVEs: `{seed_result.get('missing_cves', [])}`",
    f"- Patch results: `{seed_result.get('patch_results', [])}`",
    "",
    "## Per-CVE Status",
    "",
    "| CVE | Repo | Status | JSON | Contract OK | Ingested Raw | Hypotheses | Evidence-backed | Fix Commits | Multi-fix Mapping | Errors |",
    "| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |",
  ]
  records = _load_dataset(dataset)
  for result in summary.get("results", []) or []:
    cve_id = str(result.get("cve_id") or "")
    repo = (records.get(cve_id) or {}).get("repo", "")
    errors = "; ".join(str(error) for error in result.get("errors", []) if error)
    lines.append(
      f"| {cve_id} | {repo} | {result.get('status')} | {result.get('json_parse_status')} | "
      f"{result.get('contract_ok')} | {1 if result.get('status') == 'ingested_raw' else 0} | "
      f"{result.get('hypothesis_count', 0)} | {result.get('evidence_backed_hypothesis_count', 0)} | "
      f"{result.get('fix_commit_count', 0)} | {result.get('multi_fix_anchor_mapping_ok')} | {errors} |"
    )
  lines.extend(
    [
      "",
      "## Failure Taxonomy",
      "",
      "```json",
      json.dumps(taxonomy, ensure_ascii=False, indent=2),
      "```",
      "",
      "## Manual Review",
      "",
      "Use `evaluation.csv` and `semantic_review_template.md` for semantic labeling. Do not treat `ingested_raw` as semantic correctness.",
    ]
  )
  return "\n".join(lines) + "\n"


def _render_review_template(cve_ids: list[str], dataset_records: dict[str, Any], results_by_cve: dict[str, dict[str, Any]]) -> str:
  lines = [
    "# Root Cause Semantic Review Template",
    "",
    "For each CVE, inspect packet, evidence trace, parsed output, contract lint, structural validation, and ingestion result before filling `evaluation.csv`.",
  ]
  checklist = [
    "1. 机制是否解释了真实漏洞原因，而不是只复述补丁。",
    "2. VulnerablePredicate 是否表达漏洞成立条件。",
    "3. FixPredicate 是否表达补丁阻断条件。",
    "4. CodeAnchor 是否指向正确文件、函数、PatchHunk。",
    "5. SUPPORTS 边是否由对应 GitObservation 真实支撑。",
    "6. 是否有 patch/evidence 外的无证据推断。",
    "7. multi-fix 是否覆盖完整 fix_set。",
    "8. 是否把无关重构或上下文误认为 root cause。",
  ]
  for cve_id in cve_ids:
    record = dataset_records.get(cve_id, {})
    result = results_by_cve.get(cve_id, {})
    lines.extend(
      [
        "",
        f"## {cve_id}",
        "",
        f"- Repo: `{record.get('repo', '')}`",
        f"- CWE: `{record.get('CWE', [])}`",
        f"- Fix commits: `{record.get('fixing_commits', [])}`",
        f"- Run dir: `{result.get('run_dir', '')}`",
        f"- Status: `{result.get('status', 'not_run')}`",
        "",
        *checklist,
      ]
    )
  return "\n".join(lines) + "\n"


def _render_per_cve_report(cve_id: str, result: dict[str, Any]) -> str:
  return "\n".join(
    [
      f"# {cve_id} Root Cause Semantic Baseline Artifact",
      "",
      "## Structural Status",
      "",
      f"- Status: `{result.get('status', 'not_run')}`",
      f"- JSON parse status: `{result.get('json_parse_status', '')}`",
      f"- Contract OK: `{result.get('contract_ok', '')}`",
      f"- Evidence-backed hypotheses: {result.get('evidence_backed_hypothesis_count', 0)}",
      f"- Errors: `{result.get('errors', [])}`",
      "",
      "## Manual Semantic Review",
      "",
      "Fill the corresponding row in `evaluation.csv`; `ingested_raw` is structural acceptance, not semantic correctness.",
    ]
  ) + "\n"


def _load_dataset(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError("dataset must be a JSON object keyed by CVE")
  return data


def _read_json(path: Path, *, default: Any) -> Any:
  if not path.exists():
    return default
  try:
    return json.loads(path.read_text(encoding="utf-8"))
  except Exception:
    return default


def _fix_commit_count(value: Any) -> int:
  if not isinstance(value, list):
    return 0
  count = 0
  for group in value:
    if isinstance(group, list):
      count += len([item for item in group if str(item).strip()])
    elif str(group).strip():
      count += 1
  return count


def _write_json(path: Path, data: Any) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
