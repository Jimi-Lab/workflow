from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from vulngraph.agent_io import lint_root_cause_contract, validate_root_cause_structure
from vulngraph.builder import build_dataset_graph, build_patch_graph_from_repo
from vulngraph.services import VulnGraphClient


DEFAULT_DATASET = Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json")
DEFAULT_REPO_ROOT = Path(r"E:\AI\Agent\workflow\VulnVersion\repo")


def main() -> None:
  parser = argparse.ArgumentParser(description="Replay native Root Cause artifacts through the structural gate without invoking an agent.")
  parser.add_argument("--source", type=Path, required=True)
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  if args.reset and args.out_dir.exists():
    shutil.rmtree(args.out_dir)
  args.out_dir.mkdir(parents=True, exist_ok=True)
  cve_ids = sorted(path.name for path in args.source.iterdir() if path.is_dir() and path.name.startswith("CVE-"))
  client = VulnGraphClient(args.out_dir / "graph_store")
  seed_result = _seed_graph(client, cve_ids, args.dataset, args.repo_root)
  results = []
  for cve_id in cve_ids:
    source_dir = args.source / cve_id
    out_dir = args.out_dir / cve_id
    out_dir.mkdir(parents=True, exist_ok=True)
    packet = client.build_root_cause_packet(cve_id)
    trace = _load_json(source_dir / "evidence_trace.json")
    parsed = _load_json(source_dir / "parsed_output.json")
    validation = validate_root_cause_structure(parsed, packet, trace)
    lint = lint_root_cause_contract(parsed, packet, trace)
    ingestion = client.ingest_root_cause_output(cve_id, parsed, trace=trace, packet=packet)
    ingestion_payload = {
      "status": ingestion.status,
      "lifecycle": ingestion.lifecycle,
      "appended_events": ingestion.appended_events,
      "errors": ingestion.errors,
      "warnings": ingestion.warnings,
      "failure_case_id": ingestion.failure_case_id,
      "raw_hypothesis_count": ingestion.raw_hypothesis_count,
      "rejected_hypothesis_count": ingestion.rejected_hypothesis_count,
      "details": ingestion.details,
    }
    parity = validation.accepted_hypothesis_ids == [
      item_id for item_id, item in ingestion.details.get("hypothesis_results", {}).items() if item.get("lifecycle") == "raw"
    ]
    result = {
      "cve_id": cve_id,
      "source_artifact": str(source_dir),
      "status": ingestion.status,
      "accepted_hypothesis_ids": validation.accepted_hypothesis_ids,
      "rejected_hypothesis_ids": validation.rejected_hypothesis_ids,
      "structural_error_count": len(validation.errors),
      "taxonomy": validation.taxonomy,
      "invented_ids": validation.invented_ids,
      "lint_ok": lint.ok,
      "lint_ingestion_parity": parity,
      "legacy_adapter_count": 0,
      "fix_set_results": validation.fix_set_results,
    }
    results.append(result)
    _write_json(out_dir / "root_cause_packet.json", packet)
    _write_json(out_dir / "evidence_trace.json", trace)
    _write_json(out_dir / "parsed_output.json", parsed)
    _write_json(out_dir / "contract_lint.json", lint.to_dict())
    _write_json(out_dir / "structural_validation.json", validation.to_dict())
    _write_json(out_dir / "ingestion_result.json", ingestion_payload)
  summary = {
    "source": str(args.source),
    "out_dir": str(args.out_dir),
    "agent_invocation_count": 0,
    "legacy_adapter_count": 0,
    "seed_result": seed_result,
    "status_counts": dict(Counter(item["status"] for item in results)),
    "structural_error_count": sum(item["structural_error_count"] for item in results),
    "lint_ingestion_parity": all(item["lint_ingestion_parity"] for item in results),
    "results": results,
  }
  _write_json(args.out_dir / "summary.json", summary)
  (args.out_dir / "report.md").write_text(_render_report(summary), encoding="utf-8")
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def _seed_graph(client: VulnGraphClient, cve_ids: list[str], dataset: Path, repo_root: Path) -> list[dict[str, Any]]:
  graph = build_dataset_graph(dataset, limit=10, include_offline_eval=True)
  client.append_graph(graph, created_from="structural_replay_dataset")
  selected = set(cve_ids)
  results = []
  for node in graph.nodes:
    if node.type != "FixCommit" or str(node.content.get("cve_id") or "") not in selected:
      continue
    cve_id = str(node.content.get("cve_id") or "")
    repo = str(node.content.get("repo") or "")
    commit_sha = str(node.content.get("commit_sha") or "")
    repo_path = repo_root / repo
    item = {"cve_id": cve_id, "repo": repo, "commit_sha": commit_sha}
    try:
      patch_graph = build_patch_graph_from_repo(
        cve_id=cve_id,
        repo=repo,
        repo_path=repo_path,
        commit_sha=commit_sha,
        fix_commit_content=dict(node.content),
      )
      client.append_graph(patch_graph, created_from="structural_replay_patch")
      item.update(status="ok", nodes=len(patch_graph.nodes), edges=len(patch_graph.edges))
    except Exception as error:
      item.update(status="failed", error=str(error))
    results.append(item)
  return results


def _render_report(summary: dict[str, Any]) -> str:
  lines = [
    "# Root Cause Structural Replay",
    "",
    "This replay invokes no Agent and uses no legacy reconstruction adapter. Old parsed output and native wrapper trace are evaluated unchanged against a freshly rebuilt graph.",
    "",
    f"- Agent invocation count: {summary['agent_invocation_count']}",
    f"- Legacy adapter count: {summary['legacy_adapter_count']}",
    f"- Status counts: `{summary['status_counts']}`",
    f"- Structural error count: {summary['structural_error_count']}",
    f"- Lint/ingestion parity: `{summary['lint_ingestion_parity']}`",
    "",
    "| CVE | Status | Accepted hypotheses | Rejected hypotheses | Structural errors | Invented IDs | Parity |",
    "| --- | --- | --- | --- | ---: | --- | --- |",
  ]
  for item in summary["results"]:
    lines.append(
      f"| {item['cve_id']} | {item['status']} | {item['accepted_hypothesis_ids']} | {item['rejected_hypothesis_ids']} | "
      f"{item['structural_error_count']} | {item['invented_ids']} | {item['lint_ingestion_parity']} |"
    )
  lines.extend(
    [
      "",
      "## Compatibility Boundary",
      "",
      "A rejection of an old artifact is retained as a structural regression finding. The replay does not rewrite stale function IDs or relax the production gate.",
    ]
  )
  return "\n".join(lines) + "\n"


def _load_json(path: Path) -> dict[str, Any]:
  data = json.loads(path.read_text(encoding="utf-8"))
  return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: Any) -> None:
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
  main()
