from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from vulngraph.agent_backend import OpenCodeBackendConfig, add_opencode_model_arguments
from vulngraph.agent_backends import OpenCodeGenerateBackend
from vulngraph.builder import build_dataset_graph, build_patch_graph_from_repo
from vulngraph.services import VulnGraphClient
from vulngraph.workflows.root_cause import run_root_cause_batch


DEFAULT_DATASET = Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json")
DEFAULT_REPO_ROOT = Path(r"E:\AI\Agent\workflow\VulnVersion\repo")
SMOKE_CVES = ["CVE-2022-3109"]
PILOT_CVES = ["CVE-2022-3109", "CVE-2023-47342", "CVE-2020-24020"]


def main() -> None:
  parser = argparse.ArgumentParser(description="Run real OpenCode Root Cause Agent v2 pilot.")
  parser.add_argument("--mode", choices=["smoke-1", "pilot-3"], default="smoke-1")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--base-url", default="http://127.0.0.1:4096")
  add_opencode_model_arguments(parser)
  parser.add_argument("--agent")
  parser.add_argument("--timeout", type=float, default=300.0)
  parser.add_argument("--reset", action="store_true", help="Delete out-dir before running.")
  args = parser.parse_args()

  cve_ids = SMOKE_CVES if args.mode == "smoke-1" else PILOT_CVES
  if args.reset and args.out_dir.exists():
    shutil.rmtree(args.out_dir)
  args.out_dir.mkdir(parents=True, exist_ok=True)

  client = VulnGraphClient(args.out_dir / "graph_store")
  seed_result = _seed_graph(client, cve_ids, dataset=args.dataset, repo_root=args.repo_root)
  backend = OpenCodeGenerateBackend(
    OpenCodeBackendConfig(
      base_url=args.base_url,
      provider_id=args.provider_id,
      model_id=args.model_id,
      agent=args.agent,
      timeout_s=args.timeout,
      max_retries=0,
    ),
    timeout_s=args.timeout,
  )
  summary = run_root_cause_batch(
    cve_ids,
    client=client,
    backend=backend,
    repo_root=args.repo_root,
    out_dir=args.out_dir,
    timeout_s=args.timeout,
  )
  summary["mode"] = args.mode
  summary["selected_cves"] = cve_ids
  summary["seed_result"] = seed_result
  summary["backend_config"] = {
    "base_url": args.base_url,
    "provider_id": args.provider_id,
    "model_id": args.model_id,
    "agent": args.agent,
    "timeout": args.timeout,
  }
  (args.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
  _append_pilot_notes(args.out_dir / "report.md", summary)
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def _seed_graph(client: VulnGraphClient, cve_ids: list[str], *, dataset: Path, repo_root: Path) -> dict[str, Any]:
  graph = build_dataset_graph(dataset, limit=10, include_offline_eval=True)
  client.append_graph(graph, created_from="opencode_pilot_seed_dataset")

  selected = set(cve_ids)
  patch_results = []
  for node in graph.nodes:
    if node.type != "FixCommit":
      continue
    cve_id = str(node.content.get("cve_id") or "")
    if cve_id not in selected:
      continue
    repo = str(node.content.get("repo") or "")
    commit_sha = str(node.content.get("commit_sha") or "")
    repo_path = repo_root / repo
    item = {"cve_id": cve_id, "repo": repo, "commit_sha": commit_sha, "status": "skipped"}
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
      client.append_graph(patch_graph, created_from="opencode_pilot_seed_patch")
      item.update({"status": "ok", "nodes": len(patch_graph.nodes), "edges": len(patch_graph.edges)})
    except Exception as error:
      item.update({"status": "failed", "error": str(error)})
    patch_results.append(item)
  return {
    "dataset": str(dataset),
    "repo_root": str(repo_root),
    "imported_cves": cve_ids,
    "patch_results": patch_results,
  }


def _append_pilot_notes(report_path: Path, summary: dict[str, Any]) -> None:
  text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
  notes = [
    "",
    "## OpenCode Pilot Notes",
    "",
    f"- Mode: `{summary['mode']}`",
    f"- Selected CVEs: `{summary['selected_cves']}`",
    f"- Backend config: `{summary['backend_config']}`",
    f"- Seed patch results: `{summary['seed_result']['patch_results']}`",
    "- This report contains only real `backend_type=opencode` runs. Fixture outputs are not mixed into these counts.",
  ]
  report_path.write_text(text.rstrip() + "\n" + "\n".join(notes) + "\n", encoding="utf-8")


if __name__ == "__main__":
  main()
