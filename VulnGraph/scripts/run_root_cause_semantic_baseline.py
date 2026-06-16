from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from vulngraph.agent_backend import OpenCodeBackendConfig, add_opencode_model_arguments
from vulngraph.agent_backends import OpenCodeGenerateBackend
from vulngraph.workflows.semantic_baseline import DEFAULT_SEMANTIC_BASELINE_CVES, run_semantic_baseline


DEFAULT_DATASET = Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json")
DEFAULT_REPO_ROOT = Path(r"E:\AI\Agent\workflow\VulnVersion\repo")


def main() -> None:
  parser = argparse.ArgumentParser(description="Run the fixed 10-CVE Root Cause v2 semantic baseline.")
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--cves", nargs="+", default=DEFAULT_SEMANTIC_BASELINE_CVES)
  parser.add_argument("--base-url", default="http://127.0.0.1:4096")
  add_opencode_model_arguments(parser)
  parser.add_argument("--agent")
  parser.add_argument("--timeout", type=float, default=300.0)
  parser.add_argument("--reset", action="store_true", help="Delete only this run's out-dir before running.")
  args = parser.parse_args()

  cve_ids = _parse_cves(args.cves)
  if args.reset and args.out_dir.exists():
    shutil.rmtree(args.out_dir)
  args.out_dir.mkdir(parents=True, exist_ok=True)

  command = " ".join([Path(sys.argv[0]).name, *sys.argv[1:]])
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
  summary = run_semantic_baseline(
    cve_ids,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=args.out_dir,
    backend=backend,
    provider_id=args.provider_id,
    model_id=args.model_id,
    command=command,
    timeout_s=args.timeout,
  )
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def _parse_cves(values: list[str]) -> list[str]:
  cves: list[str] = []
  for value in values:
    for item in value.split(","):
      cve = item.strip()
      if cve:
        cves.append(cve)
  return cves


if __name__ == "__main__":
  main()
