from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.agent_backend import OpenCodeBackend, OpenCodeBackendConfig, add_opencode_model_arguments
from vulngraph.agent_backends import OpenCodeGenerateBackend
from vulngraph.workflows.judge_boundary_v1_2 import FixtureJudgeBoundaryBackendV12, run_judge_boundary_v1_2_batch
from vulngraph.workflows.judge_v0_full_stress import discover_cve_dirs


def main() -> None:
  parser = argparse.ArgumentParser(description="Run VulnGraph Judge Boundary v1.2.")
  parser.add_argument("--judge-packet-root", type=Path, default=Path("runs/batches/vulngraph-judge-input-hardening-v1-30-p0-fix"))
  parser.add_argument("--detailed-evidence-root", type=Path, default=Path("runs/batches/vulngraph-detailed-szz-evidence-v0-30"))
  parser.add_argument("--slimming-root", type=Path, default=Path("runs/batches/vulngraph-core-dataflow-slimming-v1"))
  parser.add_argument("--judge-v0-run", type=Path, default=Path("runs/batches/vulngraph-judge-v0-full-stress-10plus30"))
  parser.add_argument("--dataset", type=Path, default=Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json"))
  parser.add_argument("--repo-root", type=Path, default=Path(r"E:\AI\Agent\workflow\VulnVersion\repo"))
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--cves", nargs="+")
  parser.add_argument("--base-url", default="http://127.0.0.1:4096")
  add_opencode_model_arguments(parser)
  parser.add_argument("--timeout", type=float, default=300.0)
  parser.add_argument("--repair-retries", type=int, default=1)
  parser.add_argument("--fixture", action="store_true")
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()
  cves = [item for value in args.cves or discover_cve_dirs(args.judge_packet_root) for item in str(value).split(",") if item]
  if args.fixture:
    backend = FixtureJudgeBoundaryBackendV12()
  else:
    config = OpenCodeBackendConfig(base_url=args.base_url, provider_id=args.provider_id, model_id=args.model_id, timeout_s=args.timeout, max_retries=0)
    OpenCodeBackend(config).health()
    backend = OpenCodeGenerateBackend(config, timeout_s=args.timeout)
  summary = run_judge_boundary_v1_2_batch(
    cve_ids=cves, judge_packet_root=args.judge_packet_root,
    detailed_evidence_root=args.detailed_evidence_root, slimming_root=args.slimming_root,
    judge_v0_run=args.judge_v0_run, dataset=args.dataset, repo_root=args.repo_root,
    out_dir=args.out_dir, backend=backend, reset=args.reset, repair_retries=args.repair_retries,
  )
  summary.update({"provider_id": "fixture" if args.fixture else args.provider_id, "model_id": "fixture" if args.fixture else args.model_id})
  (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
  print(json.dumps(summary, indent=2))


if __name__ == "__main__":
  main()
