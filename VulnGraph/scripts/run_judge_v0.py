from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.agent_backend import OpenCodeBackend, OpenCodeBackendConfig, add_opencode_model_arguments
from vulngraph.agent_backends import OpenCodeGenerateBackend
from vulngraph.workflows.judge_v0 import DEFAULT_JUDGE_V0_CVES, FixtureJudgeBackend, run_judge_v0_batch


DEFAULT_JUDGE_PACKET_ROOT = Path("runs/batches/vulngraph-judge-input-hardening-v1-30-p0-fix")
DEFAULT_DETAILED_EVIDENCE_ROOT = Path("runs/batches/vulngraph-detailed-szz-evidence-v0-30")
DEFAULT_SLIMMING_ROOT = Path("runs/batches/vulngraph-core-dataflow-slimming-v1")
DEFAULT_DATASET = Path(r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json")


def main() -> None:
  parser = argparse.ArgumentParser(description="Run VulnGraph Judge Agent v0 over raw candidate boundary packets.")
  parser.add_argument("--judge-packet-root", type=Path, default=DEFAULT_JUDGE_PACKET_ROOT)
  parser.add_argument("--detailed-evidence-root", type=Path, default=DEFAULT_DETAILED_EVIDENCE_ROOT)
  parser.add_argument("--slimming-root", type=Path, default=DEFAULT_SLIMMING_ROOT)
  parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
  parser.add_argument("--out-dir", type=Path, required=True)
  parser.add_argument("--cves", nargs="+", default=DEFAULT_JUDGE_V0_CVES)
  parser.add_argument("--base-url", default="http://127.0.0.1:4096")
  add_opencode_model_arguments(parser)
  parser.add_argument("--agent")
  parser.add_argument("--timeout", type=float, default=300.0)
  parser.add_argument("--reset", action="store_true")
  parser.add_argument("--fixture", action="store_true")
  args = parser.parse_args()

  if args.fixture:
    backend = FixtureJudgeBackend()
  else:
    config = OpenCodeBackendConfig(
      base_url=args.base_url,
      provider_id=args.provider_id,
      model_id=args.model_id,
      agent=args.agent,
      timeout_s=args.timeout,
      max_retries=0,
    )
    OpenCodeBackend(config).health()
    backend = OpenCodeGenerateBackend(config, timeout_s=args.timeout)

  summary = run_judge_v0_batch(
    cve_ids=_parse_cves(args.cves),
    judge_packet_root=args.judge_packet_root,
    detailed_evidence_root=args.detailed_evidence_root,
    slimming_root=args.slimming_root,
    dataset=args.dataset,
    out_dir=args.out_dir,
    backend=backend,
    reset=args.reset,
  )
  summary.update(
    {
      "provider_id": "fixture" if args.fixture else args.provider_id,
      "model_id": "fixture" if args.fixture else args.model_id,
      "base_url": "" if args.fixture else args.base_url,
      "execution_mode": "fixture" if args.fixture else "clean_smoke",
    }
  )
  (args.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
  print(json.dumps(summary, ensure_ascii=False, indent=2))


def _parse_cves(values: list[str]) -> list[str]:
  output: list[str] = []
  for value in values:
    output.extend(item.strip() for item in value.split(",") if item.strip())
  return output


if __name__ == "__main__":
  main()
