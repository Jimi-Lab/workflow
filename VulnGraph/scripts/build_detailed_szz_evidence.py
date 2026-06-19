from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from vulngraph.workflows.detailed_szz_evidence import build_detailed_szz_evidence_v0


def main() -> None:
  parser = argparse.ArgumentParser(description="Build deterministic detailed SZZ evidence packets for Judge inputs.")
  parser.add_argument("--slimming-root", required=True)
  parser.add_argument("--judge-packet-root", required=True)
  parser.add_argument("--dataset", required=True)
  parser.add_argument("--repo-root", required=True)
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  out_dir = Path(args.out_dir)
  if args.reset and out_dir.exists():
    shutil.rmtree(out_dir)

  summary = build_detailed_szz_evidence_v0(
    slimming_root=args.slimming_root,
    judge_packet_root=args.judge_packet_root,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=out_dir,
  )
  print(f"wrote {out_dir}")
  print(f"cases_total={summary['cases_total']}")
  print(f"candidates_total={summary['candidates_total']}")
  print(f"evidence_packet_generated_count={summary['evidence_packet_generated_count']}")
  print(f"blame_variant_success_rate={summary['blame_variant_success_rate']}")
  print(f"blame_variant_disagreement_count={summary['blame_variant_disagreement_count']}")
  print(f"lifecycle={summary['lifecycle']}")


if __name__ == "__main__":
  main()
