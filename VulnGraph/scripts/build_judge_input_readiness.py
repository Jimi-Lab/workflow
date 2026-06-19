from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from vulngraph.workflows.judge_input_readiness import build_judge_input_readiness


def main() -> None:
  parser = argparse.ArgumentParser(description="Build frozen Judge input packets from raw SZZ candidate artifacts.")
  parser.add_argument("--anchor-artifact", required=True)
  parser.add_argument("--version-probe", required=True)
  parser.add_argument("--ten-artifact", required=False)
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  out_dir = Path(args.out_dir)
  if args.reset and out_dir.exists():
    shutil.rmtree(out_dir)

  summary = build_judge_input_readiness(
    anchor_artifact=args.anchor_artifact,
    version_probe=args.version_probe,
    ten_artifact=args.ten_artifact,
    out_dir=out_dir,
  )
  print(f"wrote {out_dir}")
  print(f"cases_total={summary['cases_total']}")
  print(f"candidate_ready_after_fallback={summary['candidate_ready_after_fallback']}")
  print(f"strong_candidate_ready={summary['strong_candidate_ready']}")
  print(f"fallback_candidate_ready={summary['fallback_candidate_ready']}")
  print(f"no_candidate_cases={summary['no_candidate_cases']}")


if __name__ == "__main__":
  main()
