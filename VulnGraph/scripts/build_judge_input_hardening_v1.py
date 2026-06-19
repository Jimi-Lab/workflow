from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from vulngraph.workflows.judge_input_hardening import build_judge_input_hardening_v1


def main() -> None:
  parser = argparse.ArgumentParser(description="Build deterministic Judge blind/audit input packets from raw candidate artifacts.")
  parser.add_argument("--readiness-dir", required=True)
  parser.add_argument("--anchor-artifact", required=True)
  parser.add_argument("--version-probe", required=True)
  parser.add_argument("--dataset", required=True)
  parser.add_argument("--repo-root", required=True)
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--top-k", type=int, default=5)
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  out_dir = Path(args.out_dir)
  if args.reset and out_dir.exists():
    shutil.rmtree(out_dir)

  summary = build_judge_input_hardening_v1(
    readiness_dir=args.readiness_dir,
    anchor_artifact=args.anchor_artifact,
    version_probe=args.version_probe,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=out_dir,
    top_k=args.top_k,
  )
  print(f"wrote {out_dir}")
  print(f"cases_total={summary['cases_total']}")
  print(f"judge_ready_cases_after_hardening={summary['judge_ready_cases_after_hardening']}")
  print(f"strong_ready_cases={summary['strong_ready_cases']}")
  print(f"fallback_ready_cases={summary['fallback_ready_cases']}")
  print(f"no_candidate_cases={summary['no_candidate_cases']}")
  print(f"cve_2020_27814_repaired={summary['cve_2020_27814_repaired']}")
  print(f"blind_packet_forbidden_field_scan_ok={summary['blind_packet_forbidden_field_scan_ok']}")


if __name__ == "__main__":
  main()
