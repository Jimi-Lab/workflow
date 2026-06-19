from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from vulngraph.workflows.szz_fallback_candidates import build_fallback_enhanced_artifact


def main() -> None:
  parser = argparse.ArgumentParser(description="Build a fallback-enhanced SZZ anchor audit artifact.")
  parser.add_argument("--anchor-audit-run", required=True)
  parser.add_argument("--root-cause-run", required=True)
  parser.add_argument("--dataset", required=False)
  parser.add_argument("--repo-root", required=True)
  parser.add_argument("--out-dir", required=True)
  parser.add_argument("--top-k-per-fix-commit", type=int, default=5)
  parser.add_argument("--reset", action="store_true")
  args = parser.parse_args()

  out_dir = Path(args.out_dir)
  if args.reset and out_dir.exists():
    shutil.rmtree(out_dir)

  summary = build_fallback_enhanced_artifact(
    anchor_run=args.anchor_audit_run,
    root_cause_run=args.root_cause_run,
    dataset=args.dataset,
    repo_root=args.repo_root,
    out_dir=out_dir,
    top_k_per_fix_commit=args.top_k_per_fix_commit,
  )
  print(f"wrote {out_dir}")
  print(f"cases_total={summary['cases_total']}")
  print(f"strong_candidate_ready_count={summary['strong_candidate_ready_count']}")
  print(f"fallback_candidate_ready_count={summary['fallback_candidate_ready_count']}")
  print(f"judge_input_ready_count={summary['judge_input_ready_count']}")
  print(f"no_candidate_count={summary['no_candidate_count']}")


if __name__ == "__main__":
  main()
