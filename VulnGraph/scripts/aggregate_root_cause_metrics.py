from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.workflows.semantic_baseline import write_evaluation_metrics


DEFAULT_EVALUATION = Path(r"E:\AI\Agent\workflow\VulnGraph\runs\batches\root-cause-v2-semantic-baseline-10\evaluation.csv")


def main() -> None:
  parser = argparse.ArgumentParser(description="Aggregate Root Cause semantic metrics from a manually filled evaluation.csv.")
  parser.add_argument("--evaluation", type=Path, default=DEFAULT_EVALUATION)
  parser.add_argument("--out", type=Path, default=None)
  args = parser.parse_args()

  out_path = args.out or args.evaluation.with_name("metrics_summary.json")
  metrics = write_evaluation_metrics(args.evaluation, out_path)
  print(json.dumps(metrics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
  main()
