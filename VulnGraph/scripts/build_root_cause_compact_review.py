from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.workflows.semantic_baseline import write_compact_review_packet


DEFAULT_RUN_DIR = Path(r"E:\AI\Agent\workflow\VulnGraph\runs\batches\root-cause-v2-semantic-baseline-10")


def main() -> None:
  parser = argparse.ArgumentParser(description="Build compact manual review packets for an existing Root Cause baseline run.")
  parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN_DIR)
  args = parser.parse_args()

  artifacts = write_compact_review_packet(args.run_dir)
  print(json.dumps({key: str(value) for key, value in artifacts.items()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
  main()
