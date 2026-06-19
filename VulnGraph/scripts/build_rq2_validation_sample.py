from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulngraph.workflows.benchmark_sampling import build_validation_sample


def main() -> None:
  parser = argparse.ArgumentParser(description="Build the deterministic VulnGraph 100-CVE validation/RQ2 sample")
  parser.add_argument("--dataset", required=True)
  parser.add_argument("--development-dataset", required=True)
  parser.add_argument("--repo-root", required=True)
  parser.add_argument("--manifest-out", required=True)
  parser.add_argument("--dataset-out", required=True)
  parser.add_argument("--sample-size", type=int, default=100)
  parser.add_argument("--seed", type=int, default=20260619)
  args = parser.parse_args()

  manifest, dataset = build_validation_sample(
    dataset_path=args.dataset,
    development_dataset_path=args.development_dataset,
    repo_root=args.repo_root,
    sample_size=args.sample_size,
    seed=args.seed,
  )
  manifest_path = Path(args.manifest_out)
  dataset_path = Path(args.dataset_out)
  manifest_path.parent.mkdir(parents=True, exist_ok=True)
  dataset_path.parent.mkdir(parents=True, exist_ok=True)
  manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
  dataset_path.write_text(json.dumps(dataset, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
  print(json.dumps({
    "manifest": str(manifest_path.resolve()),
    "dataset": str(dataset_path.resolve()),
    "selected": len(dataset),
    "distribution": manifest["selected_distribution"],
  }, indent=2))


if __name__ == "__main__":
  main()
