from __future__ import annotations

import argparse
import json

from vulngraph.git_graph.run import TARGET_REPOSITORIES, build_index_run


def main() -> int:
    parser = argparse.ArgumentParser(description="Build reusable read-only Git graph indexes.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repos", nargs="+", choices=TARGET_REPOSITORIES, required=True)
    parser.add_argument("--batch-size", type=int, default=5000)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--reset", action="store_true")
    modes.add_argument("--reset-repo", action="store_true")
    modes.add_argument("--update", action="store_true")
    args = parser.parse_args()
    summary = build_index_run(
        dataset_path=args.dataset,
        repo_root=args.repo_root,
        out_dir=args.out_dir,
        repo_ids=args.repos,
        reset=args.reset,
        reset_repo=args.reset_repo,
        update=args.update,
        batch_size=args.batch_size,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

