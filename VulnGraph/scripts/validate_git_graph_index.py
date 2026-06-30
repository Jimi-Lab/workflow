from __future__ import annotations

import argparse
import json

from vulngraph.git_graph.run import validate_index_run


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate reusable Git graph indexes.")
    parser.add_argument("--index-root", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--repo-root", required=True)
    args = parser.parse_args()
    result = validate_index_run(
        dataset_path=args.dataset,
        repo_root=args.repo_root,
        index_root=args.index_root,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["all_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

