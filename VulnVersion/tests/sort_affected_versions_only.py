from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import sys


THIS_FILE = Path(__file__).resolve()
REPO_ROOT = THIS_FILE.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulnversion.stage3_verify.version_registry import line_family_key, line_key, parse_version


def _line_sort_key(repo: str, line: str) -> tuple[Any, ...]:
    if repo == "curl":
        return (0, 0, 0, 0)

    if repo == "openssl":
        if line.startswith("fips-"):
            nums = tuple(int(x) for x in re.findall(r"\d+", line))
            return (1, *nums)
        if line.startswith("engine-"):
            nums = tuple(int(x) for x in re.findall(r"\d+", line))
            return (2, *nums)
        nums = tuple(int(x) for x in re.findall(r"\d+", line))
        return (0, *nums)

    nums = tuple(int(x) for x in re.findall(r"\d+", line))
    return (0, *nums) if nums else (99, line)


def _tag_sort_key(repo: str, tag: str) -> tuple[Any, ...]:
    line = line_key(repo, tag)
    family = line_family_key(repo, line)
    return (family, _line_sort_key(repo, line), parse_version(repo, tag), tag)


def _sort_affected_versions(repo: str, tags: list[str]) -> list[str]:
    return sorted(tags, key=lambda tag: _tag_sort_key(repo, tag))


def _validate_no_semantic_change(
    original: dict[str, Any],
    sorted_dataset: dict[str, Any],
) -> dict[str, Any]:
    same_cve_keys = set(original.keys()) == set(sorted_dataset.keys())
    changed_order_cves = 0
    invalid_cves: list[str] = []

    for cve_id, original_record in original.items():
        sorted_record = sorted_dataset[cve_id]
        original_tags = list(original_record.get("affected_version", []))
        sorted_tags = list(sorted_record.get("affected_version", []))
        if original_tags != sorted_tags:
            changed_order_cves += 1
        if Counter(original_tags) != Counter(sorted_tags):
            invalid_cves.append(cve_id)

    return {
        "same_cve_keys": same_cve_keys,
        "total_cves": len(original),
        "changed_order_cves": changed_order_cves,
        "invalid_cves": invalid_cves,
        "is_permutation_only": same_cve_keys and not invalid_cves,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sort affected_version lists only; do not add/remove any CVE or tag."
    )
    parser.add_argument(
        "--input",
        default=str(REPO_ROOT / "DataSet" / "BaseDataOrder.json"),
        help="Path to input dataset JSON",
    )
    parser.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "tests" / "affected_version_sorted"),
        help="Directory for sorted-only output and validation report",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with input_path.open("r", encoding="utf-8") as f:
        dataset = json.load(f)

    sorted_dataset: dict[str, Any] = {}
    repo_changed_counter: Counter[str] = Counter()

    for cve_id, record in dataset.items():
        repo = str(record.get("repo", ""))
        affected_versions = list(record.get("affected_version", []))
        sorted_versions = _sort_affected_versions(repo, affected_versions)

        new_record = dict(record)
        new_record["affected_version"] = sorted_versions
        sorted_dataset[cve_id] = new_record

        if affected_versions != sorted_versions:
            repo_changed_counter[repo] += 1

    validation = _validate_no_semantic_change(dataset, sorted_dataset)
    validation["repos_with_reordered_cves"] = dict(sorted(repo_changed_counter.items()))

    sorted_json_path = out_dir / "BaseDataSet.sorted_only.json"
    validation_path = out_dir / "sort_validation.json"

    with sorted_json_path.open("w", encoding="utf-8") as f:
        json.dump(sorted_dataset, f, ensure_ascii=False, indent=4)
    with validation_path.open("w", encoding="utf-8") as f:
        json.dump(validation, f, ensure_ascii=False, indent=4)

    print(f"INPUT={input_path}")
    print(f"SORTED_OUT={sorted_json_path}")
    print(f"VALIDATION_OUT={validation_path}")
    print(f"TOTAL_CVES={validation['total_cves']}")
    print(f"CHANGED_ORDER_CVES={validation['changed_order_cves']}")
    print(f"IS_PERMUTATION_ONLY={validation['is_permutation_only']}")
    if validation["invalid_cves"]:
        print(f"INVALID_CVES={len(validation['invalid_cves'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
