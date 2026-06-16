from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnversion.git_ops.repo import GitRepo
import vulnversion.stage3_verify.vuln_tree as vuln_tree_mod
from vulnversion.stage3_verify.vuln_tree import build_vuln_tree_plan, write_vuln_tree_artifacts


def normalize_fix_families(fixing_commits: list[Any] | None) -> list[list[str]]:
    """Compatibility wrapper for legacy callers/tests.

    Step3 no longer uses the old family-planning pipeline, but some callers
    still import this helper to normalize the dataset's fix-commit layout.
    """
    return vuln_tree_mod.normalize_commit_groups(fixing_commits)


def build_tag_plan(
    *,
    repo_path: str,
    cve_id: str,
    fixing_commits: list[Any] | None,
    rci_path: str | Path | None = None,
    vuln_commit: str | None = None,
    tags_glob: str | None = None,
    mode: str = "eval",
) -> dict[str, Any]:
    """Build the Step3 tag plan.

    Step3 planning is now VulnTree-only. Legacy frontier heuristics, bounded
    unknown-line scans, max-tag truncation, and cross-line early-stop planning
    were removed intentionally. Explicit-tag verification is handled directly
    in ``verify_tags.py`` and does not use this planner.
    """
    vuln_tree_mod.GitRepo = GitRepo
    return build_vuln_tree_plan(
        repo_path=repo_path,
        cve_id=cve_id,
        fixing_commits=fixing_commits,
        rci_path=rci_path,
        vuln_commit=vuln_commit,
        tags_glob=tags_glob,
        mode=mode,
    )


def write_tag_plan(out_dir: str | Path, tag_plan: dict[str, Any]) -> Path:
    out = Path(out_dir) / "tag_plan.json"
    out.write_text(json.dumps(tag_plan, ensure_ascii=False, indent=2), encoding="utf-8")
    if tag_plan.get("plan_kind") == "vuln_tree":
        write_vuln_tree_artifacts(out_dir, tag_plan)
    return out
