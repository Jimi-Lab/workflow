from __future__ import annotations

from collections import Counter

from vulngraph.workflows.benchmark_sampling import (
  allocate_repo_quotas,
  parse_unified_diff,
  select_cases,
)


def _case(cve_id: str, repo: str, patch: str, scope: str, *, merge: bool = False, multi: bool = False) -> dict:
  return {
    "cve_id": cve_id,
    "repo": repo,
    "patch_type": patch,
    "modification_scope": scope,
    "branch_context": "multi_branch",
    "merge_fix": merge,
    "multi_fix": multi,
    "classification_errors": [],
  }


def test_parse_unified_diff_counts_source_hunks_and_functions() -> None:
  parsed = parse_unified_diff(
    """diff --git a/lib/a.c b/lib/a.c
--- a/lib/a.c
+++ b/lib/a.c
@@ -10,1 +10,2 @@ int vulnerable(int x) {
-old_call(x);
+guard(x);
+old_call(x);
diff --git a/docs/readme.md b/docs/readme.md
--- a/docs/readme.md
+++ b/docs/readme.md
@@ -1 +1 @@
-old
+new
"""
  )
  assert parsed["status"] == "ok"
  assert parsed["added_lines"] == 2
  assert parsed["deleted_lines"] == 1
  assert parsed["source_paths"] == ["lib/a.c"]
  assert parsed["function_contexts"] == ["lib/a.c:vulnerable"]


def test_allocate_repo_quotas_is_exact_and_respects_capacity() -> None:
  counts = Counter({"large": 100, "medium": 20, "small": 7})
  quotas = allocate_repo_quotas(counts, 30, minimum=5)
  assert sum(quotas.values()) == 30
  assert all(quotas[repo] <= counts[repo] for repo in counts)
  assert all(quotas[repo] >= 5 for repo in counts)


def test_selection_is_deterministic_and_keeps_repo_quotas() -> None:
  pool = [
    _case("CVE-1", "a", "mixed", "single_function"),
    _case("CVE-2", "a", "add_only", "multi_file", merge=True),
    _case("CVE-3", "a", "del_only", "multi_function_single_file"),
    _case("CVE-4", "b", "mixed", "single_function"),
    _case("CVE-5", "b", "add_only", "multi_file", multi=True),
    _case("CVE-6", "b", "del_only", "multi_function_single_file"),
  ]
  first = select_cases(pool, repo_quotas={"a": 2, "b": 2}, seed=7)
  second = select_cases(pool, repo_quotas={"a": 2, "b": 2}, seed=7)
  assert [item["cve_id"] for item in first] == [item["cve_id"] for item in second]
  assert Counter(item["repo"] for item in first) == Counter({"a": 2, "b": 2})
  assert [item["selection_rank"] for item in first] == [1, 2, 3, 4]
