from __future__ import annotations

import pytest

pytest.skip(
  "v1.2.3 predicate-pair semantic-state modules are outside Git Graph Index v1 scope",
  allow_module_level=True,
)

from vulngraph.workflows.predicate_pair_inventory_v1_2_3 import (
  build_atoms_from_patch,
)
from vulngraph.workflows.predicate_pair_verifier_v1_2_3 import (
  match_atom_in_source,
)
from vulngraph.workflows.release_tag_universe_v1_2_3 import (
  audit_release_tag_set,
  canonical_release_universe,
)
from vulngraph.workflows.tri_state_policy_v1_2_3 import (
  aggregate_applicable_contexts,
  classify_context_state_v1_2_3,
)


def test_semantic_context_missing_is_unknown() -> None:
  result = classify_context_state_v1_2_3(
    vulnerability_evidence={
      "state": "absent",
      "tier": "unavailable",
      "reason": "semantic_context_missing",
      "scope_verified": False,
    },
    fix_code_evidence={"state": "absent", "tier": "unavailable"},
    fix_commit_reachability_state="absent",
    fix_group_completion_state="unknown",
    prerequisite_state="complete",
    branch_applicability="confirmed",
  )

  assert result["final_tri_state"] == "unknown"
  assert result["final_reason"] == "semantic_context_missing"


def test_normalized_only_match_is_not_strong_presence() -> None:
  result = classify_context_state_v1_2_3(
    vulnerability_evidence={
      "state": "present",
      "tier": "lexical_normalized",
      "reason": "normalized_text_only",
      "scope_verified": True,
    },
    fix_code_evidence={"state": "absent", "tier": "code_exact"},
    fix_commit_reachability_state="absent",
    fix_group_completion_state="incomplete",
    prerequisite_state="complete",
    branch_applicability="confirmed",
  )

  assert result["final_tri_state"] == "unknown"
  assert result["normalized_only_confirmation"] is False


def test_fix_reachability_absent_cannot_confirm_affected() -> None:
  result = classify_context_state_v1_2_3(
    vulnerability_evidence={
      "state": "present",
      "tier": "code_exact",
      "reason": "exact_statement",
      "scope_verified": True,
    },
    fix_code_evidence={"state": "unknown", "tier": "unavailable"},
    fix_commit_reachability_state="absent",
    fix_group_completion_state="unknown",
    prerequisite_state="complete",
    branch_applicability="confirmed",
  )

  assert result["final_tri_state"] == "unknown"
  assert result["reachability_only_affected"] is False


def test_ambiguous_context_blocks_confirmed_context() -> None:
  combined = aggregate_applicable_contexts([
    {"branch_applicability": "confirmed", "final_tri_state": "confirmed_affected"},
    {"branch_applicability": "ambiguous", "final_tri_state": "unknown"},
  ])

  assert combined["final_tri_state"] == "unknown"
  assert combined["final_reason"] == "ambiguous_branch_context_applicability"


def test_canonical_release_universe_has_stable_hash_and_exact_set_audit() -> None:
  universe = canonical_release_universe(
    "repo",
    [
      {"tag": "v1.0.0", "commit_sha": "a" * 40, "source_ref": "refs/tags/v1.0.0"},
      {"tag": "v1.0.1rc1", "commit_sha": "b" * 40, "source_ref": "refs/tags/v1.0.1rc1"},
      {"tag": "v1.1.0", "commit_sha": "c" * 40, "source_ref": "refs/tags/v1.1.0"},
    ],
  )

  assert [item["tag"] for item in universe["ordered_release_tags"]] == ["v1.0.0", "v1.1.0"]
  assert len(universe["sha256"]) == 64
  assert audit_release_tag_set(["v1.0.0", "v1.1.0"], universe)["set_equal"] is True
  mismatch = audit_release_tag_set(["v1.0.0", "extra"], universe)
  assert mismatch["missing_tags"] == ["v1.1.0"]
  assert mismatch["extra_tags"] == ["extra"]


def test_patch_inventory_builds_vulnerability_and_fix_atoms() -> None:
  diff = """diff --git a/a.c b/a.c
--- a/a.c
+++ b/a.c
@@ -10,2 +10,4 @@ int parse(int len) {
-  copy(buf, src, len);
+  if (len > sizeof(buf))
+    return -1;
+  copy(buf, src, len);
 }
"""

  inventory = build_atoms_from_patch(
    cve_id="CVE-X",
    repo="repo",
    fix_commit_sha="f" * 40,
    diff_text=diff,
    fix_group_id="fix-group-1",
    patch_family_id="patch-family-1",
    predicate_bindings={"vulnerable": ["vp-1"], "fix": ["fp-1"]},
  )

  assert any(item["atom_type"] == "VulnerabilityPredicateAtom" for item in inventory["atoms"])
  assert any(item["atom_type"] == "FixPredicateAtom" for item in inventory["atoms"])
  assert inventory["predicate_pairs"]
  assert {item["path"] for item in inventory["atoms"]} == {"a.c"}


def test_tree_sitter_ast_match_is_distinct_from_lexical_normalization() -> None:
  atom = {
    "statement": "if (len > sizeof(buf)) return -1;",
    "path": "a.c",
    "function_name": "parse",
  }
  source = """
int parse(int len) {
  if (
      len > sizeof(buf)
  ) {
    return -1;
  }
  return 0;
}
"""

  result = match_atom_in_source(atom, source)

  assert result["state"] == "present"
  assert result["tier"] == "ast_or_expression_normalized"
  assert result["scope_verified"] is True
