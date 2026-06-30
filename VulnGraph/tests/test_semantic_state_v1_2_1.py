from __future__ import annotations

import hashlib

from vulngraph.workflows.history_event_candidates_v1_2_1 import materialize_semantic_history_events
from vulngraph.workflows.semantic_state_v1_2_1 import SemanticStateVerifier, cluster_history_events


def _sha(char: str) -> str:
  return char * 40


def _event(event_id: str, event_sha: str, predicate: str = "vp-1") -> dict:
  line = "if (len > capacity) return ERROR;"
  return {
    "event_candidate_id": event_id,
    "source_anchor_id": "anchor-1",
    "event_commit_sha": event_sha,
    "fix_commit_sha": _sha("f"),
    "patch_family_id": "family-1",
    "path_before": "src/parser.c",
    "old_line_start": 12,
    "old_line_end": 12,
    "old_line_text": line,
    "old_line_text_hash": hashlib.sha256(line.encode()).hexdigest(),
    "root_cause_binding_refs": ["rc-1"],
    "vulnerable_predicate_refs": [predicate],
    "fix_predicate_refs": ["fp-1"],
    "evidence_refs": [f"history_event:{event_id}"],
    "candidate_source": "strong",
    "branch_context_ids": ["branch-1"],
    "lifecycle": "raw_candidate",
  }


class SemanticRunner:
  def __init__(self, files: dict[tuple[str, str], str], aliases: dict[str, list[str]] | None = None) -> None:
    self.files = files
    self.aliases = aliases or {}

  def read_file(self, commitish: str, path: str) -> str | None:
    return self.files.get((commitish, path))

  def related_paths(self, commitish: str, path: str) -> list[str]:
    return self.aliases.get(path, [])


def test_verifier_reports_exact_normalized_and_rename_aware_states() -> None:
  exact = _event("event-exact", _sha("a"))
  normalized = dict(exact, event_candidate_id="event-normalized", old_line_text="while (remaining > 0) { /* old note */")
  normalized["old_line_text_hash"] = hashlib.sha256(normalized["old_line_text"].encode()).hexdigest()
  renamed = dict(exact, event_candidate_id="event-renamed", path_before="src/old.c")
  verifier = SemanticStateVerifier(SemanticRunner(
    {
      ("v1", "src/parser.c"): "if (len > capacity) return ERROR;\n",
      ("v2", "src/parser.c"): "while   (remaining > 0) { // renamed note\n",
      ("v3", "src/new.c"): "if (len > capacity) return ERROR;\n",
    },
    {"src/old.c": ["src/new.c"]},
  ))

  assert verifier.verify(exact, "v1")["state"] == "present_exact"
  assert verifier.verify(normalized, "v2")["state"] == "present_normalized"
  rename_result = verifier.verify(renamed, "v3")
  assert rename_result["state"] == "present_exact"
  assert rename_result["matched_path"] == "src/new.c"
  assert rename_result["path_resolution"] == "rename_or_move"


def test_verifier_uses_predicate_fingerprint_without_event_ancestry() -> None:
  event = _event("event-1", _sha("a"))
  event["function_name"] = "parse"
  event["semantic_context"] = ["len", "capacity", "ERROR"]
  runner = SemanticRunner({("maintenance-v1", "src/parser.c"): "int parse(void) {\n  if ((len) > capacity) { return ERROR; }\n}\n"})

  result = SemanticStateVerifier(runner).verify(event, "maintenance-v1")

  assert result["state"] == "present_predicate_equivalent"
  assert result["event_ancestry_required"] is False


def test_verifier_returns_unknown_when_line_hash_is_missing() -> None:
  event = _event("event-1", _sha("a"))
  event["old_line_text_hash"] = ""

  result = SemanticStateVerifier(SemanticRunner({("v1", "src/parser.c"): event["old_line_text"]})).verify(event, "v1")

  assert result["state"] == "unknown"
  assert result["reason"] == "missing_old_line_text_hash"


def test_history_event_cluster_treats_blame_variants_as_alternatives() -> None:
  first, second = _event("event-normal", _sha("a")), _event("event-w", _sha("b"))
  judgments = [
    {"event_candidate_id": "event-normal", "decision": "selected", "boundary_role": "primary_boundary"},
    {"event_candidate_id": "event-w", "decision": "uncertain", "boundary_role": "branch_equivalent_boundary"},
  ]

  clusters = cluster_history_events([first, second], judgments)

  assert len(clusters) == 1
  assert clusters[0]["resolution"] == "selected_primary"
  assert set(clusters[0]["alternative_event_candidate_ids"]) == {"event-normal", "event-w"}


def test_history_event_cluster_never_merges_distinct_predicates() -> None:
  assert len(cluster_history_events([_event("event-a", _sha("a"), "vp-a"), _event("event-b", _sha("a"), "vp-b")], [])) == 2


def test_bound_root_hunk_semantic_declaration_is_retained() -> None:
  candidate = {
    "candidate_id": "line-1", "candidate_commit_sha": _sha("a"), "candidate_source": "fallback",
    "candidate_selection_mode": "pre_fix_function_body", "path_before": "src/state.c",
    "old_line_start": 7, "old_line_end": 7, "old_line_text": "callback_fn on_error;",
    "line_text_hash": "hash", "fix_commit_id": f"fix-commit:repo:{_sha('f')}",
    "patch_family_id": "family-1", "patch_hunk_id": "hunk-1", "root_cause_hunk_match": True,
    "semantic_role": "callback_activation", "root_cause_binding_refs": ["rc-1"],
    "vulnerable_predicate_refs": ["vp-1"], "fix_predicate_refs": ["fp-1"],
    "evidence_refs": ["candidate:line-1"], "risk_flags": [],
  }
  evidence = {
    "candidate_identity": {"candidate_id": "line-1", "fix_commit_sha": _sha("f")},
    "blame_variants": {"variants": [{"variant": "normal", "exit_code": 0, "blamed_commit_sha": _sha("a")}]},
    "line_survival_evidence": {}, "risk_flags": [], "confidence_features": ["root_cause_predicate_bound"],
  }

  events = materialize_semantic_history_events([candidate], [evidence])

  assert len(events) == 1
  assert events[0]["fallback_semantic_taxonomy"] == "callback_activation_declaration"


def test_unbound_declaration_remains_deterministic_noise() -> None:
  candidate = {
    "candidate_id": "line-1", "candidate_source": "fallback", "old_line_text": "int value;",
    "root_cause_binding_refs": [], "vulnerable_predicate_refs": [],
  }
  assert materialize_semantic_history_events([candidate], []) == []
