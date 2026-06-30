from __future__ import annotations

from vulngraph.workflows.history_root_boundary_v1 import (
    apply_history_root_boundary,
    build_synthetic_history_root_boundary_event,
    detect_history_root_boundary,
    extract_boundary_verification_inputs,
    is_invalid_primary_boundary_anchor,
    verify_history_root_boundary_evidence,
)
from vulngraph.git_graph.schema import QueryResult, QueryStatus


ROOT_SHA = "3ed852eea50f9d4cd633efb8c2b054b8e33c2530"
RELATED_SHA = "13aeafe87d395d3a00f9907c7a8cada8588ae2a7"
GOOD_SHA = "d021f2e8a0067fc769652f27afec9024c0d02b3d"


def _root_event() -> dict:
    return {
        "cve_id": "CVE-2020-19667",
        "repo_id": "ImageMagick",
        "event_id": f"event:{ROOT_SHA[:12]}",
        "event_commit_sha": ROOT_SHA,
        "rank": 2,
        "gate_score": 30,
        "gate_decision": "promoted",
        "gate_reasons": ["root_boundary"],
        "promotion_sources": ["blame_normal"],
        "role_proposals": ["root_boundary", "unresolved_boundary"],
        "source_candidate_ids": ["source-root"],
        "source_refs": [{"candidate_id": "source-root", "source": "blame_normal"}],
        "evidence_features": {
            "root_or_boundary_source": True,
            "invalid_anchor_count": 1,
            "anchor_paths": ["coders/xpm.c"],
        },
        "lifecycle": "raw_history_event_candidate",
    }


def _related_event() -> dict:
    return {
        "cve_id": "CVE-2020-19667",
        "repo_id": "ImageMagick",
        "event_id": f"event:{RELATED_SHA[:12]}",
        "event_commit_sha": RELATED_SHA,
        "rank": 3,
        "gate_score": 45,
        "gate_decision": "promoted",
        "gate_reasons": ["pickaxe_related"],
        "promotion_sources": ["log_S"],
        "role_proposals": ["possible_introduction_event"],
        "source_candidate_ids": ["source-related"],
        "source_refs": [{"candidate_id": "source-related", "source": "log_S"}],
        "evidence_features": {"root_or_boundary_source": False, "invalid_anchor_count": 0},
        "lifecycle": "raw_history_event_candidate",
    }


def _good_event() -> dict:
    return {
        "cve_id": "CVE-2020-8231",
        "repo_id": "curl",
        "event_id": f"event:{GOOD_SHA[:12]}",
        "event_commit_sha": GOOD_SHA,
        "rank": 1,
        "gate_score": 90,
        "gate_decision": "promoted",
        "gate_reasons": ["direct_candidate"],
        "promotion_sources": ["direct_candidate"],
        "role_proposals": ["possible_introduction_event"],
        "source_candidate_ids": ["source-good"],
        "source_refs": [{"candidate_id": "source-good", "source": "direct_candidate"}],
        "evidence_features": {"root_or_boundary_source": False, "invalid_anchor_count": 0},
        "lifecycle": "raw_history_event_candidate",
    }


def _history_packet(candidate_id: str, sha: str, *, is_root: bool, line_text: str = "}") -> dict:
    return {
        "candidate_id": candidate_id,
        "repo_id": "ImageMagick",
        "candidate_origin": {
            "anchor_path": "coders/xpm.c",
            "old_line_start": 120,
            "old_line_end": 120,
            "old_line_text": line_text,
            "old_line_text_hash": "hash",
            "root_cause_hypothesis_bindings": ["hyp-xpm"],
            "vulnerable_predicate_bindings": ["vp-xpm"],
            "fix_predicate_bindings": ["fp-xpm"],
        },
        "candidate_event": {
            "candidate_commit_sha": sha,
            "parent_shas": [] if is_root else ["p" * 40],
            "is_root": is_root,
            "boundary_marker": is_root,
            "changed_paths": ["coders/xpm.c"],
        },
    }


class FakeRootBoundaryQuery:
    def __init__(
        self,
        *,
        root_parent_count: int,
        root_file: str | None = None,
        fix_parent_file: str | None = None,
        fix_diff: str = "",
        root_count: int = 1,
        ancestry: bool | None = True,
    ):
        self.root_parent_count = root_parent_count
        self.root_file = root_file
        self.fix_parent_file = fix_parent_file
        self.fix_diff = fix_diff
        self.root_count = root_count
        self.ancestry = ancestry

    def get_commit(self, sha: str) -> QueryResult[dict]:
        if sha == ROOT_SHA:
            return QueryResult(QueryStatus.FOUND, {"commit_sha": sha, "parent_count": self.root_parent_count, "is_root": self.root_parent_count == 0})
        if sha == "f" * 40:
            return QueryResult(QueryStatus.FOUND, {"commit_sha": sha, "parent_count": 1, "is_root": False})
        if sha == "p" * 40:
            return QueryResult(QueryStatus.FOUND, {"commit_sha": sha, "parent_count": 1, "is_root": False})
        return QueryResult(QueryStatus.NOT_FOUND)

    def get_parents(self, sha: str) -> QueryResult[list[str]]:
        if sha == ROOT_SHA:
            return QueryResult(QueryStatus.FOUND, [] if self.root_parent_count == 0 else ["p" * 40])
        if sha == "f" * 40:
            return QueryResult(QueryStatus.FOUND, ["p" * 40])
        return QueryResult(QueryStatus.NOT_FOUND)

    def iter_commits(self):
        yield {"commit_sha": ROOT_SHA, "is_root": True}
        for index in range(max(0, self.root_count - 1)):
            yield {"commit_sha": f"{index + 1:040x}", "is_root": True}

    def read_file_at_revision(self, revision: str, path: str, *, max_bytes: int = 4 * 1024 * 1024) -> QueryResult[str]:
        if revision == ROOT_SHA:
            if self.root_file is None:
                return QueryResult(QueryStatus.NOT_FOUND, reason="missing_root_path")
            return QueryResult(QueryStatus.FOUND, self.root_file)
        if revision == "p" * 40:
            if self.fix_parent_file is None:
                return QueryResult(QueryStatus.NOT_FOUND, reason="missing_fix_parent_path")
            return QueryResult(QueryStatus.FOUND, self.fix_parent_file)
        return QueryResult(QueryStatus.NOT_FOUND)

    def get_commit_diff(self, sha: str) -> QueryResult[str]:
        if sha == "f" * 40:
            return QueryResult(QueryStatus.FOUND, self.fix_diff)
        return QueryResult(QueryStatus.NOT_FOUND)

    def is_ancestor(self, ancestor: str, descendant: str) -> QueryResult[bool]:
        if self.ancestry is None:
            return QueryResult(QueryStatus.CENSORED, reason="ancestry_query_failed")
        return QueryResult(QueryStatus.FOUND, self.ancestry)


def test_invalid_structural_anchors_cannot_be_primary_boundary_evidence() -> None:
    assert is_invalid_primary_boundary_anchor("}") is True
    assert is_invalid_primary_boundary_anchor("break;") is True
    assert is_invalid_primary_boundary_anchor("") is True
    assert is_invalid_primary_boundary_anchor("/* comment */") is True
    assert is_invalid_primary_boundary_anchor("memset(target,0,length);") is False


def test_packet_root_claim_without_gitgraph_query_is_not_accepted() -> None:
    history = {"source-root": _history_packet("source-root", ROOT_SHA, is_root=True)}

    boundary = detect_history_root_boundary(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        promoted_events=[_root_event()],
        history_packets_by_candidate_id=history,
    )

    assert boundary is None


def test_packet_root_claim_is_rejected_when_gitgraph_parent_count_is_not_zero() -> None:
    query = FakeRootBoundaryQuery(root_parent_count=1, root_file="static Image *ReadXPMImage(void) {}", fix_parent_file="same")
    history = {
        "source-root": {
            **_history_packet("source-root", ROOT_SHA, is_root=True),
            "candidate_origin": {
                **_history_packet("source-root", ROOT_SHA, is_root=True)["candidate_origin"],
                "fix_commit_sha": "f" * 40,
                "fix_parent_sha": "p" * 40,
            },
        }
    }

    boundary = detect_history_root_boundary(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        promoted_events=[_root_event()],
        history_packets_by_candidate_id=history,
        git_graph_query=query,
    )

    assert boundary is None


def test_gitgraph_confirmed_root_boundary_contains_source_state_evidence() -> None:
    root_file = """
static char *ParseXPMColor(char *color) { return color; }
static char *CopyXPMColor(char *target,const char *source,size_t length) { return target; }
static Image *ReadXPMImage(const ImageInfo *image_info,ExceptionInfo *exception) {
  char target[MaxTextExtent], symbolic[MaxTextExtent];
  return image;
}
"""
    fix_diff = """
diff --git a/coders/xpm.c b/coders/xpm.c
@@ -1,4 +1,6 @@
+        (void) memset(target,0,sizeof(target));
+        (void) memset(symbolic,0,sizeof(symbolic));
"""
    query = FakeRootBoundaryQuery(
        root_parent_count=0,
        root_file=root_file,
        fix_parent_file=root_file,
        fix_diff=fix_diff,
    )

    evidence = verify_history_root_boundary_evidence(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        boundary_commit_sha=ROOT_SHA,
        fix_relevant_paths=["coders/xpm.c"],
        fix_commit_shas=["f" * 40],
        fix_parent_shas=["p" * 40],
        source_terms=["ReadXPMImage", "ParseXPMColor", "target", "symbolic", "CopyXPMColor"],
        query=query,
    )

    assert evidence["verification_status"] == "accepted"
    assert evidence["git_graph_evidence"]["parent_count"] == 0
    assert evidence["git_graph_evidence"]["is_repo_root"] is True
    assert evidence["git_graph_evidence"]["boundary_to_fix_ancestry"] == [
        {
            "fix_commit_sha": "f" * 40,
            "fix_parent_shas": ["p" * 40],
            "fix_commit_query_status": "found",
            "fix_commit_is_descendant_of_boundary": True,
            "fix_parent_ancestry": [],
            "is_descendant_of_boundary": True,
        }
    ]
    assert evidence["source_state_evidence"]["path_exists_at_root"] is True
    assert evidence["source_state_evidence"]["path_exists_at_fix_parent"] is True
    assert evidence["source_state_evidence"]["relevant_code_state_at_root"] == "present"
    assert evidence["source_state_evidence"]["vulnerable_predicate_state_at_root"] == "not_verified"
    assert evidence["source_state_evidence"]["fix_predicate_state_at_root"] == "not_verified"
    assert set(evidence["source_state_evidence"]["mechanism_signature_terms_present"]) >= {
        "ReadXPMImage",
        "ParseXPMColor",
        "target",
        "CopyXPMColor",
    }
    assert evidence["source_state_evidence"]["fix_hardening_terms_present_at_root"] is False
    assert evidence["state_at_boundary"] == "vulnerability_relevant_code_present_at_root"
    assert evidence["source_state_evidence"]["root_source_excerpt_refs"]
    assert evidence["source_state_evidence"]["fix_diff_excerpt_refs"]


def test_root_that_is_not_ancestor_of_fix_is_not_accepted() -> None:
    root_file = "static Image *ReadXPMImage(void) { CopyXPMColor(target,p,width); }"
    query = FakeRootBoundaryQuery(
        root_parent_count=0,
        root_file=root_file,
        fix_parent_file=root_file,
        fix_diff="+ memset(target,0,sizeof(target));",
        ancestry=False,
    )

    evidence = verify_history_root_boundary_evidence(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        boundary_commit_sha=ROOT_SHA,
        fix_relevant_paths=["coders/xpm.c"],
        fix_commit_shas=["f" * 40],
        fix_parent_shas=["p" * 40],
        source_terms=["ReadXPMImage", "target"],
        query=query,
    )

    assert evidence["verification_status"] == "failed"
    assert evidence["reason"] == "root_not_ancestor_of_any_related_fix"
    assert evidence["git_graph_evidence"]["boundary_to_fix_ancestry"][0]["is_descendant_of_boundary"] is False


def test_missing_fix_path_at_root_does_not_claim_verified_predicate_state() -> None:
    query = FakeRootBoundaryQuery(
        root_parent_count=0,
        root_file=None,
        fix_parent_file="static Image *ReadXPMImage(void) {}",
        fix_diff="+ memset(target,0,sizeof(target));",
    )

    evidence = verify_history_root_boundary_evidence(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        boundary_commit_sha=ROOT_SHA,
        fix_relevant_paths=["coders/xpm.c"],
        fix_commit_shas=["f" * 40],
        fix_parent_shas=["p" * 40],
        source_terms=["ReadXPMImage", "target"],
        query=query,
    )

    assert evidence["verification_status"] == "failed"
    assert evidence["source_state_evidence"]["path_exists_at_root"] is False
    assert evidence["source_state_evidence"]["vulnerable_predicate_state_at_root"] == "not_verified"
    assert evidence["source_state_evidence"]["fix_predicate_state_at_root"] == "not_verified"
    assert evidence["state_at_boundary"] == "unknown"


def test_extract_boundary_verification_inputs_from_history_packets() -> None:
    packet = _history_packet("source-root", ROOT_SHA, is_root=True, line_text="count=CopyXPMColor(key,p,width);")
    packet["candidate_origin"]["fix_commit_sha"] = "f" * 40
    packet["candidate_origin"]["fix_parent_sha"] = "p" * 40
    packet["candidate_origin"]["anchor_path"] = "coders/xpm.c"

    inputs = extract_boundary_verification_inputs({"source-root": packet})

    assert inputs["fix_relevant_paths"] == ["coders/xpm.c"]
    assert inputs["fix_commit_shas"] == ["f" * 40]
    assert inputs["fix_parent_shas"] == ["p" * 40]
    assert "CopyXPMColor" in inputs["source_terms"]


def test_synthetic_root_boundary_event_never_gets_introduction_role() -> None:
    boundary = {
        "boundary_type": "history_root_boundary",
        "boundary_subtype": "repository_import_snapshot",
        "boundary_commit_sha": ROOT_SHA,
        "supporting_candidate_ids": ["source-root"],
        "evidence_refs": [{"source": "git_root_commit", "commit_sha": ROOT_SHA}],
    }

    event = build_synthetic_history_root_boundary_event("CVE-2020-19667", "ImageMagick", boundary)

    assert event["event_id"] == "history-boundary:CVE-2020-19667:root:3ed852eea50f"
    assert event["event_commit_sha"] == ROOT_SHA
    assert "history_root_boundary" in event["role_proposals"]
    assert "possible_introduction_event" not in event["role_proposals"]
    assert event["source_candidate_ids"] == ["source-root"]
    assert event["lifecycle"] == "raw_history_event_candidate"


def test_apply_history_root_boundary_keeps_related_events_non_intro() -> None:
    history = {
        "source-root": _history_packet("source-root", ROOT_SHA, is_root=True, line_text="}"),
        "source-related": _history_packet("source-related", RELATED_SHA, is_root=False, line_text="if (foo)"),
    }

    query = FakeRootBoundaryQuery(
        root_parent_count=0,
        root_file="static Image *ReadXPMImage(void) { CopyXPMColor(target,p,width); }",
        fix_parent_file="static Image *ReadXPMImage(void) { CopyXPMColor(target,p,width); }",
        fix_diff="+ memset(target,0,sizeof(target));",
    )
    for packet in history.values():
        packet["candidate_origin"]["fix_commit_sha"] = "f" * 40
        packet["candidate_origin"]["fix_parent_sha"] = "p" * 40

    transformed, boundary = apply_history_root_boundary(
        cve_id="CVE-2020-19667",
        repo_id="ImageMagick",
        promoted_events=[_related_event(), _root_event()],
        history_packets_by_candidate_id=history,
        top_k=8,
        git_graph_query=query,
    )

    assert boundary is not None
    assert transformed[0]["event_id"].startswith("history-boundary:CVE-2020-19667:root:")
    assert "history_root_boundary" in transformed[0]["role_proposals"]
    for event in transformed:
        assert "possible_introduction_event" not in set(event.get("role_proposals") or [])
    related = next(event for event in transformed if event.get("event_commit_sha") == RELATED_SHA)
    assert set(related["role_proposals"]) & {"prerequisite", "uncertain", "related_state_expansion"}
    assert boundary["projection_hint"] == {
        "first_observed_vulnerable_boundary": ROOT_SHA,
        "introduction_status": "censored_before_or_at_boundary",
        "introduction_commit_verified": False,
    }


def test_non_boundary_cases_are_not_rewritten() -> None:
    transformed, boundary = apply_history_root_boundary(
        cve_id="CVE-2020-8231",
        repo_id="curl",
        promoted_events=[_good_event()],
        history_packets_by_candidate_id={},
        top_k=8,
    )

    assert boundary is None
    assert transformed[0]["event_commit_sha"] == GOOD_SHA
    assert transformed[0]["role_proposals"] == ["possible_introduction_event"]
