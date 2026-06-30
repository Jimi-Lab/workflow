from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from git_graph_helpers import git

from vulngraph.git_graph.builder import GitGraphBuilder
from vulngraph.git_graph.query import GitGraphQuery
from vulngraph.services.history_anchor_relocator import (
    build_anchor_reference,
    relocate_history_event_anchor,
)


def _commit(repo: Path, message: str) -> str:
    git(repo, "add", ".")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def _init_repo(tmp_path: Path, content: str, *, path: str = "src/sample.c") -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return repo, _commit(repo, "base")


def _query(repo: Path, tmp_path: Path) -> GitGraphQuery:
    output = tmp_path / "index"
    GitGraphBuilder().build(repo, output, repo_id="fixture", reset=True)
    return GitGraphQuery(output / "graph.sqlite", repo)


def _packet(
    *,
    parent: str,
    candidate: str,
    anchor_text: str,
    old_line: int,
    path: str = "src/sample.c",
    parent_shas: list[str] | None = None,
    source_lane: str = "strong",
    blame_hints: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": "history_event_packet_v1",
        "cve_id": "CVE-TEST-RELOCATION",
        "repo_id": "fixture",
        "candidate_id": "candidate:test",
        "source_lane": source_lane,
        "lifecycle": "raw_history_event_candidate",
        "candidate_origin": {
            "anchor_path": path,
            "old_line_start": old_line,
            "old_line_end": old_line,
            "old_line_text": anchor_text,
            "old_line_text_hash": hashlib.sha256(anchor_text.encode()).hexdigest(),
            "fix_parent_sha": parent,
            "fix_commit_sha": "f" * 40,
            "patch_family": "patch-family:test",
            "function_id": None,
        },
        "candidate_event": {
            "candidate_commit_sha": candidate,
            "parent_shas": parent_shas if parent_shas is not None else [parent],
            "changed_paths": [path],
            "is_merge": len(parent_shas or [parent]) > 1,
            "is_root": False,
        },
        "path_history": {
            "path_at_candidate": path,
            "path_at_fix_parent": path,
            "rename_move_copy_hints": [],
        },
        "blame_variants": {
            "variants": blame_hints or [],
        },
    }


def _parent_and_candidate(result: dict) -> tuple[dict, dict]:
    assert len(result["parent_resolutions"]) == 1
    return result["parent_resolutions"][0], result["candidate_resolution"]


def test_line_insertion_relocates_anchor_down(tmp_path):
    text = "int f(void) {\n  vulnerable_call();\n  return 0;\n}\n"
    repo, parent = _init_repo(tmp_path, text)
    (repo / "src/sample.c").write_text(
        "/* inserted */\nint f(void) {\n  vulnerable_call();\n  return 0;\n}\n",
        encoding="utf-8",
    )
    candidate = _commit(repo, "insert line")
    result = relocate_history_event_anchor(
        _packet(parent=parent, candidate=candidate, anchor_text="  vulnerable_call();", old_line=2),
        _query(repo, tmp_path),
    )

    parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert parent_resolution["relocated_line_start"] == 2
    assert candidate_resolution["relocated_line_start"] == 3
    assert candidate_resolution["relocation_status"] == "found"
    assert candidate_resolution["matched_text"].strip() == "vulnerable_call();"


def test_line_deletion_relocates_anchor_up(tmp_path):
    text = "/* removed */\nint f(void) {\n  vulnerable_call();\n  return 0;\n}\n"
    repo, parent = _init_repo(tmp_path, text)
    (repo / "src/sample.c").write_text(
        "int f(void) {\n  vulnerable_call();\n  return 0;\n}\n",
        encoding="utf-8",
    )
    candidate = _commit(repo, "delete line")
    result = relocate_history_event_anchor(
        _packet(parent=parent, candidate=candidate, anchor_text="  vulnerable_call();", old_line=3),
        _query(repo, tmp_path),
    )

    _parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert candidate_resolution["relocated_line_start"] == 2
    assert candidate_resolution["match_kind"] in {"exact_hash", "exact_text"}


def test_whitespace_only_change_uses_unique_normalized_match(tmp_path):
    repo, parent = _init_repo(
        tmp_path,
        "int f(void) {\n  vulnerable_call(value);\n  return 0;\n}\n",
    )
    (repo / "src/sample.c").write_text(
        "int f(void) {\n\tvulnerable_call(value);\n  return 0;\n}\n",
        encoding="utf-8",
    )
    candidate = _commit(repo, "whitespace")
    result = relocate_history_event_anchor(
        _packet(parent=parent, candidate=candidate, anchor_text="  vulnerable_call(value);", old_line=2),
        _query(repo, tmp_path),
    )

    _parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert candidate_resolution["relocation_status"] == "found"
    assert candidate_resolution["match_kind"] == "normalized_unique"
    assert candidate_resolution["relation_to_anchor"] == "same_statement"


def test_duplicate_statement_is_ambiguous_without_unique_provenance(tmp_path):
    repo, parent = _init_repo(
        tmp_path,
        "void a(void) {\n  vulnerable_call();\n}\nvoid b(void) {\n  vulnerable_call();\n}\n",
    )
    candidate = parent
    result = relocate_history_event_anchor(
        _packet(parent=parent, candidate=candidate, anchor_text="  vulnerable_call();", old_line=99),
        _query(repo, tmp_path),
    )

    _parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert candidate_resolution["relocation_status"] == "ambiguous"
    assert candidate_resolution["selected_path"] is None
    assert len(candidate_resolution["candidate_matches"]) == 2


def test_rename_path_drift_is_verified_by_text(tmp_path):
    repo, parent = _init_repo(
        tmp_path,
        "int f(void) {\n  vulnerable_call();\n}\n",
        path="src/old.c",
    )
    git(repo, "mv", "src/old.c", "src/new.c")
    candidate = _commit(repo, "rename")
    packet = _packet(
        parent=parent,
        candidate=candidate,
        anchor_text="  vulnerable_call();",
        old_line=2,
        path="src/old.c",
    )
    packet["path_history"]["path_at_candidate"] = "src/new.c"
    result = relocate_history_event_anchor(packet, _query(repo, tmp_path))

    parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert parent_resolution["selected_path"] == "src/old.c"
    assert candidate_resolution["selected_path"] == "src/new.c"
    assert candidate_resolution["match_kind"] in {"rename_verified", "exact_hash", "exact_text"}


def test_introduction_marks_parent_absent_by_event(tmp_path):
    repo, parent = _init_repo(tmp_path, "int f(void) {\n  return 0;\n}\n")
    (repo / "src/sample.c").write_text(
        "int f(void) {\n  vulnerable_call();\n  return 0;\n}\n",
        encoding="utf-8",
    )
    candidate = _commit(repo, "introduce statement")
    result = relocate_history_event_anchor(
        _packet(parent=parent, candidate=candidate, anchor_text="  vulnerable_call();", old_line=2),
        _query(repo, tmp_path),
    )

    parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert parent_resolution["relocation_status"] == "absent_by_event"
    assert parent_resolution["relation_to_anchor"] == "introduced_in_candidate"
    assert candidate_resolution["relocation_status"] == "found"
    assert candidate_resolution["relation_to_anchor"] == "introduced_in_candidate"


def test_modified_anchor_uses_diff_mapping_not_old_absolute_line(tmp_path):
    repo, parent = _init_repo(
        tmp_path,
        "int f(void) {\n  vulnerable_call(old_value);\n  return 0;\n}\n",
    )
    (repo / "src/sample.c").write_text(
        "/* inserted */\nint f(void) {\n  vulnerable_call(new_value);\n  return 0;\n}\n",
        encoding="utf-8",
    )
    candidate = _commit(repo, "modify statement")
    result = relocate_history_event_anchor(
        _packet(parent=parent, candidate=candidate, anchor_text="  vulnerable_call(old_value);", old_line=2),
        _query(repo, tmp_path),
    )

    _parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert candidate_resolution["relocation_status"] == "found"
    assert candidate_resolution["match_kind"] in {"diff_hunk_mapped", "context_fingerprint"}
    assert candidate_resolution["relation_to_anchor"] == "structurally_changed"
    assert candidate_resolution["matched_text"].strip() == "vulnerable_call(new_value);"


def test_removed_anchor_marks_candidate_absent_by_event(tmp_path):
    repo, parent = _init_repo(
        tmp_path,
        "int f(void) {\n  vulnerable_call();\n  return 0;\n}\n",
    )
    (repo / "src/sample.c").write_text(
        "int f(void) {\n  return 0;\n}\n",
        encoding="utf-8",
    )
    candidate = _commit(repo, "remove statement")
    result = relocate_history_event_anchor(
        _packet(parent=parent, candidate=candidate, anchor_text="  vulnerable_call();", old_line=2),
        _query(repo, tmp_path),
    )

    parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert parent_resolution["relocation_status"] == "found"
    assert candidate_resolution["relocation_status"] == "absent_by_event"
    assert candidate_resolution["relation_to_anchor"] == "removed_in_candidate"
    assert candidate_resolution["evidence_refs"]


def test_comment_or_blank_at_old_line_is_not_accepted(tmp_path):
    repo, parent = _init_repo(
        tmp_path,
        "int f(void) {\n  vulnerable_call();\n  return 0;\n}\n",
    )
    (repo / "src/sample.c").write_text(
        "int f(void) {\n  /* unrelated */\n\n  vulnerable_call();\n  return 0;\n}\n",
        encoding="utf-8",
    )
    candidate = _commit(repo, "insert comment and blank")
    result = relocate_history_event_anchor(
        _packet(parent=parent, candidate=candidate, anchor_text="  vulnerable_call();", old_line=2),
        _query(repo, tmp_path),
    )

    _parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert candidate_resolution["relocation_status"] == "found"
    assert candidate_resolution["relocated_line_start"] == 4
    assert "unrelated" not in candidate_resolution["matched_text"]


def test_hash_mismatch_cannot_be_exact_and_normalized_match_must_be_unique(tmp_path):
    repo, parent = _init_repo(
        tmp_path,
        "int f(void) {\n  vulnerable_call();\n  vulnerable_call();\n}\n",
    )
    candidate = parent
    packet = _packet(parent=parent, candidate=candidate, anchor_text="\tvulnerable_call();", old_line=2)
    result = relocate_history_event_anchor(packet, _query(repo, tmp_path))

    _parent_resolution, candidate_resolution = _parent_and_candidate(result)
    assert candidate_resolution["relocation_status"] == "ambiguous"
    assert candidate_resolution["match_kind"] == "unavailable"
    assert all(match["match_kind"] != "exact_hash" for match in candidate_resolution["candidate_matches"])


def test_path_missing_not_found_and_censored_are_distinct(tmp_path):
    repo, parent = _init_repo(tmp_path, "int f(void) {\n  return 0;\n}\n")
    (repo / "other.txt").write_text("next\n", encoding="utf-8")
    candidate = _commit(repo, "next")
    query = _query(repo, tmp_path)

    missing_packet = _packet(
        parent=parent,
        candidate=candidate,
        anchor_text="  vulnerable_call();",
        old_line=2,
        path="src/missing.c",
    )
    missing = relocate_history_event_anchor(missing_packet, query)
    assert missing["candidate_resolution"]["relocation_status"] == "path_missing"

    not_found_packet = _packet(
        parent=parent,
        candidate=candidate,
        anchor_text="  vulnerable_call();",
        old_line=2,
    )
    not_found = relocate_history_event_anchor(not_found_packet, query)
    assert not_found["candidate_resolution"]["relocation_status"] == "not_found"

    censored_packet = _packet(
        parent=parent,
        candidate="0" * 40,
        anchor_text="  vulnerable_call();",
        old_line=2,
    )
    censored = relocate_history_event_anchor(censored_packet, query)
    assert censored["candidate_resolution"]["relocation_status"] == "censored"


def test_merge_commit_resolves_each_parent_separately(tmp_path):
    repo, base = _init_repo(tmp_path, "int f(void) {\n  return 0;\n}\n")
    git(repo, "checkout", "-b", "left")
    (repo / "src/sample.c").write_text(
        "int f(void) {\n  vulnerable_call();\n  return 0;\n}\n",
        encoding="utf-8",
    )
    left = _commit(repo, "left")
    git(repo, "checkout", "-b", "right", base)
    (repo / "right.txt").write_text("right\n", encoding="utf-8")
    right = _commit(repo, "right")
    git(repo, "checkout", "left")
    git(repo, "merge", "--no-ff", "right", "-m", "merge")
    merge = git(repo, "rev-parse", "HEAD")
    result = relocate_history_event_anchor(
        _packet(
            parent=left,
            candidate=merge,
            anchor_text="  vulnerable_call();",
            old_line=2,
            parent_shas=[left, right],
        ),
        _query(repo, tmp_path),
    )

    assert len(result["parent_resolutions"]) == 2
    assert {item["revision_sha"] for item in result["parent_resolutions"]} == {left, right}
    assert any(item["relocation_status"] == "found" for item in result["parent_resolutions"])
    assert result["candidate_resolution"]["relocation_status"] == "found"


def test_anchor_reference_is_immutable_and_normalized(tmp_path):
    repo, parent = _init_repo(tmp_path, "int f(void) {\n  vulnerable_call();\n}\n")
    packet = _packet(
        parent=parent,
        candidate=parent,
        anchor_text="  vulnerable_call();",
        old_line=2,
    )
    reference = build_anchor_reference(packet, _query(repo, tmp_path))

    assert reference.old_line_text_hash == hashlib.sha256(reference.old_line_text.encode()).hexdigest()
    assert reference.normalized_line_hash
    with pytest.raises(Exception):
        reference.old_line_start = 99


def test_cve_2020_8231_never_accepts_comment_or_blank_as_anchor():
    history_path = Path(
        "runs/batches/vulngraph-history-event-reconstruction-v1-dev30/"
        "CVE-2020-8231/history_event_packets.json"
    )
    index_path = Path("runs/batches/vulngraph-git-graph-index-v1/curl/graph.sqlite")
    repo_path = Path("../VulnVersion/repo/curl")
    if not history_path.exists() or not index_path.exists() or not repo_path.exists():
        pytest.skip("CVE-2020-8231 relocation regression inputs unavailable")

    query = GitGraphQuery(index_path, repo_path)
    packets = json.loads(history_path.read_text(encoding="utf-8"))
    by_text = {
        packet["candidate_origin"]["old_line_text"].strip(): relocate_history_event_anchor(packet, query)
        for packet in packets
    }

    store = by_text["data->state.lastconnect = conn;"]
    for resolution in [*store["parent_resolutions"], store["candidate_resolution"]]:
        if resolution["relocation_status"] == "found":
            assert resolution["matched_text"].strip()
            assert not resolution["matched_text"].lstrip().startswith(("/*", "*", "//"))
            assert resolution["evidence_refs"]

    load = by_text["struct connectdata *c = data->state.lastconnect;"]
    for resolution in [*load["parent_resolutions"], load["candidate_resolution"]]:
        assert resolution["relocation_status"] in {
            "found",
            "absent_by_event",
            "ambiguous",
            "not_found",
            "path_missing",
            "censored",
        }
        if resolution["relocation_status"] == "found":
            assert resolution["matched_text"].strip()
            assert resolution["evidence_refs"]
