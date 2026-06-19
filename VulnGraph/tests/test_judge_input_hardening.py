from __future__ import annotations

import csv
import json
from types import SimpleNamespace
from pathlib import Path

import vulngraph.workflows.judge_input_hardening as jih
from vulngraph.workflows.judge_input_hardening import (
  FORBIDDEN_BLIND_TOKENS,
  build_judge_input_hardening_v1,
  rank_fallback_candidates,
  scan_blind_packets_for_forbidden_fields,
)


def _write_json(path: Path, data: object) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_json(path: Path) -> dict:
  return json.loads(path.read_text(encoding="utf-8"))


def _anchor(
  candidate_id: str,
  *,
  cve_id: str = "CVE-X",
  fallback: bool = False,
  selection_mode: str = "modified_old_side",
) -> dict:
  return {
    "anchor_id": f"{'fallback-anchor' if fallback else 'pre-fix-anchor'}:{candidate_id}",
    "candidate_id": candidate_id,
    "cve_id": cve_id,
    "fix_set_id": f"{cve_id}:fix-set:1",
    "patch_family_id": "patch-family:one",
    "fix_commit_id": "fix-commit:repo:fix",
    "fix_commit_sha": "f" * 40,
    "parent_sha": "p" * 40,
    "patch_hunk_id": "patch-hunk:one",
    "path_before": "src/a.c",
    "path_after": "src/a.c",
    "old_line_start": 7,
    "old_line_end": 7,
    "line_text": "dangerous_use(ptr);",
    "line_text_sha256": "h" * 64,
    "candidate_source": "deleted_line",
    "role": "dangerous_use",
    "selection_mode": selection_mode,
    "root_cause_hypothesis_ids": ["hyp-1"],
    "predicate_ids": ["vp-1", "fix-pred-1"],
    "git_observation_refs": ["obs-1"],
    "rationale": "anchor rationale",
    "confidence": 0.8,
    "lifecycle": "raw_candidate",
    "uncertainty_reasons": [],
    "exclusion_reasons": [],
  }


def _candidate(
  commit_sha: str,
  candidate_id: str,
  *,
  cve_id: str = "CVE-X",
  mode: str = "strong_model_anchor",
  evidence: str = "strong",
  old_text: str = "dangerous_use(ptr);",
  selection_mode: str = "modified_old_side",
) -> dict:
  return {
    "commit_sha": commit_sha,
    "anchor_ids": [f"{'fallback-anchor' if mode.startswith('fallback') else 'pre-fix-anchor'}:{candidate_id}"],
    "candidate_ids": [candidate_id],
    "roles": ["dangerous_use"],
    "selection_modes": [selection_mode],
    "vote_count": 1,
    "old_text": old_text,
    "old_path": "src/a.c",
    "old_line": 7,
    "line_provenance": [
      {
        "anchor_id": f"{'fallback-anchor' if mode.startswith('fallback') else 'pre-fix-anchor'}:{candidate_id}",
        "candidate_id": candidate_id,
        "fix_commit_id": "fix-commit:repo:fix",
        "patch_family_id": "patch-family:one",
        "fix_commit_sha": "f" * 40,
        "parent_sha": "p" * 40,
        "path_before": "src/a.c",
        "old_line": 7,
        "old_text": old_text,
        "line_text_sha256": "h" * 64,
        "blamed_commit_sha": commit_sha,
        "boundary_marker": False,
        "role": "dangerous_use",
        "selection_mode": selection_mode,
        "status": "success",
        "lifecycle": "raw_candidate",
      }
    ],
    "lifecycle": "raw_candidate",
    "candidate_generation_mode": mode,
    "evidence_level": evidence,
  }


def _minimal_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
  readiness = tmp_path / "readiness"
  anchor = tmp_path / "anchor"
  probe = tmp_path / "probe"
  dataset = tmp_path / "dataset.json"
  _write_json(dataset, {"CVE-X": {"repo": "repo"}, "CVE-F": {"repo": "repo"}})
  _write_json(readiness / "summary.json", {"cases_total": 2})
  _write_json(
    anchor / "summary.json",
    {
      "cases_total": 2,
      "strong_candidate_ready_count": 1,
      "fallback_candidate_ready_count": 1,
      "judge_input_ready_count": 2,
      "no_candidate_count": 0,
      "no_candidate_cases": [],
      "strong_raw_candidate_commit_count": 1,
      "fallback_raw_candidate_commit_count": 2,
      "results": [
        {"cve_id": "CVE-X", "candidate_generation_mode": "strong_model_anchor", "candidate_commit_count": 1},
        {"cve_id": "CVE-F", "candidate_generation_mode": "fallback_inventory_anchor", "candidate_commit_count": 2},
      ],
    },
  )
  for cve_id, commit, mode, evidence, fallback in [
    ("CVE-X", "a" * 40, "strong_model_anchor", "strong", False),
    ("CVE-F", "b" * 40, "fallback_inventory_anchor", "fallback", True),
  ]:
    candidates = [_candidate(commit, f"cand-{cve_id}", cve_id=cve_id, mode=mode, evidence=evidence)]
    if cve_id == "CVE-F":
      candidates.append(
        _candidate(
          "b" * 40,
          "cand-CVE-F-dup",
          cve_id=cve_id,
          mode=mode,
          evidence=evidence,
          old_text="}",
          selection_mode="context_fallback",
        )
      )
    _write_json(anchor / cve_id / "candidate_commits.json", candidates)
    _write_json(
      anchor / cve_id / "resolved_pre_fix_anchors.json",
      [_anchor(f"cand-{cve_id}", fallback=fallback)],
    )
    _write_json(anchor / cve_id / "blame_trace.json", {"status": "success", "errors": []})
    _write_json(anchor / cve_id / "ingestion_result.json", {"status": "ingested_raw_candidate", "taxonomy": {}})
  _write_json(
    probe / "summary.json",
    {
      "release_line_overreach_cases": ["CVE-F"],
      "any_candidate_non_release_tag_noise_cases": [],
      "manual_anchor_review_required_cases": ["CVE-F"],
    },
  )
  _write_json(
    probe / "per_candidate_probe.json",
    {
      "CVE-X": {
        "release_tag_universe": [
          {
            "commit_sha": "a" * 40,
            "predicted_tags": ["v1"],
            "metrics": {"f1": 1.0},
            "false_positive_taxonomy": {},
          }
        ],
        "ground_truth_affected_versions": ["v1"],
      },
      "CVE-F": {
        "release_tag_universe": [
          {
            "commit_sha": "b" * 40,
            "predicted_tags": ["v2", "v3"],
            "metrics": {"f1": 0.5},
            "false_positive_taxonomy": {"release_line_overreach": ["v3"]},
          }
        ],
        "ground_truth_affected_versions": ["v2", "v3"],
      },
    },
  )
  return readiness, anchor, probe, dataset


def test_hardening_writes_blind_and_audit_packets_without_gt_leakage(tmp_path: Path) -> None:
  readiness, anchor, probe, dataset = _minimal_inputs(tmp_path)
  out_dir = tmp_path / "out"

  summary = build_judge_input_hardening_v1(
    readiness_dir=readiness,
    anchor_artifact=anchor,
    version_probe=probe,
    dataset=dataset,
    repo_root=tmp_path / "repo",
    out_dir=out_dir,
  )

  blind = _read_json(out_dir / "CVE-F" / "judge_blind_input_packet.json")
  audit = _read_json(out_dir / "CVE-F" / "judge_audit_packet.json")
  assert blind["schema_version"] == "judge_blind_input_packet_v0"
  assert audit["schema_version"] == "judge_audit_packet_v0"
  assert blind["candidates"][0]["candidate_source"] == "fallback"
  assert blind["candidates"][0]["lifecycle"] == "raw_candidate"
  assert blind["candidates"][0]["predicted_release_tags_from_version_probe"] == ["v2", "v3"]
  assert "diagnostic_gt_overlap" not in json.dumps(blind, ensure_ascii=False)
  assert audit["diagnostic"]["ground_truth_available"] is True
  assert summary["blind_packet_cases"] == 2
  assert summary["audit_packet_cases"] == 2
  assert summary["model_invocation_count"] == 0
  scan = scan_blind_packets_for_forbidden_fields(out_dir)
  assert scan["ok"] is True
  assert all(token in scan["forbidden_tokens"] for token in FORBIDDEN_BLIND_TOKENS)


def test_candidate_summary_is_candidate_level_and_fallback_ranking_is_compacted(tmp_path: Path) -> None:
  readiness, anchor, probe, dataset = _minimal_inputs(tmp_path)
  out_dir = tmp_path / "out"

  build_judge_input_hardening_v1(
    readiness_dir=readiness,
    anchor_artifact=anchor,
    version_probe=probe,
    dataset=dataset,
    repo_root=tmp_path / "repo",
    out_dir=out_dir,
  )

  rows = list(csv.DictReader((out_dir / "judge_candidate_summary.csv").open(encoding="utf-8")))
  assert len(rows) == 3
  assert {row["candidate_source"] for row in rows} == {"strong", "fallback"}
  assert all(row["blind_packet_path"].endswith("judge_blind_input_packet.json") for row in rows)
  ranked = _read_json(out_dir / "fallback_ranked_candidates.json")
  cve_f = ranked["cases"]["CVE-F"]
  assert cve_f["original_fallback_candidate_count"] == 2
  assert cve_f["ranked_candidate_count"] == 1
  assert len(cve_f["recommended_top_k"]) == 1
  assert cve_f["recommended_top_k"][0]["candidate_commit_sha"] == "b" * 40


def test_fallback_only_blind_packet_uses_recommended_top_k_while_audit_keeps_full_set(tmp_path: Path) -> None:
  readiness = tmp_path / "readiness"
  anchor = tmp_path / "anchor"
  probe = tmp_path / "probe"
  dataset = tmp_path / "dataset.json"
  out_dir = tmp_path / "out"
  cve_id = "CVE-MANY"
  _write_json(dataset, {cve_id: {"repo": "repo"}})
  _write_json(readiness / "summary.json", {"cases_total": 1})
  _write_json(
    anchor / "summary.json",
    {
      "cases_total": 1,
      "strong_candidate_ready_count": 0,
      "fallback_candidate_ready_count": 1,
      "judge_input_ready_count": 1,
      "no_candidate_count": 0,
      "no_candidate_cases": [],
      "strong_raw_candidate_commit_count": 0,
      "fallback_raw_candidate_commit_count": 6,
      "results": [{"cve_id": cve_id, "candidate_generation_mode": "fallback_inventory_anchor", "candidate_commit_count": 6}],
    },
  )
  candidates = [
    _candidate(
      f"{index:040x}",
      f"cand-{index}",
      cve_id=cve_id,
      mode="fallback_inventory_anchor",
      evidence="fallback",
      old_text="dangerous_use(ptr);",
    )
    for index in range(1, 7)
  ]
  anchors = [_anchor(f"cand-{index}", cve_id=cve_id, fallback=True) for index in range(1, 7)]
  _write_json(anchor / cve_id / "candidate_commits.json", candidates)
  _write_json(anchor / cve_id / "resolved_pre_fix_anchors.json", anchors)
  _write_json(anchor / cve_id / "blame_trace.json", {"status": "success", "errors": []})
  _write_json(anchor / cve_id / "ingestion_result.json", {"status": "ingested_raw_candidate", "taxonomy": {}})
  _write_json(probe / "summary.json", {})
  _write_json(probe / "per_candidate_probe.json", {cve_id: {"release_tag_universe": [], "ground_truth_affected_versions": ["v1"]}})

  summary = build_judge_input_hardening_v1(
    readiness_dir=readiness,
    anchor_artifact=anchor,
    version_probe=probe,
    dataset=dataset,
    repo_root=tmp_path / "repo",
    out_dir=out_dir,
    top_k=5,
  )

  blind = _read_json(out_dir / cve_id / "judge_blind_input_packet.json")
  audit = _read_json(out_dir / cve_id / "judge_audit_packet.json")
  assert blind["candidate_count"] == 5
  assert len(blind["candidates"]) == 5
  assert audit["candidate_count"] == 6
  assert len(audit["candidates"]) == 6
  actual_max_fallback_in_blind = max(
    sum(1 for item in _read_json(path)["candidates"] if item["candidate_source"] == "fallback")
    for path in out_dir.glob("*/judge_blind_input_packet.json")
  )
  assert summary["max_fallback_candidates_after"] == actual_max_fallback_in_blind == 5
  rows = [row for row in csv.DictReader((out_dir / "judge_candidate_summary.csv").open(encoding="utf-8")) if row["cve_id"] == cve_id]
  assert len(rows) == 6
  assert sum(row["included_in_blind_packet"] == "True" for row in rows) == 5
  assert sum(row["fallback_recommended"] == "True" for row in rows) == 5
  assert {row["fallback_rank"] for row in rows} == {"1", "2", "3", "4", "5", "6"}
  assert any(row["fallback_deprioritized_reason"] == "ranked_below_top_k" for row in rows)
  assert scan_blind_packets_for_forbidden_fields(out_dir)["ok"] is True


def test_blind_packet_summarizes_large_release_tag_lists(tmp_path: Path) -> None:
  readiness, anchor, probe, dataset = _minimal_inputs(tmp_path)
  out_dir = tmp_path / "out"
  large_tags = [f"v1.{index}" for index in range(100)]
  probe_data = _read_json(probe / "per_candidate_probe.json")
  probe_data["CVE-X"]["release_tag_universe"][0]["predicted_tags"] = large_tags
  _write_json(probe / "per_candidate_probe.json", probe_data)

  build_judge_input_hardening_v1(
    readiness_dir=readiness,
    anchor_artifact=anchor,
    version_probe=probe,
    dataset=dataset,
    repo_root=tmp_path / "repo",
    out_dir=out_dir,
  )

  blind = _read_json(out_dir / "CVE-X" / "judge_blind_input_packet.json")
  audit = _read_json(out_dir / "CVE-X" / "judge_audit_packet.json")
  blind_candidate = blind["candidates"][0]
  audit_candidate = audit["candidates"][0]
  assert "predicted_release_tags_from_version_probe" not in blind_candidate
  assert blind_candidate["release_tag_summary"]["count"] == 100
  assert blind_candidate["release_tag_artifact_ref"]
  assert audit_candidate["predicted_release_tags_from_version_probe"] == large_tags
  assert scan_blind_packets_for_forbidden_fields(out_dir)["ok"] is True


def test_missing_candidate_equivalent_fix_repair_is_not_cve_specific(tmp_path: Path, monkeypatch) -> None:
  cve_id = "CVE-GENERIC-MERGE"
  readiness = tmp_path / "readiness"
  anchor = tmp_path / "anchor"
  probe = tmp_path / "probe"
  repo_root = tmp_path / "repo-root"
  repo_path = repo_root / "repo"
  repo_path.mkdir(parents=True)
  dataset = tmp_path / "dataset.json"
  out_dir = tmp_path / "out"
  fix_sha = "f" * 40
  equivalent_sha = "e" * 40

  _write_json(dataset, {cve_id: {"repo": "repo", "fixing_commits": [[fix_sha]]}})
  _write_json(readiness / "summary.json", {"cases_total": 1})
  _write_json(
    anchor / "summary.json",
    {
      "cases_total": 1,
      "strong_candidate_ready_count": 0,
      "fallback_candidate_ready_count": 0,
      "judge_input_ready_count": 0,
      "no_candidate_count": 1,
      "no_candidate_cases": [cve_id],
      "results": [{"cve_id": cve_id, "candidate_generation_mode": "none", "candidate_commit_count": 0}],
    },
  )
  _write_json(anchor / cve_id / "candidate_commits.json", [])
  _write_json(anchor / cve_id / "resolved_pre_fix_anchors.json", [])
  _write_json(anchor / cve_id / "blame_trace.json", {"status": "not_run", "errors": []})
  _write_json(anchor / cve_id / "ingestion_result.json", {"status": "raw_candidate_censored", "no_fallback_candidate_reason": "no_blameable_old_side"})
  _write_json(probe / "summary.json", {})
  _write_json(probe / "per_candidate_probe.json", {cve_id: {"release_tag_universe": []}})

  class _Node:
    def __init__(self, node_type: str, data: dict) -> None:
      self.type = node_type
      self._data = data

    def model_dump(self, mode: str = "json") -> dict:
      return self._data

  def fake_build_patch_graph_from_repo(**kwargs):
    assert kwargs["cve_id"] == cve_id
    assert kwargs["commit_sha"] == equivalent_sha
    assert kwargs["fix_commit_content"]["equivalent_to_fix_commit"] == fix_sha
    return SimpleNamespace(
      nodes=[
        _Node(
          "FixCommit",
          {
            "id": f"fix-commit:repo:{equivalent_sha}",
            "type": "FixCommit",
            "content": {"repo": "repo", "commit_sha": equivalent_sha, **kwargs["fix_commit_content"]},
          },
        ),
        _Node(
          "PatchHunk",
          {
            "id": "patch-hunk:repo:eq:src/a.c:1",
            "type": "PatchHunk",
            "content": {"repo": "repo", "commit_sha": equivalent_sha, "path": "src/a.c"},
          },
        ),
      ]
    )

  candidate = {
    "candidate_id": "prefx-1",
    "cve_id": cve_id,
    "repo_id": "repo:repo",
    "fix_set_id": f"{cve_id}:fix-set:equivalent",
    "patch_family_id": "patch-family:eq",
    "fix_commit_id": f"fix-commit:repo:{equivalent_sha}",
    "fix_commit_sha": equivalent_sha,
    "parent_sha": "p" * 40,
    "patch_hunk_id": "patch-hunk:repo:eq:src/a.c:1",
    "path_before": "src/a.c",
    "path_after": "src/a.c",
    "old_line_start": 9,
    "old_line_end": 9,
    "line_text": "dangerous_use(ptr);",
    "line_text_sha256": "h" * 64,
    "candidate_source": "deleted_line",
    "change_type": "modify",
    "selection_mode_eligibility": ["modified_old_side"],
    "git_observation_refs": ["obs-eq"],
    "source_file": True,
    "exclusion_reasons": [],
  }

  monkeypatch.setattr(jih, "_find_equivalent_fix_commits", lambda **kwargs: [equivalent_sha], raising=False)
  monkeypatch.setattr(jih, "build_patch_graph_from_repo", fake_build_patch_graph_from_repo)
  monkeypatch.setattr(
    jih,
    "build_pre_fix_candidate_inventory",
    lambda **kwargs: SimpleNamespace(model_dump=lambda mode="json": {"cve_id": cve_id, "repo_id": "repo:repo", "repo_path": str(repo_path), "candidates": [candidate], "fix_families": {"patch-family:eq": [equivalent_sha]}, "issues": []}),
  )

  class _Blame:
    status = "success"
    errors: list[str] = []
    candidate_commits = [
      {
        "commit_sha": "b" * 40,
        "anchor_ids": ["fallback-anchor:prefx-1:1"],
        "candidate_ids": ["prefx-1"],
        "line_provenance": [
          {
            "anchor_id": "fallback-anchor:prefx-1:1",
            "candidate_id": "prefx-1",
            "status": "success",
            "blamed_commit_sha": "b" * 40,
            "boundary_marker": False,
          }
        ],
        "lifecycle": "raw_candidate",
      }
    ]

    def to_dict(self) -> dict:
      return {"status": self.status, "errors": self.errors, "candidate_commits": self.candidate_commits}

  monkeypatch.setattr(jih, "run_blame_for_anchors", lambda *args, **kwargs: _Blame())

  summary = build_judge_input_hardening_v1(
    readiness_dir=readiness,
    anchor_artifact=anchor,
    version_probe=probe,
    dataset=dataset,
    repo_root=repo_root,
    out_dir=out_dir,
    top_k=5,
  )

  blind = _read_json(out_dir / cve_id / "judge_blind_input_packet.json")
  repaired_inventory = _read_json(out_dir / cve_id / "repaired_candidate_inventory.json")
  ingestion = _read_json(out_dir / cve_id / "ingestion_result.json")
  assert blind["candidate_count"] == 1
  assert blind["candidates"][0]["candidate_commit_sha"] == "b" * 40
  assert blind["candidates"][0]["candidate_generation_mode"] == "fallback_equivalent_fix_anchor"
  assert blind["candidates"][0]["lifecycle"] == "raw_candidate"
  assert repaired_inventory["candidates"][0]["cve_id"] == cve_id
  assert ingestion["cve_id"] == cve_id
  assert summary["judge_ready_cases_after_hardening"] == 1
  assert summary["cve_2020_27814_repaired"] is False


def test_rank_fallback_candidates_prioritizes_direct_old_side_and_merges_duplicate_commits() -> None:
  noisy = {
    "candidate_commit_sha": "b" * 40,
    "candidate_source": "fallback",
    "candidate_generation_mode": "fallback_inventory_anchor",
    "evidence_level": "fallback",
    "candidate_ids": ["noisy"],
    "old_line_text": "}",
    "blame_trace": {"line_provenance": [{"selection_mode": "context_fallback"}]},
    "root_cause_hypothesis_bindings": ["fallback:root-cause-hypothesis"],
    "vulnerable_predicate_bindings": [],
    "predicate_bindings": ["fallback:predicate"],
    "risk_flags": ["broad_candidate_range"],
  }
  direct = {
    "candidate_commit_sha": "b" * 40,
    "candidate_source": "fallback",
    "candidate_generation_mode": "fallback_inventory_anchor",
    "evidence_level": "fallback",
    "candidate_ids": ["direct"],
    "old_line_text": "dangerous_use(ptr);",
    "blame_trace": {"line_provenance": [{"selection_mode": "modified_old_side", "role": "dangerous_use"}]},
    "root_cause_hypothesis_bindings": ["hyp-1"],
    "vulnerable_predicate_bindings": ["vp-1"],
    "predicate_bindings": ["vp-1"],
    "risk_flags": [],
  }

  ranked = rank_fallback_candidates([noisy, direct], top_k=5)

  assert ranked["original_fallback_candidate_count"] == 2
  assert ranked["ranked_candidate_count"] == 1
  assert ranked["recommended_top_k"][0]["candidate_commit_sha"] == "b" * 40
  assert set(ranked["recommended_top_k"][0]["merged_candidate_ids"]) == {"noisy", "direct"}
  assert "duplicate_candidate_commit_merged" in ranked["dropped_or_deprioritized_reason"]
