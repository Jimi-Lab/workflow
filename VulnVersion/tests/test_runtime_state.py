"""P0-1: Runtime state population tests.

These tests assert that build_vuln_tree_plan() mutates TagRuntimeState /
LineRuntimeState / BoundaryRuntimeState in-place when planning, so the
planner stage has a single source of truth for downstream consumers
(no-FIC subtype, ASBS verdict source separation, artifact serialization).

Verifier-stage fields (verdict, verdict_source, confidence, probe_round,
inferred_from) are NOT covered here — they belong to a follow-up that
runs against the LLM agent.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vulnversion.stage3_verify.plan_tags import build_tag_plan
from vulnversion.stage3_verify.vuln_tree import (
    BoundaryRuntimeState,
    LineRuntimeState,
    TagRuntimeState,
    write_vuln_tree_artifacts,
)


class _BaseFakeRepo:
    def list_remote_branches_containing(self, commit):
        return []

    def patch_id(self, commit):
        return ""

    def show_patch(self, commit):
        return ""

    def changed_files(self, commit):
        return []

    def commit_parents(self, commit):
        return []

    def commit_message(self, commit):
        return ""

    def tag_commit(self, tag):
        return f"{tag}-commit"

    def rev_parse(self, rev):
        return rev

    def log_commits_touching_paths(self, paths, max_count=1000):
        return []


def _build_plan(repo_obj, *, fixing_commits, repo_dir_name="FFmpeg", cve_id="CVE-RT-1"):
    import vulnversion.stage3_verify.plan_tags as plan_mod

    orig_open = plan_mod.GitRepo.open
    try:
        plan_mod.GitRepo.open = staticmethod(lambda repo_path: repo_obj)  # type: ignore[method-assign]
        return build_tag_plan(
            repo_path=str(Path(tempfile.gettempdir()) / repo_dir_name),
            cve_id=cve_id,
            fixing_commits=fixing_commits,
        )
    finally:
        plan_mod.GitRepo.open = orig_open  # type: ignore[method-assign]


# ────────────────────────────────────────────────────────────────────
# Section 1 — dataclass round-trip & defaults
# ────────────────────────────────────────────────────────────────────


class TestRuntimeStateDataclasses(unittest.TestCase):
    def test_tag_runtime_state_default_unplanned(self):
        s = TagRuntimeState()
        self.assertEqual(s.plan_status, "unplanned")
        self.assertEqual(s.plan_roles, [])
        self.assertIsNone(s.verdict)
        self.assertIsNone(s.verdict_source)
        self.assertEqual(s.contains_fix_clusters, [])
        self.assertEqual(s.contains_vic_clusters, [])
        self.assertIsNone(s.no_fic_reason)

    def test_line_runtime_state_default_unplanned(self):
        s = LineRuntimeState()
        self.assertEqual(s.plan_status, "unplanned")
        self.assertIsNone(s.search_mode)
        self.assertIsNone(s.boundary_status)

    def test_boundary_runtime_state_default_unplanned(self):
        s = BoundaryRuntimeState()
        self.assertEqual(s.plan_status, "unplanned")
        self.assertIsNone(s.certificate_id)

    def test_runtime_to_dict_preserves_all_13_fields(self):
        for s in (TagRuntimeState(), LineRuntimeState(), BoundaryRuntimeState()):
            d = s.to_dict()
            self.assertEqual(
                set(d.keys()),
                {
                    "plan_status",
                    "plan_roles",
                    "verdict",
                    "verdict_source",
                    "confidence",
                    "contains_fix_clusters",
                    "contains_vic_clusters",
                    "probe_round",
                    "inferred_from",
                    "certificate_id",
                    "no_fic_reason",
                    "search_mode",
                    "boundary_status",
                },
            )


# ────────────────────────────────────────────────────────────────────
# Section 2 — LineRuntimeState population at planner stage
# ────────────────────────────────────────────────────────────────────


class TestLineRuntimePopulation(unittest.TestCase):
    """build_vuln_tree_plan must populate LineNode.runtime for every line."""

    def _two_line_plan_with_fic(self):
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2.2", "n4.2.1", "n4.2", "n4.1.6", "n4.1.5", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix42":
                    return ["n4.2.3"]
                if commit == "fix41":
                    return ["n4.1.6"]
                return []

            def patch_id(self, commit):
                return commit

        return _build_plan(_Repo(), fixing_commits=[["fix42", "fix41"]])

    def test_no_line_remains_unplanned(self):
        plan = self._two_line_plan_with_fic()
        for line, line_dict in plan["lines"].items():
            self.assertNotEqual(
                line_dict["runtime"]["plan_status"],
                "unplanned",
                f"line {line} runtime not populated by planner",
            )

    def test_line_runtime_search_mode_matches_task_mode(self):
        plan = self._two_line_plan_with_fic()
        task_mode_by_line = {t["line"]: t["mode"] for t in plan["verification_tasks"]}
        for line, line_dict in plan["lines"].items():
            search_mode = line_dict["runtime"]["search_mode"]
            expected = task_mode_by_line.get(line, "no_task")
            self.assertEqual(
                search_mode,
                expected,
                f"line {line}: search_mode={search_mode!r} expected {expected!r}",
            )

    def test_line_runtime_boundary_status_mirrors_line_boundary(self):
        plan = self._two_line_plan_with_fic()
        for line, line_dict in plan["lines"].items():
            self.assertEqual(
                line_dict["runtime"]["boundary_status"],
                plan["line_boundaries"][line]["status"],
            )

    def test_line_runtime_contains_fix_clusters_when_fic_hit(self):
        plan = self._two_line_plan_with_fic()
        # line 4.2 has FIC from fix_cluster_0 — must record cluster id
        line_42 = plan["lines"]["4.2"]["runtime"]
        self.assertIn("fix_cluster_0", line_42["contains_fix_clusters"])
        # line 4.1 has FIC from same cluster (same CVE, semantics=any)
        line_41 = plan["lines"]["4.1"]["runtime"]
        self.assertIn("fix_cluster_0", line_41["contains_fix_clusters"])

    def test_line_runtime_no_fic_reason_set_when_no_line_local_fic(self):
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2.2", "n4.2", "n4.1.6", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                # Only 4.2 line has a fix-containing tag
                if commit == "fix":
                    return ["n4.2.3"]
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        # 4.1 line has no FIC — no_fic_reason must be set (subtype refined by P0-3)
        line_41 = plan["lines"]["4.1"]["runtime"]
        self.assertIsNotNone(line_41["no_fic_reason"])
        # 4.2 line has FIC — no_fic_reason must remain None
        line_42 = plan["lines"]["4.2"]["runtime"]
        self.assertIsNone(line_42["no_fic_reason"])

    def test_line_runtime_certificate_id_is_stable(self):
        plan_a = self._two_line_plan_with_fic()
        plan_b = self._two_line_plan_with_fic()
        for line in plan_a["lines"]:
            self.assertEqual(
                plan_a["lines"][line]["runtime"]["certificate_id"],
                plan_b["lines"][line]["runtime"]["certificate_id"],
                f"line {line}: certificate_id is not deterministic",
            )
            self.assertIsNotNone(plan_a["lines"][line]["runtime"]["certificate_id"])


# ────────────────────────────────────────────────────────────────────
# Section 3 — TagRuntimeState population at planner stage
# ────────────────────────────────────────────────────────────────────


class TestTagRuntimePopulation(unittest.TestCase):
    def _plan(self):
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2.2", "n4.2.1", "n4.2", "n4.1.6", "n4.1.5", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix42":
                    return ["n4.2.3"]
                if commit == "fix41":
                    return ["n4.1.6"]
                return []

            def patch_id(self, commit):
                return commit

        return _build_plan(_Repo(), fixing_commits=[["fix42", "fix41"]])

    def test_fic_tag_gets_fic_tag_role(self):
        plan = self._plan()
        # n4.2.3 is FIC on 4.2
        for tag_node in plan["lines"]["4.2"]["tag_nodes"]:
            if tag_node["tag"] == "n4.2.3":
                self.assertIn("fic_tag", tag_node["runtime"]["plan_roles"])
                self.assertIn("fix_cluster_0", tag_node["runtime"]["contains_fix_clusters"])
                return
        self.fail("did not find FIC tag node n4.2.3")

    def test_candidate_tags_get_candidate_role(self):
        plan = self._plan()
        candidate_tags_42 = set(plan["line_plans"]["4.2"]["candidate_tags"])
        for tag_node in plan["lines"]["4.2"]["tag_nodes"]:
            if tag_node["tag"] in candidate_tags_42:
                self.assertIn(
                    "candidate_tag",
                    tag_node["runtime"]["plan_roles"],
                    f"tag {tag_node['tag']} in candidate_tags but missing candidate_tag role",
                )

    def test_probe_tags_get_probe_role(self):
        plan = self._plan()
        for task in plan["verification_tasks"]:
            line = task["line"]
            probe_set = set(task["probe_tags"])
            for tag_node in plan["lines"][line]["tag_nodes"]:
                if tag_node["tag"] in probe_set:
                    self.assertIn(
                        "probe_tag",
                        tag_node["runtime"]["plan_roles"],
                        f"line {line} tag {tag_node['tag']} probe but missing probe_tag role",
                    )

    def test_non_candidate_tags_have_outside_status(self):
        plan = self._plan()
        # n4.2.3 is FIC — outside the candidate interval (which excludes FIC)
        for tag_node in plan["lines"]["4.2"]["tag_nodes"]:
            if tag_node["tag"] == "n4.2.3":
                self.assertEqual(tag_node["runtime"]["plan_status"], "outside_candidate")
                return
        self.fail("did not find n4.2.3 node")

    def test_candidate_tags_have_in_candidate_status(self):
        plan = self._plan()
        candidate_tags_42 = set(plan["line_plans"]["4.2"]["candidate_tags"])
        for tag_node in plan["lines"]["4.2"]["tag_nodes"]:
            if tag_node["tag"] in candidate_tags_42:
                self.assertEqual(
                    tag_node["runtime"]["plan_status"],
                    "in_candidate",
                    f"tag {tag_node['tag']} should be in_candidate",
                )


# ────────────────────────────────────────────────────────────────────
# Section 4 — BoundaryRuntimeState population at planner stage
# ────────────────────────────────────────────────────────────────────


class TestBoundaryRuntimePopulation(unittest.TestCase):
    def test_boundary_runtime_status_matches_line_boundary_status(self):
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2.2", "n4.2", "n4.1.6", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix":
                    return ["n4.2.3"]
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        for line, boundary_dict in plan["line_boundaries"].items():
            self.assertEqual(
                boundary_dict["runtime"]["boundary_status"],
                boundary_dict["status"],
                f"line {line}: boundary runtime.boundary_status mismatch",
            )

    def test_boundary_runtime_certificate_id_format(self):
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix":
                    return ["n4.2.3"]
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        cert = plan["line_boundaries"]["4.2"]["runtime"]["certificate_id"]
        # deterministic format: starts with "boundary:" followed by line key and status
        self.assertIsNotNone(cert)
        self.assertTrue(cert.startswith("boundary:"))
        self.assertIn("4.2", cert)


# ────────────────────────────────────────────────────────────────────
# Section 5 — artifact serialization
# ────────────────────────────────────────────────────────────────────


class TestRuntimeArtifactSerialization(unittest.TestCase):
    def _plan(self):
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2.2", "n4.2", "n4.1.6", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix":
                    return ["n4.2.3"]
                return []

        return _build_plan(_Repo(), fixing_commits=[["fix"]])

    def test_vuln_tree_runtime_artifact_written(self):
        plan = self._plan()
        with tempfile.TemporaryDirectory() as tmp:
            write_vuln_tree_artifacts(tmp, plan)
            runtime_path = Path(tmp) / "vuln_tree_runtime.json"
            self.assertTrue(runtime_path.exists(), "vuln_tree_runtime.json must be written")
            data = json.loads(runtime_path.read_text(encoding="utf-8"))
            self.assertIn("lines", data)
            self.assertIn("line_boundaries", data)
            # Schema sanity: every line has all 13 runtime fields
            for line, line_runtime in data["lines"].items():
                self.assertIn("plan_status", line_runtime)
                self.assertIn("certificate_id", line_runtime)
                self.assertIn("contains_fix_clusters", line_runtime)

    def test_existing_artifacts_unchanged_keys(self):
        plan = self._plan()
        with tempfile.TemporaryDirectory() as tmp:
            write_vuln_tree_artifacts(tmp, plan)
            vt = json.loads((Path(tmp) / "vuln_tree.json").read_text(encoding="utf-8"))
            # vuln_tree.json keys must keep its existing top-level shape
            for k in ("repo", "cve_id", "ordered_lines", "lines", "fix_clusters", "vic_clusters"):
                self.assertIn(k, vt, f"vuln_tree.json missing key {k}")


if __name__ == "__main__":
    unittest.main()
