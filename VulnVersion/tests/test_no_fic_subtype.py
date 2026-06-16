"""P0-3: no-FIC subtype diagnosis tests.

Replaces the placeholder LineRuntimeState.no_fic_reason="no_fic_pending_search"
with one of three deterministic subtypes:

  - "never_fixed_on_this_line"
        Line has no FIC AND the newer_line chain has no fix-cluster hit
        anywhere upstream → fix wave never reached this branch.
  - "duplicate_expansion_missed"
        Line has no FIC BUT some ancestor line (via newer_line) does carry
        a fix-cluster hit → fix wave exists upstream but did not propagate
        via patch-id / equivalence to this line. BAPEE candidate.
  - "line_not_vulnerable_in_released_tags"
        ASBS verifier returns "verified_no_affected_on_line" → no released
        tag on this line ever exhibits the vulnerability. Set after probe.

Lines that DO have a FIC must keep no_fic_reason=None (they are bounded).

Classification must be deterministic and work uniformly across all 9 repos.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnversion.stage3_verify.plan_tags import build_tag_plan
from vulnversion.stage3_verify.verify_tags import verify_tags


CANONICAL_NO_FIC_SUBTYPES = {
    "never_fixed_on_this_line",
    "duplicate_expansion_missed",
    "line_not_vulnerable_in_released_tags",
}


# ────────────────────────────────────────────────────────────────────
# Fake-repo helpers (mirror existing test patterns)
# ────────────────────────────────────────────────────────────────────


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


def _build_plan(repo_obj, *, fixing_commits, repo_dir_name="FFmpeg", cve_id="CVE-NF-1"):
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
# Section 1 — taxonomy invariants
# ────────────────────────────────────────────────────────────────────


class TestNoFicTaxonomyInvariants(unittest.TestCase):
    def test_line_with_fic_keeps_no_fic_reason_None(self):
        # Two lines, fix lands on both → both have FIC → both no_fic_reason==None
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2.2", "n4.2", "n4.1.6", "n4.1.5", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix":
                    return ["n4.2.3", "n4.1.6"]
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        for line, line_dict in plan["lines"].items():
            self.assertIsNotNone(line_dict["line_key"])
            rt = line_dict["runtime"]
            self.assertIsNone(
                rt.get("no_fic_reason"),
                f"line {line} has FIC but no_fic_reason={rt.get('no_fic_reason')!r}",
            )

    def test_no_fic_reason_value_is_canonical(self):
        # Build a setup where some line has FIC and another doesn't
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2", "n4.1.6", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix":
                    return ["n4.2.3"]  # only 4.2 line has FIC
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        for line, line_dict in plan["lines"].items():
            rt = line_dict["runtime"]
            reason = rt.get("no_fic_reason")
            if reason is not None:
                self.assertIn(
                    reason, CANONICAL_NO_FIC_SUBTYPES,
                    f"line {line}: no_fic_reason={reason!r} not in canonical set",
                )

    def test_placeholder_no_fic_pending_search_not_used(self):
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2", "n4.1.6", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                return [] if commit != "fix" else ["n4.2.3"]

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        for line_dict in plan["lines"].values():
            self.assertNotEqual(
                line_dict["runtime"].get("no_fic_reason"),
                "no_fic_pending_search",
                "P0-3 placeholder must be replaced by canonical subtype",
            )


# ────────────────────────────────────────────────────────────────────
# Section 2 — planner-stage classification
# ────────────────────────────────────────────────────────────────────


class TestPlannerStageClassification(unittest.TestCase):
    def test_duplicate_expansion_missed_when_newer_line_has_fic(self):
        # 4.2 has FIC (fix lands at n4.2.3). 4.1 has NO FIC.
        # newer_line of 4.1 is 4.2 which has fix-cluster hit → 4.1 is
        # duplicate_expansion_missed (BAPEE candidate).
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2.2", "n4.2", "n4.1.6", "n4.1.5", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix":
                    return ["n4.2.3"]
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        rt_41 = plan["lines"]["4.1"]["runtime"]
        rt_42 = plan["lines"]["4.2"]["runtime"]
        # 4.2 has FIC → no_fic_reason None
        self.assertIsNone(rt_42["no_fic_reason"])
        # 4.1 has no FIC, but its newer line (4.2) has FIC → duplicate_expansion_missed
        self.assertEqual(
            rt_41["no_fic_reason"], "duplicate_expansion_missed",
            f"expected duplicate_expansion_missed, got {rt_41.get('no_fic_reason')!r}",
        )

    def test_never_fixed_on_this_line_when_no_ancestor_has_fic(self):
        # Single line, no fix anywhere → never_fixed_on_this_line.
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.1.3", "n4.1.2", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                # No tag contains the fix → no FIC anywhere
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        rt = plan["lines"]["4.1"]["runtime"]
        self.assertEqual(
            rt["no_fic_reason"], "never_fixed_on_this_line",
            f"expected never_fixed_on_this_line, got {rt.get('no_fic_reason')!r}",
        )

    def test_oldest_line_inherits_duplicate_expansion_missed_via_chain(self):
        # 3 lines: 4.3 has FIC, 4.2 and 4.1 have no FIC.
        # newer_line(4.1) = 4.2; newer_line(4.2) = 4.3 (which has FIC).
        # Both 4.2 and 4.1 → duplicate_expansion_missed (chain reaches FIC).
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.3.1", "n4.3", "n4.2.1", "n4.2", "n4.1.1", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix":
                    return ["n4.3.1"]
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        self.assertIsNone(plan["lines"]["4.3"]["runtime"]["no_fic_reason"])
        self.assertEqual(
            plan["lines"]["4.2"]["runtime"]["no_fic_reason"],
            "duplicate_expansion_missed",
        )
        self.assertEqual(
            plan["lines"]["4.1"]["runtime"]["no_fic_reason"],
            "duplicate_expansion_missed",
        )

    def test_classification_is_deterministic(self):
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.3.1", "n4.3", "n4.2", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                return ["n4.3.1"] if commit == "fix" else []

        plan_a = _build_plan(_Repo(), fixing_commits=[["fix"]])
        plan_b = _build_plan(_Repo(), fixing_commits=[["fix"]])
        for line in plan_a["lines"]:
            self.assertEqual(
                plan_a["lines"][line]["runtime"]["no_fic_reason"],
                plan_b["lines"][line]["runtime"]["no_fic_reason"],
                f"line {line}: classification not deterministic",
            )

    def test_openssl_no_fic_ignores_cross_family_fix_hits(self):
        # FIPS has a fix hit, but mainline has none. Mainline must NOT inherit
        # duplicate_expansion_missed from the FIPS family.
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return [
                    "OpenSSL-fips-2_0",
                    "OpenSSL-fips-1_2",
                    "OpenSSL_1_1_1",
                    "OpenSSL_1_1_0",
                ]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix":
                    return ["OpenSSL-fips-2_0"]
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]], repo_dir_name="openssl")
        self.assertIsNone(plan["lines"]["fips-2.0"]["runtime"]["no_fic_reason"])
        self.assertEqual(
            plan["lines"]["1.1.1"]["runtime"]["no_fic_reason"],
            "never_fixed_on_this_line",
        )
        boundary = plan["line_boundaries"]["1.1.1"]
        family_evidence = [
            e for e in boundary.get("evidence", [])
            if e.get("source") == "family_local_no_fic_diagnosis"
        ]
        self.assertTrue(family_evidence, "no family-local no-FIC evidence recorded")
        ignored = family_evidence[0].get("cross_family_fix_hits_ignored") or []
        self.assertTrue(
            any(x.get("line") == "fips-2.0" and x.get("family_key") == "openssl-fips" for x in ignored),
            f"expected fips fix hit to be recorded as ignored cross-family evidence, got {ignored!r}",
        )

    def test_same_family_newer_fix_still_marks_duplicate_missed(self):
        # Default repos keep the old single-family behavior: newer 4.2 has FIC,
        # older 4.1 has no FIC → duplicate_expansion_missed.
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.2.3", "n4.2", "n4.1.6", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                return ["n4.2.3"] if commit == "fix" else []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]], repo_dir_name="FFmpeg")
        self.assertEqual(plan["lines"]["4.2"]["family_key"], "FFmpeg-mainline")
        self.assertEqual(plan["lines"]["4.1"]["family_key"], "FFmpeg-mainline")
        self.assertEqual(
            plan["lines"]["4.1"]["runtime"]["no_fic_reason"],
            "duplicate_expansion_missed",
        )


# ────────────────────────────────────────────────────────────────────
# Section 3 — verifier-stage upgrade (ASBS verified_no_affected → line_not_vulnerable)
# ────────────────────────────────────────────────────────────────────


class _AlwaysNotAffectedAgent:
    """ASBS sees every probe as NOT_AFFECTED → returns verified_no_affected_on_line.
    Implements AgentRuntime Protocol."""

    @property
    def backend(self) -> str:
        return "always_na_test"

    def capabilities(self):
        from vulnversion.agent_harness.base import AgentCapabilities
        return AgentCapabilities(backend="always_na_test")

    def create_readonly_session(self, *, title=None) -> str:
        return "na-session"

    def run_json(self, *, session_id: str, prompt: str, system=None, tools=None,
                 timeout_s=None, metadata=None):
        tag = ""
        line = ""
        for prompt_line in prompt.splitlines():
            if prompt_line.startswith("# Task: Verify whether tag `"):
                tag = prompt_line.split("`")[1]
            if prompt_line.startswith("Release line: `"):
                line = prompt_line.split("`")[1]
        return {
            "tag": tag, "line": line, "verdict": "NOT_AFFECTED", "run_status": "OK",
            "confidence": 0.7, "reasoning_summary": "all-na",
            "matched_predicates": [], "failed_predicates": [], "triggered_guards": [],
            "evidence_snippets": [],
        }


def _init_real_repo(repo_dir: Path, tags: list[str]) -> str:
    subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "t@t"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "t"], check=True, capture_output=True)
    for i, tag in enumerate(tags):
        (repo_dir / "f.txt").write_text(f"line-{i}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_dir), "add", "f.txt"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", f"c{i}"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "tag", tag], check=True, capture_output=True)
    return subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-list", "-n", "1", tags[-1]]
    ).decode().strip()


def _write_minimal_rci(p: Path) -> None:
    p.write_text(json.dumps({
        "anchor": {"file_paths": ["f.txt"], "function_names": [], "stable_tokens": []},
        "vuln_predicates": [{"kind": "token_any", "args": {"tokens": ["unlikely"]}}],
        "fix_predicates": [{"kind": "token_any", "args": {"tokens": ["unlikely_fix_token"]}}],
        "guards": [],
    }, ensure_ascii=False, indent=2), encoding="utf-8")


class TestVerifierStageUpgrade(unittest.TestCase):
    def test_verified_no_affected_upgrades_to_line_not_vulnerable(self):
        # No FIC anywhere (no fixing_commits), single line, agent says all NA.
        # ASBS returns verified_no_affected_on_line → upgrade to line_not_vulnerable_in_released_tags.
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            out_dir = Path(tmp) / "out"
            repo_dir.mkdir(parents=True, exist_ok=True)
            _init_real_repo(repo_dir, ["1.0.0", "1.0.1", "1.0.2"])
            rci_path = Path(tmp) / "rci.json"
            _write_minimal_rci(rci_path)
            # Pass a totally unrelated commit as "fix" so contains-tag returns nothing
            verify_tags(
                repo_path=str(repo_dir),
                cve_id="CVE-X",
                rci_path=str(rci_path),
                out_dir=str(out_dir),
                fixing_commits=[["0000000000000000000000000000000000000000"]],
                resume=False,
                agent=_AlwaysNotAffectedAgent(),
                session_id="s",
                per_tag_session=False,
                log_progress=False,
            )
            line_boundaries = json.loads(
                (out_dir / "line_boundaries.json").read_text(encoding="utf-8")
            )
            runtime = json.loads(
                (out_dir / "vuln_tree_runtime.json").read_text(encoding="utf-8")
            )
            # main line should have status verified_no_affected_on_line
            for line, boundary in line_boundaries.items():
                if boundary.get("status") == "verified_no_affected_on_line":
                    rt = (boundary.get("runtime") or {})
                    self.assertEqual(
                        rt.get("no_fic_reason"),
                        "line_not_vulnerable_in_released_tags",
                        f"line {line}: ASBS verified no-affected but no_fic_reason={rt.get('no_fic_reason')!r}",
                    )
                    self.assertEqual(
                        ((runtime.get("line_boundaries") or {}).get(line) or {}).get("no_fic_reason"),
                        "line_not_vulnerable_in_released_tags",
                        "final vuln_tree_runtime.json must mirror verifier-stage no-FIC upgrade",
                    )
                    self.assertEqual(
                        ((runtime.get("lines") or {}).get(line) or {}).get("no_fic_reason"),
                        "line_not_vulnerable_in_released_tags",
                        "line runtime must mirror verifier-stage no-FIC upgrade",
                    )
                    return
            self.fail("no line returned verified_no_affected_on_line; cannot test upgrade")


# ────────────────────────────────────────────────────────────────────
# Section 4 — invariant: every no-FIC line has a canonical subtype
# ────────────────────────────────────────────────────────────────────


class TestNoFicInvariant(unittest.TestCase):
    def test_every_no_fic_line_has_canonical_subtype(self):
        class _Repo(_BaseFakeRepo):
            def list_tags(self, tags_glob=None, max_tags=None):
                return ["n4.3.1", "n4.3", "n4.2.5", "n4.2", "n4.1.3", "n4.1"]

            def list_tags_containing(self, commit, tags_glob=None):
                if commit == "fix":
                    return ["n4.3.1"]  # only 4.3 has FIC
                return []

        plan = _build_plan(_Repo(), fixing_commits=[["fix"]])
        for line, line_dict in plan["lines"].items():
            rt = line_dict["runtime"]
            has_fic = bool(rt.get("contains_fix_clusters"))
            reason = rt.get("no_fic_reason")
            if has_fic:
                self.assertIsNone(reason, f"line {line} has FIC but reason={reason!r}")
            else:
                self.assertIn(
                    reason, CANONICAL_NO_FIC_SUBTYPES,
                    f"no-FIC line {line} has invalid reason={reason!r}",
                )


if __name__ == "__main__":
    unittest.main()
