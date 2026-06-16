from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tests.global_fic_tag_plan_experiment import build_global_fic_tag_plan


class TestGlobalFicTagPlanExperiment(unittest.TestCase):
  def test_global_fic_ignores_release_lines(self):
    class _Repo:
      def list_tags(self, tags_glob=None, max_tags=None):
        return ["n4.2.2", "n4.1.1", "n4.2", "n4.1", "n4.2.1"]

      def list_tags_containing(self, commit, tags_glob=None):
        if commit == "fix":
          return ["n4.2.2"]
        return []

    import tests.global_fic_tag_plan_experiment as exp

    original_open = exp.GitRepo.open
    try:
      exp.GitRepo.open = staticmethod(lambda repo_path: _Repo())  # type: ignore[method-assign]
      plan = build_global_fic_tag_plan(
        repo_path=Path(tempfile.gettempdir()) / "FFmpeg",
        repo_name="FFmpeg",
        cve_id="CVE-GLOBAL",
        fixing_commits=["fix"],
      )
    finally:
      exp.GitRepo.open = original_open  # type: ignore[method-assign]

    self.assertEqual(plan["plan_kind"], "global_fic_baseline")
    self.assertEqual(plan["global_tag_plan"], ["n4.1", "n4.1.1", "n4.2", "n4.2.1", "n4.2.2"])
    self.assertEqual(plan["global_fic_tag"], "n4.2.2")
    self.assertEqual(plan["candidate_tags_before_fic"], ["n4.1", "n4.1.1", "n4.2", "n4.2.1"])
    self.assertEqual(plan["candidate_count"], 4)

  def test_no_global_fic_marks_all_release_tags_as_candidates(self):
    class _Repo:
      def list_tags(self, tags_glob=None, max_tags=None):
        return ["n4.1.1", "n4.1", "not-a-release"]

      def list_tags_containing(self, commit, tags_glob=None):
        return []

    import tests.global_fic_tag_plan_experiment as exp

    original_open = exp.GitRepo.open
    try:
      exp.GitRepo.open = staticmethod(lambda repo_path: _Repo())  # type: ignore[method-assign]
      plan = build_global_fic_tag_plan(
        repo_path=Path(tempfile.gettempdir()) / "FFmpeg",
        repo_name="FFmpeg",
        cve_id="CVE-NO-FIC",
        fixing_commits=["fix"],
      )
    finally:
      exp.GitRepo.open = original_open  # type: ignore[method-assign]

    self.assertEqual(plan["status"], "no_global_fic")
    self.assertIsNone(plan["global_fic_tag"])
    self.assertEqual(plan["candidate_tags_before_fic"], ["n4.1", "n4.1.1"])


if __name__ == "__main__":
  unittest.main()
