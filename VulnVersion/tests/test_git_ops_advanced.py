import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnversion.git_ops.blame import git_blame
from vulnversion.git_ops.log import git_line_history, git_log_pickaxe
from vulnversion.git_ops.refs import git_rev_list_ancestry_path
from vulnversion.git_ops.repo import GitRepo, _git_base_cmd


class TestGitOpsAdvanced(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.repo_dir = Path(self._tmp.name) / "repo"
    self.repo_dir.mkdir()
    self._git("init")
    self._git("config", "user.email", "test@example.com")
    self._git("config", "user.name", "Test User")

    (self.repo_dir / "math.c").write_text(
      "int calc(int x) {\n"
      "  return x + 1;\n"
      "}\n",
      encoding="utf-8",
    )
    self._git("add", ".")
    self._git("commit", "-m", "add calc")
    self.commit_add_calc = self._head()

    (self.repo_dir / "math.c").write_text(
      "int calc(int x) {\n"
      "  return x + 2;\n"
      "}\n",
      encoding="utf-8",
    )
    self._git("add", ".")
    self._git("commit", "-m", "adjust calc")
    self.commit_adjust_calc = self._head()

    (self.repo_dir / "limits.c").write_text(
      "#define BUFFER_LIMIT 1024\n"
      "int get_limit(void) {\n"
      "  return BUFFER_LIMIT;\n"
      "}\n",
      encoding="utf-8",
    )
    self._git("add", ".")
    self._git("commit", "-m", "introduce buffer limit")
    self.commit_limit = self._head()

    self.repo = GitRepo.open(self.repo_dir)

  def tearDown(self):
    self._tmp.cleanup()

  def _git(self, *args: str) -> str:
    result = subprocess.run(
      ["git", "-C", str(self.repo_dir), *args],
      check=True,
      capture_output=True,
      text=True,
      encoding="utf-8",
    )
    return result.stdout.strip()

  def _head(self) -> str:
    return self._git("rev-parse", "HEAD")

  def test_git_log_pickaxe_string(self):
    out = git_log_pickaxe(
      self.repo,
      range_or_ref="HEAD",
      needle="BUFFER_LIMIT",
      regex=False,
    )
    commits = out["commits"]
    self.assertGreaterEqual(len(commits), 1)
    self.assertEqual(commits[0]["hash"], self.commit_limit[: len(commits[0]["hash"])])

  def test_git_log_pickaxe_regex(self):
    out = git_log_pickaxe(
      self.repo,
      range_or_ref="HEAD",
      needle=r"return x \+ [12]",
      regex=True,
    )
    subjects = [c["subject"] for c in out["commits"]]
    self.assertTrue(any("adjust calc" in s for s in subjects))
    self.assertTrue(any("add calc" in s for s in subjects))

  def test_git_line_history_function(self):
    out = git_line_history(
      self.repo,
      range_or_ref="HEAD",
      path="math.c",
      function_name="calc",
      max_chars=4000,
    )
    self.assertEqual(out["locator"], ":calc:math.c")
    self.assertGreaterEqual(len(out["commits"]), 1)
    self.assertIn("adjust calc", out["output"])

  def test_git_blame_range(self):
    out = git_blame(
      self.repo,
      ref="HEAD",
      path="math.c",
      start_line=1,
      end_line=2,
    )
    entries = out["entries"]
    self.assertEqual(len(entries), 2)
    self.assertEqual(entries[1]["final_line"], 2)
    self.assertEqual(entries[1]["author"], "Test User")
    self.assertEqual(entries[1]["text"], "  return x + 2;")

  def test_git_rev_list_ancestry_path(self):
    out = git_rev_list_ancestry_path(
      self.repo,
      older=self.commit_add_calc,
      newer=self.commit_limit,
      reverse=True,
    )
    self.assertEqual(
      out["commits"],
      [self.commit_adjust_calc, self.commit_limit],
    )

  def test_git_repo_uses_per_command_safe_directory(self):
    cmd = _git_base_cmd(str(self.repo.repo_path))
    self.assertEqual(cmd[0], "git")
    self.assertIn("-c", cmd)
    self.assertIn(f"safe.directory={self.repo.repo_path}", cmd)
    self.assertIn("-C", cmd)
    self.assertIn(str(self.repo.repo_path), cmd)


if __name__ == "__main__":
  unittest.main()
