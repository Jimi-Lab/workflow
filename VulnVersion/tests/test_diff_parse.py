import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnversion.git_ops.diff import _parse_patch


class TestDiffParse(unittest.TestCase):
  def test_parse_single_hunk(self):
    patch = "\n".join(
      [
        "diff --git a/a.txt b/a.txt",
        "index 0000000..1111111 100644",
        "--- a/a.txt",
        "+++ b/a.txt",
        "@@ -1,1 +1,1 @@",
        "-old",
        "+new",
        "",
      ]
    )
    files = _parse_patch(patch)
    self.assertEqual(len(files), 1)
    self.assertEqual(files[0]["path"], "a.txt")
    self.assertEqual(len(files[0]["hunks"]), 1)
    h = files[0]["hunks"][0]
    self.assertEqual(h["removed"], ["old"])
    self.assertEqual(h["added"], ["new"])


if __name__ == "__main__":
  unittest.main()
