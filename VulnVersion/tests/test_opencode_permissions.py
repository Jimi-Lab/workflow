import unittest

from vulnversion.opencode.client import readonly_permission_rules


class OpenCodePermissionRulesTest(unittest.TestCase):
  def test_skill_permission_is_allowed(self) -> None:
    rules = readonly_permission_rules()
    self.assertIn(
      {"permission": "skill", "action": "allow", "pattern": "*"},
      rules,
    )


if __name__ == "__main__":
  unittest.main()
