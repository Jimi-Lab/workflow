from __future__ import annotations

import re


def normalize_whitespace(s: str) -> str:
  return re.sub(r"\s+", " ", s).strip()

