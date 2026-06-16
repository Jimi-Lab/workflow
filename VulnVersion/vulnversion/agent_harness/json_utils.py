from __future__ import annotations

import json
from typing import Any


def extract_json_object(text: str) -> dict[str, Any]:
  s = text.strip()
  if not s:
    raise ValueError("empty model output")
  if s.startswith("{") and s.endswith("}"):
    return json.loads(s)
  first = s.find("{")
  last = s.rfind("}")
  if first >= 0 and last >= 0 and last > first:
    return json.loads(s[first : last + 1])
  raise ValueError("no json object found")
