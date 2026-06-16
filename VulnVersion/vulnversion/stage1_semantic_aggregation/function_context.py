from __future__ import annotations

import re


_FUNC_HEADER_RE = re.compile(
  r"([A-Za-z_][\w\s\*\(\),]*\s+)?(?P<name>[A-Za-z_][\w]*)\s*\([^;]*\)\s*\{?"
)
_HUNK_NEW_LINE_RE = re.compile(r"\+(\d+)(?:,(\d+))?")


def function_from_hunk_header(header: str) -> str | None:
  if "@@" not in header:
    return None
  tail = header.split("@@", 2)[-1].strip()
  if not tail:
    return None
  match = _FUNC_HEADER_RE.search(tail)
  if not match:
    return tail
  return match.group("name")


def new_start_line_from_hunk_header(header: str) -> int | None:
  match = _HUNK_NEW_LINE_RE.search(header)
  if not match:
    return None
  try:
    return int(match.group(1))
  except ValueError:
    return None


def infer_function_context(*, hunk_header: str, file_text: str = "", new_start_line: int | None = None) -> str | None:
  from_header = function_from_hunk_header(hunk_header)
  if from_header:
    return from_header
  if not file_text or not new_start_line:
    return None

  lines = file_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
  idx = max(0, min(len(lines), new_start_line) - 1)
  for probe in range(idx, max(-1, idx - 80), -1):
    line = lines[probe].strip()
    if not line or line.startswith(("//", "/*", "*")):
      continue
    match = _FUNC_HEADER_RE.search(line)
    if match and not line.startswith(("if", "for", "while", "switch")):
      return match.group("name")
  return None
