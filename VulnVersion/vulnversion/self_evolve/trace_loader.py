from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from vulnversion.self_evolve.schema import SourcePaths


def read_json(path: Path) -> dict[str, Any]:
  return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
  if not path.exists():
    return
  with path.open("r", encoding="utf-8", errors="replace") as f:
    for line_no, line in enumerate(f, start=1):
      text = line.strip()
      if not text:
        continue
      try:
        value = json.loads(text)
      except json.JSONDecodeError:
        yield {"_json_error": True, "line_no": line_no, "raw": text}
        continue
      if isinstance(value, dict):
        yield value


def discover_result_dirs(result_root: str | Path) -> list[Path]:
  root = Path(result_root)
  if not root.exists():
    return []
  out: list[Path] = []
  for eval_path in root.glob("*/*/eval.json"):
    result_dir = eval_path.parent
    if (result_dir / "per_tag_verdict.jsonl").exists() or (result_dir / "agent_trace.jsonl").exists():
      out.append(result_dir)
  return sorted(out)


def load_trace_index(source_paths: SourcePaths) -> dict[str, dict[str, Any]]:
  """Return trace records keyed by trace_id.

  This is best-effort.  Historical CVE results may predate agent_trace.jsonl.
  Missing traces must not block case-pack generation.
  """
  traces: dict[str, dict[str, Any]] = {}
  if not source_paths.agent_trace_path:
    return traces
  for item in iter_jsonl(Path(source_paths.agent_trace_path)):
    trace_id = item.get("trace_id")
    if isinstance(trace_id, str) and trace_id:
      traces[trace_id] = item
  return traces


def load_calls_index(source_paths: SourcePaths) -> list[dict[str, Any]]:
  if not source_paths.calls_index_path:
    return []
  return list(iter_jsonl(Path(source_paths.calls_index_path)))
