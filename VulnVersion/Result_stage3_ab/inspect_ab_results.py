from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict[str, Any]:
  if not path.exists():
    return {}
  try:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}
  except Exception:
    return {}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
  rows: list[dict[str, Any]] = []
  if not path.exists():
    return rows
  for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if not line.strip():
      continue
    try:
      item = json.loads(line)
      if isinstance(item, dict):
        rows.append(item)
    except Exception:
      continue
  return rows


def _is_agent_ok(row: dict[str, Any]) -> bool:
  verdict = str(row.get("verdict") or "").upper()
  status = str(row.get("run_status") or "").upper()
  source = str(row.get("verdict_source") or "")
  return source == "agent" and status in {"OK", "PARTIAL_PARSE"} and verdict in {"AFFECTED", "NOT_AFFECTED"}


def inspect(root: Path, version: str) -> dict[str, Any]:
  version_root = root / version
  items: list[dict[str, Any]] = []
  for cve_dir in sorted(version_root.glob("*/*")):
    if not cve_dir.is_dir():
      continue
    rows = _read_jsonl(cve_dir / "per_tag_verdict.jsonl")
    trace_rows = [
      r for r in _read_jsonl(cve_dir / "agent_trace.jsonl")
      if r.get("stage") == "stage3" and r.get("task_type") == "tag_verdict"
    ]
    message_text = ""
    message_path = cve_dir / "opencode_messages_all.jsonl"
    if message_path.exists():
      message_text = message_path.read_text(encoding="utf-8", errors="replace")
    unknown = [r for r in rows if not _is_agent_ok(r)]
    items.append({
      "repo": cve_dir.parent.name,
      "cve_id": cve_dir.name,
      "tags": len(rows),
      "unknown": [
        {
          "tag": r.get("tag"),
          "run_status": r.get("run_status"),
          "verdict": r.get("verdict"),
          "reasoning_summary": str(r.get("reasoning_summary") or "")[:300],
        }
        for r in unknown
      ],
      "avg_latency_s": (
        sum(float(r.get("latency_s") or 0.0) for r in trace_rows) / len(trace_rows)
        if trace_rows else 0.0
      ),
      "avg_prompt_chars": (
        sum(int(r.get("prompt_chars") or 0) for r in trace_rows) / len(trace_rows)
        if trace_rows else 0.0
      ),
      "message_json_chars": len(message_text),
      "avg_message_json_chars_per_tag": len(message_text) / len(rows) if rows else 0.0,
      "prompt_versions": sorted({str(r.get("prompt_version") or "") for r in trace_rows}),
    })
  total_tags = sum(int(item["tags"]) for item in items)
  total_message_chars = sum(int(item["message_json_chars"]) for item in items)
  total_unknown = sum(len(item["unknown"]) for item in items)
  return {
    "root": str(root),
    "version": version,
    "summary": {
      "cves": len(items),
      "tags": total_tags,
      "unknown": total_unknown,
      "message_json_chars": total_message_chars,
      "avg_message_json_chars_per_tag": total_message_chars / total_tags if total_tags else 0.0,
      "avg_latency_s": (
        sum(float(item["avg_latency_s"]) * int(item["tags"]) for item in items) / total_tags
        if total_tags else 0.0
      ),
      "avg_prompt_chars": (
        sum(float(item["avg_prompt_chars"]) * int(item["tags"]) for item in items) / total_tags
        if total_tags else 0.0
      ),
    },
    "cves": items,
  }


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--experiment-root", type=Path, default=Path("Result_stage3_ab_8cve"))
  parser.add_argument("--version", choices=["v0", "v1"], required=True)
  parser.add_argument("--out", type=Path, default=None)
  args = parser.parse_args()

  project = Path(__file__).resolve().parents[1]
  root = args.experiment_root if args.experiment_root.is_absolute() else project / args.experiment_root
  result = inspect(root, args.version)
  if args.out:
    out = args.out if args.out.is_absolute() else project / args.out
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
  print(json.dumps(result, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
