from __future__ import annotations

import json
from pathlib import Path


def _read_jsonl(path: Path) -> list[dict]:
  if not path.exists():
    return []
  return [json.loads(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def _tool_counts(path: Path) -> dict[str, int]:
  rows = _read_jsonl(path)
  total = git_bash = bash = skill = 0
  for row in rows:
    for msg in row.get("messages") or []:
      for part in msg.get("parts") or []:
        if not isinstance(part, dict) or part.get("type") != "tool":
          continue
        total += 1
        tool = str(part.get("tool") or "")
        if tool == "bash":
          bash += 1
        if tool == "skill":
          skill += 1
        if tool.startswith("git_") or tool == "list_tags" or tool == "bash":
          git_bash += 1
  return {"total": total, "git_bash": git_bash, "bash": bash, "skill": skill}


def _summary(version: str) -> dict:
  root = Path(__file__).resolve().parent
  cve_dir = root / version / "FFmpeg" / "CVE-2020-13904"
  trace = _read_jsonl(cve_dir / "agent_trace.jsonl")
  rows = _read_jsonl(cve_dir / "per_tag_verdict.jsonl")
  eval_data = json.loads((cve_dir / "eval.json").read_text(encoding="utf-8"))
  cm = eval_data.get("confusion_matrix") or {}
  denom = cm.get("TP", 0) + cm.get("FP", 0) + cm.get("FN", 0) + cm.get("TN", 0)
  latency_total = sum(float(row.get("latency_s") or 0.0) for row in trace)
  prompt_chars = 0
  for row in trace:
    prompt_path = row.get("prompt_path")
    if prompt_path and Path(prompt_path).exists():
      prompt_chars += len(Path(prompt_path).read_text(encoding="utf-8", errors="replace"))
  tools = _tool_counts(cve_dir / "opencode_messages_all.jsonl")
  status_counts: dict[str, int] = {}
  for row in rows:
    status = str(row.get("run_status") or "")
    status_counts[status] = status_counts.get(status, 0) + 1
  return {
    "version": version,
    "tags": len(rows),
    "trace_count": len(trace),
    "avg_latency_s_per_tag": latency_total / len(trace) if trace else 0.0,
    "avg_prompt_chars_per_tag": prompt_chars / len(trace) if trace else 0.0,
    "tool_calls": tools["total"],
    "avg_tool_calls_per_tag": tools["total"] / len(trace) if trace else 0.0,
    "git_bash_tool_calls": tools["git_bash"],
    "avg_git_bash_tool_calls_per_tag": tools["git_bash"] / len(trace) if trace else 0.0,
    "skill_tool_calls": tools["skill"],
    "TP": cm.get("TP", 0),
    "FP": cm.get("FP", 0),
    "FN": cm.get("FN", 0),
    "FN_execution": cm.get("FN_execution", 0),
    "TN": cm.get("TN", 0),
    "UNKNOWN": cm.get("UNK", 0),
    "stage3_probed_tag_accuracy": (cm.get("TP", 0) + cm.get("TN", 0)) / denom if denom else 0.0,
    "precision": eval_data.get("metrics_scanned_only", {}).get("precision"),
    "recall_scanned_only": eval_data.get("metrics_scanned_only", {}).get("recall"),
    "f1_scanned_only": eval_data.get("metrics_scanned_only", {}).get("f1"),
    "json_parse_failure": sum(1 for row in rows if str(row.get("run_status") or "").upper() == "PARSE_ERROR"),
    "run_status_counts": status_counts,
  }


def main() -> int:
  out = {"v0": _summary("v0"), "v1": _summary("v1")}
  out["delta"] = {
    "avg_latency_s_per_tag": out["v1"]["avg_latency_s_per_tag"] - out["v0"]["avg_latency_s_per_tag"],
    "avg_tool_calls_per_tag": out["v1"]["avg_tool_calls_per_tag"] - out["v0"]["avg_tool_calls_per_tag"],
    "stage3_probed_tag_accuracy": out["v1"]["stage3_probed_tag_accuracy"] - out["v0"]["stage3_probed_tag_accuracy"],
    "UNKNOWN": out["v1"]["UNKNOWN"] - out["v0"]["UNKNOWN"],
    "FN": out["v1"]["FN"] - out["v0"]["FN"],
  }
  out_path = Path(__file__).resolve().parent / "stage3_ab_strict_summary.json"
  out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
  print(json.dumps(out, ensure_ascii=False, indent=2))
  print(f"wrote {out_path}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
