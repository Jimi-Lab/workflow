from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any


TESTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_DIR.parent


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


def _result_dirs(root: Path) -> dict[tuple[str, str], Path]:
  out: dict[tuple[str, str], Path] = {}
  if not root.exists():
    return out
  for path in root.glob("*/*"):
    if not path.is_dir():
      continue
    if any((path / name).exists() for name in ("per_tag_verdict.jsonl", "eval.json", "agent_trace.jsonl")):
      out[(path.parent.name, path.name)] = path
  return out


def _is_agent_row(row: dict[str, Any]) -> bool:
  source = str(row.get("verdict_source") or "").strip()
  status = str(row.get("run_status") or "").strip().upper()
  verdict = str(row.get("verdict") or "").strip().upper()
  if source == "agent":
    return True
  return source == "" and status in {"OK", "PARTIAL_PARSE"} and verdict in {"AFFECTED", "NOT_AFFECTED"}


def _label_for(row: dict[str, Any] | None, gt_tags: set[str]) -> bool | None:
  if row is None:
    return None
  verdict = str(row.get("verdict") or "").strip().upper()
  if verdict not in {"AFFECTED", "NOT_AFFECTED"}:
    return None
  tag = str(row.get("tag") or "")
  expected = "AFFECTED" if tag in gt_tags else "NOT_AFFECTED"
  return verdict == expected


def _confusion(rows: list[dict[str, Any]], gt_tags: set[str]) -> dict[str, Any]:
  tp = fp = fn = tn = unknown = 0
  for row in rows:
    if not _is_agent_row(row):
      unknown += 1
      continue
    tag = str(row.get("tag") or "")
    verdict = str(row.get("verdict") or "").strip().upper()
    if verdict not in {"AFFECTED", "NOT_AFFECTED"}:
      unknown += 1
      continue
    gt = tag in gt_tags
    if gt and verdict == "AFFECTED":
      tp += 1
    elif gt and verdict == "NOT_AFFECTED":
      fn += 1
    elif (not gt) and verdict == "AFFECTED":
      fp += 1
    else:
      tn += 1
  precision = tp / (tp + fp) if (tp + fp) else 0.0
  recall = tp / (tp + fn) if (tp + fn) else 0.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
  accuracy_denom = tp + fp + fn + tn
  accuracy = (tp + tn) / accuracy_denom if accuracy_denom else 0.0
  return {
    "TP": tp,
    "FP": fp,
    "FN": fn,
    "TN": tn,
    "UNKNOWN": unknown,
    "precision": precision,
    "recall": recall,
    "f1": f1,
    "accuracy": accuracy,
    "probed_count": accuracy_denom + unknown,
  }


def _trace_stats(cve_dir: Path) -> dict[str, Any]:
  rows = [
    row for row in _read_jsonl(cve_dir / "agent_trace.jsonl")
    if row.get("stage") == "stage3" and row.get("task_type") == "tag_verdict"
  ]
  by_trace: dict[str, dict[str, Any]] = {}
  latencies: list[float] = []
  prompt_chars: list[int] = []
  prompt_versions: dict[str, int] = {}
  errors = 0
  for row in rows:
    trace_id = str(row.get("trace_id") or "")
    if trace_id:
      by_trace[trace_id] = row
    try:
      latencies.append(float(row.get("latency_s") or 0.0))
    except Exception:
      pass
    try:
      prompt_chars.append(int(row.get("prompt_chars") or 0))
    except Exception:
      pass
    version = str(row.get("prompt_version") or ((row.get("metadata") or {}).get("prompt_version")) or "unknown")
    prompt_versions[version] = prompt_versions.get(version, 0) + 1
    if str(row.get("status") or "").lower() != "ok" or row.get("error"):
      errors += 1

  tool_calls = _tool_call_count(cve_dir)
  message_json_chars = _message_json_chars(cve_dir)
  return {
    "stage3_trace_count": len(rows),
    "avg_latency_s": sum(latencies) / len(latencies) if latencies else 0.0,
    "total_latency_s": sum(latencies),
    "avg_prompt_chars": sum(prompt_chars) / len(prompt_chars) if prompt_chars else 0.0,
    "total_prompt_chars": sum(prompt_chars),
    "trace_error_count": errors,
    "prompt_versions": prompt_versions,
    "tool_calls": tool_calls,
    "avg_tool_calls_per_tag": tool_calls / len(rows) if rows else 0.0,
    "message_json_chars": message_json_chars,
    "avg_message_json_chars_per_tag": message_json_chars / len(rows) if rows else 0.0,
  }


def _tool_call_count(cve_dir: Path) -> int:
  total = 0
  for name in ("opencode_messages_all.jsonl", "opencode_messages.jsonl"):
    path = cve_dir / name
    if not path.exists():
      continue
    for item in _read_jsonl(path):
      messages: list[dict[str, Any]] = []
      if isinstance(item.get("messages"), list):
        messages.extend([m for m in item["messages"] if isinstance(m, dict)])
      elif isinstance(item.get("message"), dict):
        messages.append(item["message"])
      else:
        messages.append(item)
      for message in messages:
        parts = message.get("parts") if isinstance(message, dict) else None
        if isinstance(parts, list):
          total += sum(1 for part in parts if isinstance(part, dict) and part.get("type") == "tool")
  return total


def _message_json_chars(cve_dir: Path) -> int:
  total = 0
  for name in ("opencode_messages_all.jsonl", "opencode_messages.jsonl"):
    path = cve_dir / name
    if path.exists():
      total += len(path.read_text(encoding="utf-8", errors="replace"))
  return total


def _cve_summary(root: Path, key: tuple[str, str], cve_dir: Path) -> dict[str, Any]:
  eval_json = _read_json(cve_dir / "eval.json")
  dataset_record = _read_json(cve_dir / "dataset_record.json")
  gt = eval_json.get("mapped_gt_tags") or dataset_record.get("affected_version") or []
  gt_tags = {str(tag) for tag in gt if str(tag).strip()}
  rows = _read_jsonl(cve_dir / "per_tag_verdict.jsonl")
  agent_rows = [row for row in rows if _is_agent_row(row)]
  row_by_tag = {str(row.get("tag") or ""): row for row in rows if row.get("tag") is not None}
  return {
    "repo": key[0],
    "cve_id": key[1],
    "path": str(cve_dir),
    "gt_tags": sorted(gt_tags),
    "agent_rows": agent_rows,
    "row_by_tag": row_by_tag,
    "metrics": _confusion(rows, gt_tags),
    "trace": _trace_stats(cve_dir),
    "json_parse_failure_count": sum(1 for row in rows if str(row.get("run_status") or "").upper() == "PARSE_ERROR"),
  }


def _sum_metrics(items: list[dict[str, Any]]) -> dict[str, Any]:
  out = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "UNKNOWN": 0, "probed_count": 0}
  total_latency = 0.0
  total_prompt_chars = 0
  trace_count = 0
  tool_calls = 0
  message_json_chars = 0
  json_parse_failures = 0
  for item in items:
    metrics = item["metrics"]
    for key in out:
      out[key] += int(metrics.get(key) or 0)
    trace = item["trace"]
    total_latency += float(trace.get("total_latency_s") or 0.0)
    total_prompt_chars += int(trace.get("total_prompt_chars") or 0)
    trace_count += int(trace.get("stage3_trace_count") or 0)
    tool_calls += int(trace.get("tool_calls") or 0)
    message_json_chars += int(trace.get("message_json_chars") or 0)
    json_parse_failures += int(item.get("json_parse_failure_count") or 0)
  precision = out["TP"] / (out["TP"] + out["FP"]) if (out["TP"] + out["FP"]) else 0.0
  recall = out["TP"] / (out["TP"] + out["FN"]) if (out["TP"] + out["FN"]) else 0.0
  f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
  accuracy_denom = out["TP"] + out["FP"] + out["FN"] + out["TN"]
  accuracy = (out["TP"] + out["TN"]) / accuracy_denom if accuracy_denom else 0.0
  return {
    **out,
    "precision": precision,
    "recall": recall,
    "f1": f1,
    "accuracy": accuracy,
    "stage3_probed_tag_accuracy": accuracy,
    "avg_latency_s_per_tag": total_latency / trace_count if trace_count else 0.0,
    "avg_prompt_chars_per_tag": total_prompt_chars / trace_count if trace_count else 0.0,
    "avg_tool_calls_per_tag": tool_calls / trace_count if trace_count else 0.0,
    "stage3_trace_count": trace_count,
    "tool_calls": tool_calls,
    "message_json_chars": message_json_chars,
    "avg_message_json_chars_per_tag": message_json_chars / out["probed_count"] if out["probed_count"] else 0.0,
    "json_parse_failure_count": json_parse_failures,
  }


def evaluate(baseline_root: Path, candidate_root: Path, out_dir: Path) -> dict[str, Any]:
  baseline_dirs = _result_dirs(baseline_root)
  candidate_dirs = _result_dirs(candidate_root)
  keys = sorted(set(baseline_dirs) | set(candidate_dirs))
  baseline_items: list[dict[str, Any]] = []
  candidate_items: list[dict[str, Any]] = []
  improved: list[dict[str, Any]] = []
  regression: list[dict[str, Any]] = []
  unchanged: list[dict[str, Any]] = []

  for key in keys:
    if key not in baseline_dirs or key not in candidate_dirs:
      continue
    base = _cve_summary(baseline_root, key, baseline_dirs[key])
    cand = _cve_summary(candidate_root, key, candidate_dirs[key])
    baseline_items.append(base)
    candidate_items.append(cand)
    gt_tags = set(base["gt_tags"] or cand["gt_tags"])
    tags = sorted(set(base["row_by_tag"]) | set(cand["row_by_tag"]))
    for tag in tags:
      b_row = base["row_by_tag"].get(tag)
      c_row = cand["row_by_tag"].get(tag)
      b_correct = _label_for(b_row, gt_tags)
      c_correct = _label_for(c_row, gt_tags)
      record = {
        "repo": key[0],
        "cve_id": key[1],
        "tag": tag,
        "expected": "AFFECTED" if tag in gt_tags else "NOT_AFFECTED",
        "baseline_verdict": (b_row or {}).get("verdict"),
        "candidate_verdict": (c_row or {}).get("verdict"),
        "baseline_correct": b_correct,
        "candidate_correct": c_correct,
      }
      if b_correct is not True and c_correct is True:
        improved.append(record)
      elif b_correct is True and c_correct is not True:
        regression.append(record)
      else:
        unchanged.append(record)

  out_dir.mkdir(parents=True, exist_ok=True)
  summary = {
    "baseline_root": str(baseline_root),
    "candidate_root": str(candidate_root),
    "compared_cves": len(baseline_items),
    "baseline": _sum_metrics(baseline_items),
    "candidate": _sum_metrics(candidate_items),
    "case_delta": {
      "improved": len(improved),
      "regression": len(regression),
      "unchanged": len(unchanged),
    },
  }
  cost = {
    "latency_delta_s_per_tag": summary["candidate"]["avg_latency_s_per_tag"] - summary["baseline"]["avg_latency_s_per_tag"],
    "prompt_chars_delta_per_tag": summary["candidate"]["avg_prompt_chars_per_tag"] - summary["baseline"]["avg_prompt_chars_per_tag"],
    "tool_calls_delta_per_tag": summary["candidate"]["avg_tool_calls_per_tag"] - summary["baseline"]["avg_tool_calls_per_tag"],
    "message_json_chars_delta_per_tag": summary["candidate"]["avg_message_json_chars_per_tag"] - summary["baseline"]["avg_message_json_chars_per_tag"],
  }
  summary["cost_delta"] = cost
  _write_json(out_dir / "agent_enhance_eval_summary.json", summary)
  _write_jsonl(out_dir / "improved_cases.jsonl", improved)
  _write_jsonl(out_dir / "regression_cases.jsonl", regression)
  _write_jsonl(out_dir / "unchanged_cases.jsonl", unchanged)
  _write_json(out_dir / "cost_report.json", cost)
  return summary


def _write_json(path: Path, obj: Any) -> None:
  path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
  with path.open("w", encoding="utf-8") as f:
    for row in rows:
      f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _make_fixture(root: Path) -> tuple[Path, Path]:
  base = root / "baseline" / "demo_repo" / "CVE-TEST-0001"
  cand = root / "candidate" / "demo_repo" / "CVE-TEST-0001"
  base.mkdir(parents=True)
  cand.mkdir(parents=True)
  for cve_dir in (base, cand):
    _write_json(cve_dir / "dataset_record.json", {"affected_version": ["v2"]})
    _write_json(cve_dir / "eval.json", {"mapped_gt_tags": ["v2"]})
  _write_jsonl(base / "per_tag_verdict.jsonl", [
    {"tag": "v1", "line": "main", "verdict": "NOT_AFFECTED", "run_status": "OK", "verdict_source": "agent"},
    {"tag": "v2", "line": "main", "verdict": "NOT_AFFECTED", "run_status": "OK", "verdict_source": "agent"},
    {"tag": "v3", "line": "main", "verdict": "UNKNOWN", "run_status": "ERROR", "verdict_source": "agent"},
  ])
  _write_jsonl(cand / "per_tag_verdict.jsonl", [
    {"tag": "v1", "line": "main", "verdict": "NOT_AFFECTED", "run_status": "OK", "verdict_source": "agent"},
    {"tag": "v2", "line": "main", "verdict": "AFFECTED", "run_status": "OK", "verdict_source": "agent"},
    {"tag": "v3", "line": "main", "verdict": "NOT_AFFECTED", "run_status": "OK", "verdict_source": "agent"},
  ])
  for cve_dir, version, latency in ((base, "v0", 10.0), (cand, "v1", 6.0)):
    _write_jsonl(cve_dir / "agent_trace.jsonl", [
      {
        "trace_id": f"{version}-v1",
        "stage": "stage3",
        "task_type": "tag_verdict",
        "prompt_version": version,
        "latency_s": latency,
        "prompt_chars": 1000 if version == "v0" else 800,
        "status": "ok",
        "metadata": {"tag": "v1"},
      },
      {
        "trace_id": f"{version}-v2",
        "stage": "stage3",
        "task_type": "tag_verdict",
        "prompt_version": version,
        "latency_s": latency,
        "prompt_chars": 1000 if version == "v0" else 800,
        "status": "ok",
        "metadata": {"tag": "v2"},
      },
    ])
    _write_jsonl(cve_dir / "opencode_messages_all.jsonl", [
      {
        "session": {"session_id": f"{version}-session"},
        "messages_count": 1,
        "messages": [
          {
            "parts": [
              {"type": "tool", "tool": "bash"},
              {"type": "tool", "tool": "git_git_cat_file"},
            ]
          }
        ],
      }
    ])
  return root / "baseline", root / "candidate"


def self_test() -> int:
  with tempfile.TemporaryDirectory() as tmp:
    base, cand = _make_fixture(Path(tmp))
    out = Path(tmp) / "eval"
    summary = evaluate(base, cand, out)
    ok = (
      summary["case_delta"]["improved"] == 2
      and summary["case_delta"]["regression"] == 0
      and summary["candidate"]["FN"] == 0
      and summary["baseline"]["UNKNOWN"] == 1
      and summary["candidate"]["UNKNOWN"] == 0
      and summary["baseline"]["tool_calls"] == 2
      and summary["candidate"]["tool_calls"] == 2
      and summary["baseline"]["message_json_chars"] > 0
      and summary["candidate"]["message_json_chars"] > 0
      and (out / "agent_enhance_eval_summary.json").exists()
      and (out / "improved_cases.jsonl").exists()
    )
    print(json.dumps({"self_test": "pass" if ok else "fail", "summary": summary}, ensure_ascii=False, indent=2))
    return 0 if ok else 1


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--baseline-result", type=Path)
  parser.add_argument("--candidate-result", type=Path)
  parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "Result_agent_enhance_eval" / "stage3_prompt_ab")
  parser.add_argument("--self-test", action="store_true")
  args = parser.parse_args()

  if args.self_test:
    return self_test()
  if args.baseline_result is None or args.candidate_result is None:
    parser.error("--baseline-result and --candidate-result are required unless --self-test is used")

  baseline_root = args.baseline_result
  candidate_root = args.candidate_result
  if not baseline_root.is_absolute():
    baseline_root = (Path.cwd() / baseline_root).resolve()
  if not candidate_root.is_absolute():
    candidate_root = (Path.cwd() / candidate_root).resolve()
  out_dir = args.out if args.out.is_absolute() else (Path.cwd() / args.out).resolve()

  summary = evaluate(baseline_root, candidate_root, out_dir)
  print(json.dumps(summary, ensure_ascii=False, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
