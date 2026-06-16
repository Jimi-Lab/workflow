from __future__ import annotations

import argparse
import json
from pathlib import Path


REQUIRED_FILES = ("dataset_record.json", "rci.json", "per_tag_verdict.jsonl")


def _read_jsonl(path: Path) -> list[dict]:
  rows: list[dict] = []
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


def _row_score(row: dict, gt_tags: set[str]) -> tuple[int, str]:
  status = str(row.get("run_status") or "").upper()
  verdict = str(row.get("verdict") or "").upper()
  tag = str(row.get("tag") or "")
  if status in {"TIMEOUT", "ERROR", "PARSE_ERROR"} or verdict not in {"AFFECTED", "NOT_AFFECTED"}:
    return (0, tag)
  if tag in gt_tags:
    return (1, tag)
  return (2, tag)


def _select_tags(cve_dir: Path, limit: int) -> list[str]:
  record = {}
  try:
    record = json.loads((cve_dir / "dataset_record.json").read_text(encoding="utf-8"))
  except Exception:
    pass
  gt_tags = {str(t) for t in (record.get("affected_version") or []) if str(t).strip()}
  rows = [r for r in _read_jsonl(cve_dir / "per_tag_verdict.jsonl") if str(r.get("tag") or "").strip()]
  selected: list[str] = []
  for row in sorted(rows, key=lambda r: _row_score(r, gt_tags)):
    tag = str(row.get("tag") or "")
    if tag and tag not in selected:
      selected.append(tag)
    if len(selected) >= limit:
      break
  return selected


def build_plan(project: Path, cve_limit: int, tag_limit: int) -> list[dict]:
  result_root = project / "Result"
  existing_pairs: set[tuple[str, str]] = set()
  for version_root in ((project / "Result_stage3_ab_3cve" / "v0"), (project / "Result_stage3_ab_3cve" / "v1")):
    if not version_root.exists():
      continue
    for d in version_root.glob("*/*"):
      if d.is_dir():
        existing_pairs.add((d.parent.name, d.name))

  rows: list[dict] = []
  for cve_dir in sorted(result_root.glob("*/*")):
    if not cve_dir.is_dir():
      continue
    if not all((cve_dir / name).exists() for name in REQUIRED_FILES):
      continue
    repo = cve_dir.parent.name
    cve_id = cve_dir.name
    if (repo, cve_id) in existing_pairs:
      continue
    tags = _select_tags(cve_dir, tag_limit)
    if len(tags) < min(3, tag_limit):
      continue
    rows.append({
      "repo": repo,
      "cve_id": cve_id,
      "source_dir": str(cve_dir),
      "tag_source": str(cve_dir / "per_tag_verdict.jsonl"),
      "tags": tags,
      "tag_count": len(tags),
    })
    if len(rows) >= cve_limit:
      break
  return rows


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--cve-limit", type=int, default=5)
  parser.add_argument("--tag-limit", type=int, default=5)
  parser.add_argument("--out", type=Path, default=Path("Result_stage3_ab_cost_gate_plan.json"))
  args = parser.parse_args()

  project = Path(__file__).resolve().parents[1]
  plan = build_plan(project, args.cve_limit, args.tag_limit)
  out = args.out if args.out.is_absolute() else project / args.out
  out.write_text(json.dumps({"plan": plan}, ensure_ascii=False, indent=2), encoding="utf-8")
  print(json.dumps({"out": str(out), "cves": len(plan), "plan": plan}, ensure_ascii=False, indent=2))
  return 0 if plan else 1


if __name__ == "__main__":
  raise SystemExit(main())
