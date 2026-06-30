from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def read(path: Path):
  return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument("--judge-run", type=Path, required=True)
  parser.add_argument("--converter-run", type=Path, required=True)
  parser.add_argument("--out", type=Path, required=True)
  args = parser.parse_args()
  predictions = {row["cve_id"]: row for row in (json.loads(line) for line in (args.converter_run / "per_cve_predictions.jsonl").read_text(encoding="utf-8").splitlines() if line.strip())}
  checks = {}
  failures = []

  def packet(cve: str):
    return read(args.judge_run / cve / "judge_boundary_input_v1_2.json")

  value = packet("CVE-2020-11984")
  checks["CVE-2020-11984"] = {"branch_context_count": len(value["branch_contexts"]), "prediction_count": len(predictions["CVE-2020-11984"]["affected_versions"])}
  if checks["CVE-2020-11984"]["branch_context_count"] < 2 or checks["CVE-2020-11984"]["prediction_count"] == 0:
    failures.append("CVE-2020-11984_branch_local_state")
  for cve in ("CVE-2020-11647", "CVE-2020-8231"):
    value = packet(cve)
    by_anchor = {}
    for event in value["history_event_candidates"]:
      by_anchor.setdefault(event["source_anchor_id"], set()).add(event["event_commit_sha"])
    checks[cve] = {"max_variant_sha_count": max(map(len, by_anchor.values()), default=0)}
    if checks[cve]["max_variant_sha_count"] < 2:
      failures.append(f"{cve}_variant_not_materialized")
  for cve in ("CVE-2020-12284", "CVE-2020-14212"):
    value = packet(cve)
    noisy = [event["old_line_text"] for event in value["history_event_candidates"] if re.fullmatch(r"\s*(?:[{}]|}\s*else\s*{|//.*|/\*.*)", event["old_line_text"])]
    checks[cve] = {"event_count": len(value["history_event_candidates"]), "noise": noisy, "fix_count": len({event["fix_commit_sha"] for event in value["history_event_candidates"]})}
    if noisy or not value["history_event_candidates"]:
      failures.append(f"{cve}_fallback_quality")
  if checks["CVE-2020-14212"]["fix_count"] < 2:
    failures.append("CVE-2020-14212_fix_coverage")
  value = packet("CVE-2020-13164")
  checks["CVE-2020-13164"] = {"prediction_count": len(predictions["CVE-2020-13164"]["affected_versions"]), "branch_context_count": len(value["branch_contexts"])}
  value = packet("CVE-2021-23840")
  checks["CVE-2021-23840"] = {"add_only_event_count": sum("add_only_semantic_anchor" in event.get("risk_flags", []) for event in value["history_event_candidates"])}
  if not checks["CVE-2021-23840"]["add_only_event_count"]:
    failures.append("CVE-2021-23840_add_only_recall")
  result = {"ok": not failures, "failures": failures, "checks": checks}
  args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
  print(json.dumps(result, indent=2))
  if failures:
    raise SystemExit(1)


if __name__ == "__main__":
  main()
