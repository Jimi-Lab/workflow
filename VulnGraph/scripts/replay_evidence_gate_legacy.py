from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from vulngraph.services.ingestion import ingest_root_cause_output
from vulngraph.store import JsonlGraphStore
from vulngraph.workflows.git_evidence import adapt_legacy_evidence_trace, enrich_legacy_packet_fix_sets


def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument("--artifacts", default="runs/batches/root-cause-v2-opencode-3")
  parser.add_argument("--dataset", default=r"E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json")
  parser.add_argument("--output", default="runs/evidence-gate-hardening/legacy_replay_results.json")
  args = parser.parse_args()

  artifacts = Path(args.artifacts)
  dataset = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
  results = []
  for case_dir in sorted(path for path in artifacts.iterdir() if path.is_dir()):
    required = {
      "packet": case_dir / "root_cause_packet.json",
      "trace": case_dir / "evidence_trace.json",
      "output": case_dir / "parsed_output.json",
    }
    if not all(path.exists() for path in required.values()):
      continue
    cve_id = case_dir.name
    packet = enrich_legacy_packet_fix_sets(
      cve_id,
      json.loads(required["packet"].read_text(encoding="utf-8")),
      (dataset.get(cve_id) or {}).get("fixing_commits"),
    )
    trace = adapt_legacy_evidence_trace(cve_id, packet, json.loads(required["trace"].read_text(encoding="utf-8")))
    with tempfile.TemporaryDirectory() as temp_dir:
      result = ingest_root_cause_output(
        JsonlGraphStore(temp_dir),
        cve_id,
        json.loads(required["output"].read_text(encoding="utf-8")),
        trace=trace,
        packet=packet,
      )
    results.append(
      {
        "cve_id": cve_id,
        "classification": "legacy_reconstructed" if trace.get("legacy_reconstructed") else "native",
        "created_from": trace.get("created_from"),
        "status": result.status,
        "raw_hypothesis_count": result.raw_hypothesis_count,
        "rejected_hypothesis_count": result.rejected_hypothesis_count,
        "trusted_observation_count": len(result.details.get("trusted_observation_ids", [])),
        "observation_rejections": result.details.get("observation_rejections", {}),
        "errors": result.errors,
        "warnings": result.warnings,
      }
    )
  output = Path(args.output)
  output.parent.mkdir(parents=True, exist_ok=True)
  output.write_text(json.dumps({"results": results}, ensure_ascii=False, indent=2), encoding="utf-8")
  print(json.dumps({"output": str(output), "results": results}, ensure_ascii=False))


if __name__ == "__main__":
  main()
