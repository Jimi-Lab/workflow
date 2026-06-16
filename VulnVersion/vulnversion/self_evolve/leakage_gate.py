from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


FORBIDDEN_PATTERNS = [
  r"\bgt_affected_tags\b",
  r"\bground\s*truth\b",
  r"\baffected\s*range\b",
  r"\bneighbor\s*verdict",
  r"\bscan\s*order\b",
  r"\bearly\s*stop\b",
  r"\btag\s*plan\b",
  r"\bplanner\s*state\b",
  r"\boracle_label\b",
]


def leakage_findings(candidate: dict[str, Any]) -> list[str]:
  text = json.dumps(candidate.get("content", {}), ensure_ascii=False)
  findings: list[str] = []
  for pattern in FORBIDDEN_PATTERNS:
    if re.search(pattern, text, flags=re.IGNORECASE):
      findings.append(pattern)
  return findings


def apply_leakage_gate(candidate: dict[str, Any]) -> dict[str, Any]:
  out = dict(candidate)
  findings = leakage_findings(candidate)
  out["leakage_findings"] = findings
  if findings:
    out["leakage_risk"] = "blocked"
    out["status"] = "blocked"
    out["injection_allowed"] = False
    out["blocked_reason"] = "leakage_gate_failed"
  else:
    out["leakage_risk"] = "pass"
    out.setdefault("status", "candidate")
    out["injection_allowed"] = False
  return out


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
  rows: list[dict[str, Any]] = []
  with Path(path).open("r", encoding="utf-8", errors="replace") as f:
    for line in f:
      text = line.strip()
      if text:
        value = json.loads(text)
        if isinstance(value, dict):
          rows.append(value)
  return rows
