from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = PROJECT_ROOT / ".opencode" / "skills"
DATASET_FILES = [
  PROJECT_ROOT / "DataSet" / "Dataset.json",
  PROJECT_ROOT / "DataSet" / "BaseDataSet.json",
  PROJECT_ROOT / "DataSet" / "BaseDataTest.json",
  PROJECT_ROOT / "DataSet" / "BaseDataOrder.json",
]
GIT_REQUIRED_REFERENCES = [
  "stage1.md",
  "stage2.md",
  "stage3.md",
  "revision-selection.md",
  "snapshot-navigation.md",
  "code-search.md",
  "history-and-rename.md",
  "tag-and-topology.md",
  "evidence-discipline.md",
]


def _read(path: Path) -> str:
  return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def _extract_dataset_cwes() -> dict[str, list[str]]:
  out: dict[str, list[str]] = {}
  for path in DATASET_FILES:
    if not path.exists():
      out[str(path.relative_to(PROJECT_ROOT))] = []
      continue
    text = _read(path)
    out[str(path.relative_to(PROJECT_ROOT))] = sorted(set(re.findall(r"CWE-\d+", text)))
  return out


def _check_git_navigation() -> dict[str, Any]:
  root = SKILL_ROOT / "git-navigation"
  skill_md = root / "SKILL.md"
  refs = root / "references"
  missing = [name for name in GIT_REQUIRED_REFERENCES if not (refs / name).exists()]
  text = (_read(skill_md) + "\n" + _read(refs / "stage3.md") + "\n" + _read(refs / "evidence-discipline.md")).lower()
  required_phrases = [
    "opencode-native",
    "judge-only",
    "tag:path",
    "git grep",
    "git show",
    "tag plan",
    "affected range",
    "failure-triggered",
  ]
  missing_phrases = [phrase for phrase in required_phrases if phrase.lower() not in text]
  return {
    "exists": skill_md.exists(),
    "required_reference_count": len(GIT_REQUIRED_REFERENCES),
    "missing_references": missing,
    "missing_v2_phrases": missing_phrases,
    "status": "pass" if skill_md.exists() and not missing and not missing_phrases else "fail",
  }


def _check_cwe_skills(dataset_cwes: list[str]) -> dict[str, Any]:
  root = SKILL_ROOT / "cwe-skills"
  refs = root / "references"
  skill_md = root / "SKILL.md"
  index_path = refs / "index.json"
  learned_root = refs / "learned"
  missing_cwe_files: list[dict[str, Any]] = []
  for cwe_id in dataset_cwes:
    cwe_dir = refs / "by-id" / cwe_id
    missing = [
      name
      for name in ("meta.json", "stage1.md", "stage2.md", "stage3.md")
      if not (cwe_dir / name).exists()
    ]
    if missing:
      missing_cwe_files.append({"cwe_id": cwe_id, "missing": missing})

  learned_required = [
    learned_root / "README.md",
    learned_root / "by-id" / ".gitkeep",
    learned_root / "candidates" / ".gitkeep",
  ]
  missing_learned = [str(p.relative_to(PROJECT_ROOT)) for p in learned_required if not p.exists()]
  text = _read(skill_md) + "\n" + _read(learned_root / "README.md")
  required_phrases = [
    "static base knowledge",
    "learned overlay",
    "case pack",
    "ReplayRuntime",
    "leakage gate",
    "verified overlay",
    "ArtifactMemory",
  ]
  missing_phrases = [phrase for phrase in required_phrases if phrase not in text]
  return {
    "exists": skill_md.exists(),
    "index_exists": index_path.exists(),
    "dataset_cwe_count": len(dataset_cwes),
    "covered_cwe_count": len(dataset_cwes) - len(missing_cwe_files),
    "missing_cwe_files": missing_cwe_files,
    "missing_learned_overlay_files": missing_learned,
    "missing_overlay_phrases": missing_phrases,
    "status": "pass" if skill_md.exists() and index_path.exists() and not missing_learned and not missing_phrases else "fail",
    "coverage_status": "pass" if not missing_cwe_files else "warn",
  }


def main() -> int:
  dataset_map = _extract_dataset_cwes()
  dataset_cwes = sorted({cwe for values in dataset_map.values() for cwe in values})
  git_summary = _check_git_navigation()
  cwe_summary = _check_cwe_skills(dataset_cwes)
  skills = [p.name for p in SKILL_ROOT.iterdir() if p.is_dir()] if SKILL_ROOT.exists() else []
  warnings: list[str] = []
  if cwe_summary["dataset_cwe_count"] == 0:
    warnings.append("no CWE IDs found in configured dataset files")
  if cwe_summary["missing_cwe_files"]:
    warnings.append("some dataset CWE IDs are missing static by-id files; this is reported as coverage warning, not learned-overlay failure")
  summary = {
    "project_root": str(PROJECT_ROOT),
    "total_skills": len(skills),
    "skills": sorted(skills),
    "git_navigation": git_summary,
    "cwe_skills": cwe_summary,
    "dataset_cwe_coverage": {
      "dataset_files": dataset_map,
      "unique_cwe_count": len(dataset_cwes),
      "unique_cwes": dataset_cwes,
      "covered_cwe_count": cwe_summary["covered_cwe_count"],
      "coverage": (cwe_summary["covered_cwe_count"] / len(dataset_cwes)) if dataset_cwes else 0.0,
    },
    "missing_cwe_files": cwe_summary["missing_cwe_files"],
    "warnings": warnings,
  }
  print(json.dumps(summary, ensure_ascii=False, indent=2))
  ok = git_summary["status"] == "pass" and cwe_summary["status"] == "pass"
  return 0 if ok else 1


if __name__ == "__main__":
  raise SystemExit(main())
