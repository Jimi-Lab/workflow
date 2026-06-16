from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def ensure_cve_desc(
  *,
  out_dir: str | Path,
  cve_desc: str | None,
  cve_desc_file: str | Path | None,
  cve_source_json: dict[str, Any] | None,
) -> str:
  out = Path(out_dir)
  out.mkdir(parents=True, exist_ok=True)
  if cve_desc is None and cve_desc_file is not None:
    cve_desc = Path(cve_desc_file).read_text(encoding="utf-8")
  if not cve_desc or not cve_desc.strip():
    raise ValueError("cve_desc is required")
  (out / "cve_desc.txt").write_text(cve_desc.strip() + "\n", encoding="utf-8")
  if cve_source_json is not None:
    (out / "cve_source.json").write_text(json.dumps(cve_source_json, ensure_ascii=False, indent=2), encoding="utf-8")
  return cve_desc.strip()


def _load_json_file(path: str | Path) -> Any:
  return json.loads(Path(path).read_text(encoding="utf-8"))


def _read_cached_cve_desc_file(out_dir: str | Path) -> str | None:
  p = Path(out_dir) / "cve_desc.txt"
  if not p.exists():
    return None
  t = p.read_text(encoding="utf-8").strip()
  return t or None


def _read_nvd_cache_record(*, cve_id: str, nvd_cache_path: str | Path) -> dict[str, Any] | None:
  p = Path(nvd_cache_path)
  if not p.exists():
    return None
  data = _load_json_file(p)
  if not isinstance(data, dict):
    return None
  rec = data.get(cve_id)
  if not isinstance(rec, dict):
    return None
  if not isinstance(rec.get("description"), str) or not rec.get("description").strip():
    return None
  return rec


def _run_nvd_crawler_for_cve(
  *,
  cve_id: str,
  crawler_script_path: str | Path,
  dataset_path: str | Path,
  nvd_cache_path: str | Path,
  timeout_s: float = 120.0,
) -> None:
  cmd = [
    sys.executable,
    str(Path(crawler_script_path)),
    "--cve-id",
    cve_id,
    "--dataset",
    str(Path(dataset_path)),
    "--output",
    str(Path(nvd_cache_path)),
  ]
  subprocess.run(cmd, check=True, capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=timeout_s)


def ensure_cve_desc_from_nvd_cache_or_crawler(
  *,
  cve_id: str,
  out_dir: str | Path,
  nvd_cache_path: str | Path,
  crawler_script_path: str | Path,
  dataset_path: str | Path,
  allow_crawl: bool,
) -> str:
  cached = _read_cached_cve_desc_file(out_dir)
  if cached is not None:
    return cached

  rec = _read_nvd_cache_record(cve_id=cve_id, nvd_cache_path=nvd_cache_path)
  if rec is None and allow_crawl:
    _run_nvd_crawler_for_cve(
      cve_id=cve_id,
      crawler_script_path=crawler_script_path,
      dataset_path=dataset_path,
      nvd_cache_path=nvd_cache_path,
    )
    rec = _read_nvd_cache_record(cve_id=cve_id, nvd_cache_path=nvd_cache_path)

  if rec is None:
    raise RuntimeError(f"missing NVD cached record for {cve_id} in {Path(nvd_cache_path)}")

  return ensure_cve_desc(
    out_dir=out_dir,
    cve_desc=str(rec.get("description") or ""),
    cve_desc_file=None,
    cve_source_json={"source": "BaseData_nvd.json", "cve_id": cve_id, "record": rec, "cache_path": str(Path(nvd_cache_path))},
  )
