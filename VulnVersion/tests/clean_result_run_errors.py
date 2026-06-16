from __future__ import annotations

import argparse
import shutil
from pathlib import Path


# python tests/clean_result_run_errors.py --root "E:/AI/Agent/workflow/VulnVersion/Result"
def _project_root() -> Path:
  return Path(__file__).resolve().parents[1]


def _iter_cve_dirs_with_run_error(result_root: Path) -> list[Path]:
  seen: set[Path] = set()
  out: list[Path] = []
  for run_error in result_root.rglob("run_error.json"):
    cve_dir = run_error.parent
    if not cve_dir.is_dir():
      continue
    if not cve_dir.name.startswith("CVE-"):
      continue
    resolved = cve_dir.resolve()
    if resolved in seen:
      continue
    seen.add(resolved)
    out.append(resolved)
  out.sort()
  return out


def main(argv: list[str] | None = None) -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument("--root", default=None)
  ap.add_argument("--dry-run", action="store_true")
  args = ap.parse_args(argv)

  result_root = Path(args.root) if args.root else (_project_root() / "Result")
  if not result_root.is_absolute():
    result_root = (_project_root() / result_root).resolve()

  if not result_root.exists() or not result_root.is_dir():
    raise SystemExit(f"Result root not found: {result_root}")

  targets = _iter_cve_dirs_with_run_error(result_root)
  if not targets:
    print(f"[clean] no run_error.json found under: {result_root}")
    return 0

  try:
    for d in targets:
      if args.dry_run:
        print(f"[dry-run] delete: {d}")
      else:
        shutil.rmtree(d)
        print(f"[deleted] {d}")
    print(f"[clean] done. deleted={len(targets)} dry_run={bool(args.dry_run)}")
  except BrokenPipeError:
    return 0
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
