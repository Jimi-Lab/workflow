from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Paths:
  root_dir: Path
  artifacts_dir: Path

  @staticmethod
  def from_root(root_dir: str | Path, artifacts_dir: str | Path = "artifacts") -> "Paths":
    root = Path(root_dir).resolve()
    artifacts = (root / artifacts_dir).resolve() if not Path(artifacts_dir).is_absolute() else Path(artifacts_dir)
    return Paths(root_dir=root, artifacts_dir=artifacts)

  def cve_dir(self, cve_id: str) -> Path:
    return self.artifacts_dir / cve_id

  def ensure_dir(self, path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

