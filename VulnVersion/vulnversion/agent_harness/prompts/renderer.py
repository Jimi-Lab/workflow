from __future__ import annotations

from pathlib import Path
from string import Template
from typing import Any


class PromptRenderer:
  def __init__(self, *, template_dir: str | Path | None = None) -> None:
    self.template_dir = Path(template_dir) if template_dir is not None else Path(__file__).resolve().parent / "templates"

  def render(self, template_name: str, **values: Any) -> str:
    path = self.template_dir / template_name
    text = path.read_text(encoding="utf-8")
    return Template(text).safe_substitute({k: str(v) for k, v in values.items()})
