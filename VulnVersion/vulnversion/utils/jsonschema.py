from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from jsonschema import Draft202012Validator


def validate_json(schema: dict[str, Any], data: Any) -> None:
  Draft202012Validator(schema).validate(data)


def load_json(path: str | Path) -> Any:
  return json.loads(Path(path).read_text(encoding="utf-8"))


def dump_json(path: str | Path, data: Any) -> None:
  p = Path(path)
  p.parent.mkdir(parents=True, exist_ok=True)
  p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

