from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any


def log_event(service: str, level: str, message: str, extra: dict[str, Any] | None = None) -> None:
  payload: dict[str, Any] = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "service": service,
    "level": level,
    "message": message,
  }
  if extra:
    payload["extra"] = extra
  sys.stderr.write(json.dumps(payload, ensure_ascii=False) + "\n")

