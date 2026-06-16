from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SkillRecord:
  skill_id: str
  stage: str
  scope: str
  backend: str | None = None
  lifecycle: str = "candidate"
  content: str = ""
  tags: list[str] = field(default_factory=list)
