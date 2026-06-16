from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PromptSpec:
  name: str
  version: str
  schema_name: str
  builder: str = "python"
  template_name: str | None = None

  def model_dump(self) -> dict[str, Any]:
    return {
      "prompt_name": self.name,
      "prompt_version": self.version,
      "schema_name": self.schema_name,
      "prompt_builder": self.builder,
      "template_name": self.template_name,
    }

  def trace_metadata(self) -> dict[str, Any]:
    return {k: v for k, v in self.model_dump().items() if v is not None}


@dataclass(frozen=True)
class PromptProvenance:
  spec: PromptSpec
  prompt_hash: str | None = None
  system_hash: str | None = None
  prompt_chars: int | None = None
  system_chars: int | None = None

  def model_dump(self) -> dict[str, Any]:
    return {
      **self.spec.model_dump(),
      "prompt_hash": self.prompt_hash,
      "system_hash": self.system_hash,
      "prompt_chars": self.prompt_chars,
      "system_chars": self.system_chars,
    }


STAGE1_CHUNK_V0 = PromptSpec(
  name="stage1_chunk",
  version="v0",
  schema_name="stage1_chunk_role",
)

STAGE2_RCI_V0 = PromptSpec(
  name="stage2_rci",
  version="v0",
  schema_name="stage2_rci",
)

STAGE3_VERDICT_V0 = PromptSpec(
  name="stage3_verdict",
  version="v0",
  schema_name="stage3_tag_verdict",
  template_name="legacy_navigation",
)

STAGE3_VERDICT_V1 = PromptSpec(
  name="stage3_verdict",
  version="v1",
  schema_name="stage3_tag_verdict",
  template_name="target_tag_theorem_judge",
)
