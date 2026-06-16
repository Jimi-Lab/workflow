from __future__ import annotations

import json

from pydantic import BaseModel

from .context import RootCauseContextPacket
from .models import RootCauseAgentOutput


class RootCausePrompt(BaseModel):
  system: str
  user: str


SYSTEM_PROMPT = """You are the VulnGraph Root Cause Agent.
Your only task is to reconstruct the code-level vulnerability mechanism for one CVE from auditable evidence.
Do not judge affected versions, target tags, vulnerable ranges, or neighboring targets.
Use only read-only Git tools and read-only repository inspection. Never edit files, checkout, reset, clean, commit, or run generated code.
Treat CVE/CWE/advisory text as context, not proof. Prefer fix commit parents, patch hunks, changed functions, and local data/control-flow evidence.
Separate vulnerable mechanism, fix mechanism, guards, negative applicability conditions, and refactor noise.
Every anchor, predicate, risk flag, and hypothesis must cite command_refs from command_invocations.
If the causal chain is incomplete, lower confidence and emit an ambiguous_causality risk flag. Do not invent evidence.
Return one JSON object only, with no Markdown or prose outside the JSON."""


def render_root_cause_prompt(packet: RootCauseContextPacket) -> RootCausePrompt:
  packet_json = json.dumps(packet.model_dump(mode="json"), ensure_ascii=False, indent=2)
  schema_json = json.dumps(RootCauseAgentOutput.model_json_schema(), ensure_ascii=False, indent=2)
  user = f"""Analyze {packet.cve_id} in repository {packet.repo}.
Repository path for every Git tool call: {packet.repo_path}

Bounded VulnGraph context packet:
{packet_json}

Required output JSON Schema:
{schema_json}

Operational requirements:
1. Inspect the fix commit and its parent when a fix commit is present.
2. Record every tool call in command_invocations, including a concise output excerpt.
3. Build CodeAnchor nodes before predicates, then connect predicates to one or more hypotheses by ID.
4. Keep learned_candidates empty unless a reusable repo/CWE/procedure lesson is directly supported by this run.
5. Use the run identity: cve_id={packet.cve_id}, repo={packet.repo}, repo_path={packet.repo_path}. Generate a unique run_id."""
  return RootCausePrompt(system=SYSTEM_PROMPT, user=user)
