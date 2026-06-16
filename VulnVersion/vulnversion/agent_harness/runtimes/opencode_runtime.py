from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnversion.agent_harness.base import AgentCapabilities
from vulnversion.config import Config
from vulnversion.opencode.agent import OpenCodeAgent
from vulnversion.opencode.client import OpenCodeAuth, OpenCodeClient, readonly_permission_rules
from vulnversion.opencode.hints import opencode_start_hint


class OpenCodeRuntime:
  """AgentRuntime adapter for the existing OpenCode server integration."""

  def __init__(
    self,
    *,
    agent: OpenCodeAgent,
    base_url: str | None = None,
    provider_id: str | None = None,
    model_id: str | None = None,
    agent_name: str | None = None,
    project_root: str | Path | None = None,
  ) -> None:
    self._agent = agent
    self._client = getattr(agent, "_client", None)
    self._base_url = base_url
    self._provider_id = provider_id
    self._model_id = model_id
    self._agent_name = agent_name
    self._project_root = Path(project_root).resolve() if project_root is not None else Path.cwd().resolve()

  @property
  def backend(self) -> str:
    return "opencode"

  @classmethod
  def from_config(
    cls,
    cfg: Config,
    *,
    timeout_s: float,
    health_check: bool = True,
    project_root: str | Path | None = None,
  ) -> "OpenCodeRuntime":
    auth = None
    if cfg.opencode_username and cfg.opencode_password:
      auth = OpenCodeAuth(username=cfg.opencode_username, password=cfg.opencode_password)
    client = OpenCodeClient(base_url=cfg.opencode_base_url, auth=auth, timeout_s=timeout_s)
    if health_check:
      try:
        client.health()
      except Exception as e:
        raise RuntimeError(f"opencode_unreachable: {opencode_start_hint(cfg.opencode_base_url)}") from e
    agent = OpenCodeAgent(
      client=client,
      provider_id=cfg.opencode_provider_id,
      model_id=cfg.opencode_model_id,
      agent=cfg.opencode_agent,
    )
    return cls(
      agent=agent,
      base_url=cfg.opencode_base_url,
      provider_id=cfg.opencode_provider_id,
      model_id=cfg.opencode_model_id,
      agent_name=cfg.opencode_agent,
      project_root=project_root,
    )

  def capabilities(self) -> AgentCapabilities:
    return AgentCapabilities(
      backend=self.backend,
      supports_bash=True,
      supports_git_tools=True,
      supports_skills=True,
      supports_readonly_permissions=True,
      supports_system_prompt=True,
      supports_session_reuse=True,
      skill_source=".opencode/skills",
      json_reliability="repaired_json_object",
      notes=[
        "Uses the OpenCode server started from the VulnVersion project root.",
        "OpenCode skills come from VulnVersion/.opencode and are backend-specific.",
      ],
    )

  def diagnostics(self) -> dict[str, Any]:
    health: dict[str, Any]
    try:
      health = {"ok": True, "response": self._client.health() if self._client is not None else None}
    except Exception as e:
      health = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    agents: list[dict[str, Any]] = []
    agents_error: str | None = None
    try:
      if self._client is not None:
        agents = self._client.list_agents()
    except Exception as e:
      agents_error = f"{type(e).__name__}: {e}"

    return {
      "backend": self.backend,
      "base_url": self._base_url,
      "provider_id": self._provider_id,
      "model_id": self._model_id,
      "agent_name": self._agent_name,
      "project_root": str(self._project_root),
      "health": health,
      "agents_count": len(agents),
      "agents_error": agents_error,
      "agents": _summarize_opencode_agents(agents),
      "native_skills": self.native_skill_inventory(),
      "native_tools": self.native_tool_inventory(),
      "readonly_permissions": readonly_permission_rules(),
    }

  def native_skill_inventory(self) -> list[dict[str, Any]]:
    skill_root = self._project_root / ".opencode" / "skills"
    if not skill_root.exists():
      return []
    out: list[dict[str, Any]] = []
    for skill_dir in sorted(p for p in skill_root.iterdir() if p.is_dir()):
      skill_md = skill_dir / "SKILL.md"
      if not skill_md.exists():
        continue
      meta = _read_skill_frontmatter(skill_md)
      out.append(
        {
          "name": meta.get("name") or skill_dir.name,
          "description": meta.get("description"),
          "path": str(skill_md),
          "source": ".opencode/skills",
          "backend": self.backend,
        }
      )
    return out

  def native_tool_inventory(self) -> list[dict[str, Any]]:
    tools_root = self._project_root / ".opencode" / "tools"
    if not tools_root.exists():
      return []
    out: list[dict[str, Any]] = []
    for path in sorted(tools_root.glob("*.ts")):
      if path.name.endswith(".d.ts"):
        continue
      out.append({"name": path.stem, "path": str(path), "backend": self.backend})
    return out

  def create_readonly_session(self, *, title: str | None = None) -> str:
    return self._agent.create_readonly_session(title=title)

  def run_json(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str | None = None,
    tools: dict[str, bool] | None = None,
    timeout_s: float | None = None,
    metadata: dict[str, Any] | None = None,
  ) -> dict[str, Any]:
    return self._agent.run_json(
      session_id=session_id,
      prompt=prompt,
      system=system,
      tools=tools,
      timeout_s=timeout_s,
    )

  def export_session_messages(self, *, session_id: str) -> list[dict[str, Any]]:
    client = self._client
    if client is None or not hasattr(client, "list_messages"):
      return []
    return list(client.list_messages(session_id=session_id))


def _read_skill_frontmatter(path: Path) -> dict[str, str]:
  try:
    text = path.read_text(encoding="utf-8", errors="replace")
  except Exception:
    return {}
  lines = text.splitlines()
  if not lines or lines[0].strip() != "---":
    return {}
  meta: dict[str, str] = {}
  for line in lines[1:]:
    if line.strip() == "---":
      break
    if ":" not in line:
      continue
    k, v = line.split(":", 1)
    key = k.strip()
    val = v.strip().strip("\"'")
    if key:
      meta[key] = val
  return meta


def _summarize_opencode_agents(agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
  out: list[dict[str, Any]] = []
  for item in agents:
    if not isinstance(item, dict):
      continue
    summarized: dict[str, Any] = {}
    for key in ("name", "id", "description", "mode"):
      if key in item:
        summarized[key] = item.get(key)
    if summarized:
      out.append(summarized)
  return out
