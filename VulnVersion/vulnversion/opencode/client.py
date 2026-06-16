from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json

import httpx
from urllib.parse import urlparse


@dataclass(frozen=True)
class OpenCodeAuth:
  username: str
  password: str


class OpenCodeClient:
  def _trust_env(self) -> bool:
    try:
      host = (urlparse(self._base_url).hostname or "").lower()
    except Exception:
      host = ""
    if host in {"127.0.0.1", "localhost", "::1"}:
      return False
    return True

  def __init__(
    self,
    *,
    base_url: str,
    auth: OpenCodeAuth | None = None,
    timeout_s: float = 300.0,
  ) -> None:
    self._base_url = base_url.rstrip("/")
    self._auth = auth
    self._timeout_s = timeout_s

  def _headers(self) -> dict[str, str]:
    return {"accept": "application/json"}

  def _auth_tuple(self) -> tuple[str, str] | None:
    if not self._auth:
      return None
    return (self._auth.username, self._auth.password)

  def health(self) -> dict[str, Any]:
    with httpx.Client(base_url=self._base_url, timeout=self._timeout_s, trust_env=self._trust_env()) as client:
      r = client.get("/global/health", headers=self._headers(), auth=self._auth_tuple())
      r.raise_for_status()
      return r.json()

  def list_agents(self) -> list[dict[str, Any]]:
    with httpx.Client(base_url=self._base_url, timeout=self._timeout_s, trust_env=self._trust_env()) as client:
      r = client.get("/agent", headers=self._headers(), auth=self._auth_tuple())
      r.raise_for_status()
      data = r.json()
      if isinstance(data, list):
        return data
      return []

  def create_session(
    self,
    *,
    title: str | None = None,
    parent_id: str | None = None,
    permission: list[dict[str, Any]] | None = None,
  ) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if title is not None:
      body["title"] = title
    if parent_id is not None:
      body["parentID"] = parent_id
    if permission is not None:
      body["permission"] = permission
    with httpx.Client(base_url=self._base_url, timeout=self._timeout_s, trust_env=self._trust_env()) as client:
      r = client.post("/session", json=body, headers=self._headers(), auth=self._auth_tuple())
      r.raise_for_status()
      return r.json()

  def send_message(
    self,
    *,
    session_id: str,
    text: str,
    provider_id: str | None = None,
    model_id: str | None = None,
    agent: str | None = None,
    system: str | None = None,
    no_reply: bool | None = None,
    tools: dict[str, bool] | None = None,
    message_id: str | None = None,
    timeout_s: float | None = None,
  ) -> dict[str, Any]:
    body: dict[str, Any] = {
      "parts": [{"type": "text", "text": text}],
    }
    if message_id is not None:
      body["messageID"] = message_id
    if agent is not None:
      body["agent"] = agent
    if system is not None:
      body["system"] = system
    if no_reply is not None:
      body["noReply"] = no_reply
    if tools is not None:
      body["tools"] = tools
    if provider_id is not None and model_id is not None:
      body["model"] = {"providerID": provider_id, "modelID": model_id}
    effective_timeout = self._timeout_s if timeout_s is None else float(timeout_s)
    with httpx.Client(base_url=self._base_url, timeout=effective_timeout, trust_env=self._trust_env()) as client:
      r = client.post(f"/session/{session_id}/message", json=body, headers=self._headers(), auth=self._auth_tuple())
      r.raise_for_status()
      raw = r.text or ""
      if not raw.strip():
        return {}
      try:
        return r.json()
      except json.JSONDecodeError:
        return {"_raw_response_text": raw}

  def list_messages(self, *, session_id: str, limit: int | None = None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {}
    if limit is not None:
      params["limit"] = limit
    with httpx.Client(base_url=self._base_url, timeout=self._timeout_s, trust_env=self._trust_env()) as client:
      r = client.get(f"/session/{session_id}/message", params=params, headers=self._headers(), auth=self._auth_tuple())
      r.raise_for_status()
      data = r.json()
      if isinstance(data, list):
        return data
      return []


def readonly_permission_rules() -> list[dict[str, Any]]:
  deny = [
    "edit",
    "write",
    "patch",
    "multiedit",
  ]
  allow = [
    "bash",
    "read",
    "grep",
    "glob",
    "list",
    "list_tags",
    # Allow loading project-local skills discovered by OpenCode.
    "skill",
    # Git read-only tools — agent needs direct git navigation
    "git_show",
    "git_grep",
    "git_diff",
    "git_log",
    "git_list_tags",
    "git_ls_tree",
    "git_cat_file",
    "git_rev_parse",
    "git_merge_base",
    "git_show_ref",
  ]
  rules: list[dict[str, Any]] = []
  for p in deny:
    rules.append({"permission": p, "action": "deny", "pattern": "*"})
  for p in allow:
    rules.append({"permission": p, "action": "allow", "pattern": "*"})
  rules.append({"permission": "question", "action": "deny", "pattern": "*"})
  return rules
