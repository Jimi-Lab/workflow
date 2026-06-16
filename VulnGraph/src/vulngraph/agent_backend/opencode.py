from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx


DEFAULT_OPENCODE_PROVIDER_ID = "deepseek"
DEFAULT_OPENCODE_MODEL_ID = "deepseek-v4-pro"


def add_opencode_model_arguments(parser: argparse.ArgumentParser) -> None:
  parser.add_argument("--provider-id", default=DEFAULT_OPENCODE_PROVIDER_ID)
  parser.add_argument("--model-id", default=DEFAULT_OPENCODE_MODEL_ID)


READ_ONLY_GIT_TOOLS = (
  "vg_git_show",
  "vg_git_grep",
  "vg_git_diff",
  "vg_git_log",
  "vg_list_tags",
  "vg_git_ls_tree",
  "vg_git_cat_file",
  "vg_git_rev_parse",
  "vg_git_merge_base",
  "vg_git_show_ref",
)

LEGACY_GIT_TOOLS = (
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
)

DISABLED_NON_GIT_TOOLS = (
  "read",
  "grep",
  "glob",
  "list",
  "task",
  "todowrite",
  "webfetch",
  "websearch",
  "codesearch",
  "skill",
  "apply_patch",
  "question",
  "plan_enter",
  "plan_exit",
)


def readonly_permission_rules(*, allow_bash: bool = False) -> list[dict[str, str]]:
  rules = [
    {"permission": name, "action": "deny", "pattern": "*"}
    for name in ("edit", "write", "patch", "multiedit", *DISABLED_NON_GIT_TOOLS, *LEGACY_GIT_TOOLS)
  ]
  rules.append({"permission": "bash", "action": "allow" if allow_bash else "deny", "pattern": "*"})
  for name in READ_ONLY_GIT_TOOLS:
    rules.append({"permission": name, "action": "allow", "pattern": "*"})
  return rules


@dataclass(frozen=True)
class OpenCodeBackendConfig:
  base_url: str = "http://127.0.0.1:4096"
  provider_id: str | None = DEFAULT_OPENCODE_PROVIDER_ID
  model_id: str | None = DEFAULT_OPENCODE_MODEL_ID
  agent: str | None = None
  username: str | None = None
  password: str | None = None
  timeout_s: float = 300.0
  max_retries: int = 1
  allow_bash: bool = False


class OpenCodeBackend:
  def __init__(self, config: OpenCodeBackendConfig | None = None) -> None:
    self.config = config or OpenCodeBackendConfig()

  def _trust_env(self) -> bool:
    host = (urlparse(self.config.base_url).hostname or "").lower()
    return host not in {"127.0.0.1", "localhost", "::1"}

  def _auth(self) -> tuple[str, str] | None:
    if self.config.username is None or self.config.password is None:
      return None
    return self.config.username, self.config.password

  def _client(self, timeout_s: float | None = None) -> httpx.Client:
    return httpx.Client(
      base_url=self.config.base_url.rstrip("/"),
      timeout=self.config.timeout_s if timeout_s is None else timeout_s,
      trust_env=self._trust_env(),
      headers={"accept": "application/json"},
      auth=self._auth(),
    )

  def health(self) -> dict[str, Any]:
    with self._client() as client:
      response = client.get("/global/health")
      response.raise_for_status()
      data = response.json()
      return data if isinstance(data, dict) else {"healthy": True, "response": data}

  def create_readonly_session(self, *, title: str) -> str:
    body = {
      "title": title,
      "permission": readonly_permission_rules(allow_bash=self.config.allow_bash),
    }
    with self._client() as client:
      response = client.post("/session", json=body)
      response.raise_for_status()
      data = response.json()
    session_id = data.get("id") if isinstance(data, dict) else None
    if not isinstance(session_id, str) or not session_id:
      raise RuntimeError("OpenCode did not return a session id")
    return session_id

  def run_json(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str,
    timeout_s: float | None = None,
  ) -> dict[str, Any]:
    return _extract_json(
      self.run_text(
        session_id=session_id,
        prompt=prompt,
        system=system,
        timeout_s=timeout_s,
      )
    )

  def run_text(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str,
    timeout_s: float | None = None,
  ) -> str:
    last_error: Exception | None = None
    for attempt in range(max(0, self.config.max_retries) + 1):
      try:
        before = self._list_messages(session_id)
        body: dict[str, Any] = {
          "parts": [{"type": "text", "text": prompt}],
          "system": system,
          "tools": self._tool_switches(),
        }
        if self.config.agent:
          body["agent"] = self.config.agent
        if self.config.provider_id and self.config.model_id:
          body["model"] = {
            "providerID": self.config.provider_id,
            "modelID": self.config.model_id,
          }
        with self._client(timeout_s) as client:
          response = client.post(f"/session/{session_id}/prompt_async", json=body)
          response.raise_for_status()
        return self._poll_assistant_text(session_id, after_index=len(before), timeout_s=timeout_s)
      except Exception as error:
        last_error = error
        if attempt >= max(0, self.config.max_retries):
          break
        time.sleep(1.0)
    raise RuntimeError(f"OpenCode root-cause run failed: {last_error}") from last_error

  def _tool_switches(self) -> dict[str, bool]:
    switches = {name: True for name in READ_ONLY_GIT_TOOLS}
    switches.update({name: False for name in DISABLED_NON_GIT_TOOLS})
    switches["bash"] = self.config.allow_bash
    switches.update({"write": False, "edit": False, "patch": False, "multiedit": False})
    switches.update({name: False for name in LEGACY_GIT_TOOLS})
    return switches

  def _list_messages(self, session_id: str) -> list[dict[str, Any]]:
    with self._client() as client:
      response = client.get(f"/session/{session_id}/message")
      response.raise_for_status()
      data = response.json()
      return data if isinstance(data, list) else []

  def _poll_assistant_text(self, session_id: str, *, after_index: int, timeout_s: float | None) -> str:
    deadline = time.monotonic() + (timeout_s or self.config.timeout_s)
    while time.monotonic() < deadline:
      messages = self._list_messages(session_id)
      for message in reversed(messages[after_index:]):
        info = message.get("info") if isinstance(message, dict) else None
        if isinstance(info, dict) and info.get("role") == "assistant":
          error = info.get("error")
          if error:
            raise RuntimeError(f"OpenCode assistant error: {error}")
          text = _extract_text(message)
          if text:
            return text
      time.sleep(0.75)
    raise TimeoutError("OpenCode assistant reply timed out")


def _extract_text(message: Any) -> str:
  if not isinstance(message, dict):
    return ""
  texts = []
  for part in message.get("parts") or []:
    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
      texts.append(part["text"])
  return "\n".join(texts).strip()


def _extract_json(text: str) -> dict[str, Any]:
  candidate = text.strip()
  if candidate.startswith("```"):
    blocks = candidate.split("```")
    for block in blocks[1::2]:
      block = block.strip()
      if block.lower().startswith("json"):
        block = block[4:].strip()
      if block.startswith("{"):
        candidate = block
        break
  first = candidate.find("{")
  last = candidate.rfind("}")
  if first < 0 or last <= first:
    raise ValueError("assistant output does not contain a JSON object")
  parsed = json.loads(candidate[first : last + 1])
  if not isinstance(parsed, dict):
    raise ValueError("assistant output must be a JSON object")
  return parsed
