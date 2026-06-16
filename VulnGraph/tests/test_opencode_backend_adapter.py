from __future__ import annotations

import argparse
import json
from typing import Any

import httpx

from vulngraph.agent_backend import (
  DEFAULT_OPENCODE_MODEL_ID,
  DEFAULT_OPENCODE_PROVIDER_ID,
  OpenCodeBackend,
  OpenCodeBackendConfig,
  add_opencode_model_arguments,
)
from vulngraph.agent_backends.opencode import OpenCodeGenerateBackend


class _FakeOpenCodeBackend:
  def __init__(self, text: str) -> None:
    self.text = text
    self.session_id = "session-test"

  def health(self) -> dict[str, Any]:
    return {"healthy": True}

  def create_readonly_session(self, *, title: str) -> str:
    return self.session_id

  def run_text(self, *, session_id: str, prompt: str, system: str, timeout_s: float | None = None) -> str:
    assert session_id == self.session_id
    assert prompt
    return self.text


def test_opencode_defaults_to_deepseek_v4_pro() -> None:
  config = OpenCodeBackendConfig()

  assert DEFAULT_OPENCODE_PROVIDER_ID == "deepseek"
  assert DEFAULT_OPENCODE_MODEL_ID == "deepseek-v4-pro"
  assert config.provider_id == DEFAULT_OPENCODE_PROVIDER_ID
  assert config.model_id == DEFAULT_OPENCODE_MODEL_ID


def test_opencode_model_arguments_use_defaults_and_allow_override() -> None:
  parser = argparse.ArgumentParser()
  add_opencode_model_arguments(parser)

  defaults = parser.parse_args([])
  overridden = parser.parse_args(["--provider-id", "google", "--model-id", "gemini-2.5-flash"])

  assert defaults.provider_id == "deepseek"
  assert defaults.model_id == "deepseek-v4-pro"
  assert overridden.provider_id == "google"
  assert overridden.model_id == "gemini-2.5-flash"


def test_opencode_generate_backend_preserves_raw_assistant_text():
  raw = "```json\n{\"agent_run\":{\"run_id\":\"r1\",\"cve_id\":\"CVE-X\",\"backend\":\"opencode\"},\"root_cause_hypotheses\":[{\"hypothesis_id\":\"h1\",\"summary\":\"s\",\"git_observation_refs\":[\"obs-1\"]}]}\n```"
  backend = OpenCodeGenerateBackend(backend=_FakeOpenCodeBackend(raw), timeout_s=1.0)

  response = backend.generate("prompt", {"cve_id": "CVE-X", "system_prompt": "system"})

  assert response.status == "ok"
  assert response.backend_type == "opencode"
  assert response.raw_text == raw
  assert response.usage["session_id"] == "session-test"


def test_opencode_generate_backend_reports_empty_text():
  backend = OpenCodeGenerateBackend(backend=_FakeOpenCodeBackend(""), timeout_s=1.0)

  response = backend.generate("prompt", {"cve_id": "CVE-X"})

  assert response.status == "empty"
  assert response.raw_text == ""
  assert response.error == "empty assistant message"


class _MockHttpOpenCodeBackend(OpenCodeBackend):
  def __init__(self, handler) -> None:
    super().__init__(OpenCodeBackendConfig(base_url="http://opencode.test", timeout_s=0.2, max_retries=0))
    self._transport = httpx.MockTransport(handler)

  def _client(self, timeout_s: float | None = None) -> httpx.Client:
    return httpx.Client(
      base_url=self.config.base_url,
      timeout=self.config.timeout_s if timeout_s is None else timeout_s,
      transport=self._transport,
    )


def test_opencode_backend_uses_async_prompt_and_returns_assistant_text():
  requests: list[tuple[str, str]] = []
  message_reads = 0

  def handler(request: httpx.Request) -> httpx.Response:
    nonlocal message_reads
    requests.append((request.method, request.url.path))
    if request.method == "GET" and request.url.path.endswith("/message"):
      message_reads += 1
      if message_reads == 1:
        return httpx.Response(200, json=[])
      return httpx.Response(
        200,
        json=[
          {
            "info": {"role": "assistant"},
            "parts": [{"type": "text", "text": '{"ok":true}'}],
          }
        ],
      )
    if request.method == "POST" and request.url.path.endswith("/prompt_async"):
      assert json.loads(request.content)["parts"][0]["text"] == "prompt"
      return httpx.Response(204)
    return httpx.Response(404)

  backend = _MockHttpOpenCodeBackend(handler)

  assert backend.run_text(session_id="session-1", prompt="prompt", system="system", timeout_s=0.2) == '{"ok":true}'
  assert ("POST", "/session/session-1/prompt_async") in requests
  assert ("POST", "/session/session-1/message") not in requests


def test_opencode_backend_surfaces_async_assistant_error_without_timeout():
  message_reads = 0

  def handler(request: httpx.Request) -> httpx.Response:
    nonlocal message_reads
    if request.method == "GET" and request.url.path.endswith("/message"):
      message_reads += 1
      if message_reads == 1:
        return httpx.Response(200, json=[])
      return httpx.Response(
        200,
        json=[
          {
            "info": {
              "role": "assistant",
              "error": {"name": "AI_APICallError", "message": "Rate limit exceeded"},
            },
            "parts": [],
          }
        ],
      )
    if request.method == "POST" and request.url.path.endswith("/prompt_async"):
      return httpx.Response(204)
    return httpx.Response(404)

  backend = _MockHttpOpenCodeBackend(handler)

  try:
    backend.run_text(session_id="session-1", prompt="prompt", system="system", timeout_s=0.2)
  except RuntimeError as error:
    assert "Rate limit exceeded" in str(error)
  else:
    raise AssertionError("expected OpenCode assistant error")
