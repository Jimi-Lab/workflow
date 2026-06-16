from __future__ import annotations

import json
import time
from typing import Any

import httpx

from vulnversion.opencode.client import OpenCodeClient, readonly_permission_rules


class OpenCodeServerDownError(RuntimeError):
  """Raised when the OpenCode server is unreachable (connection refused / network error)."""
  pass


class OpenCodeJSONParseError(RuntimeError):
  """Raised when model output cannot be parsed into a JSON object."""

  def __init__(self, message: str, *, raw_text: str = "") -> None:
    super().__init__(message)
    self.raw_text = raw_text


def _is_connection_error(e: BaseException) -> bool:
  """Return True for errors that mean the server process is down — retrying is pointless."""
  if isinstance(e, (ConnectionRefusedError, ConnectionResetError, ConnectionError)):
    return True
  if isinstance(e, OSError) and getattr(e, 'winerror', None) in (10061, 10054, 10053):
    return True
  if isinstance(e, httpx.ConnectError):
    return True
  msg = str(e).lower()
  return "10061" in msg or "connection refused" in msg or "actively refused" in msg


def _extract_text_from_parts(message: dict[str, Any]) -> str:
  parts = message.get("parts") or []
  texts: list[str] = []
  for p in parts:
    if not isinstance(p, dict):
      continue
    if p.get("type") == "text":
      t = p.get("text")
      if isinstance(t, str) and t.strip():
        texts.append(t)
  return "\n".join(texts).strip()


def _message_role(message: dict[str, Any]) -> str:
  info = message.get("info")
  if not isinstance(info, dict):
    return ""
  role = info.get("role")
  return role if isinstance(role, str) else ""


def _message_error_text(message: dict[str, Any]) -> str:
  info = message.get("info")
  if not isinstance(info, dict):
    return ""
  err = info.get("error")
  if not isinstance(err, dict):
    return ""
  name = err.get("name")
  raw_data = err.get("data")
  data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
  raw_msg = data.get("message")
  msg = raw_msg if isinstance(raw_msg, str) else ""
  if isinstance(name, str) and name and msg:
    return f"{name}: {msg}"
  if isinstance(name, str) and name:
    return name
  return msg


def _pick_latest_assistant(messages: list[dict[str, Any]], after_idx: int) -> dict[str, Any] | None:
  if after_idx < 0:
    after_idx = 0
  for m in reversed(messages[after_idx:]):
    if _message_role(m) == "assistant":
      return m
  return None


def _extract_json_object(text: str) -> dict[str, Any]:
  s = text.strip()
  if not s:
    raise ValueError("empty model output")
  if s.startswith("{") and s.endswith("}"):
    return json.loads(s)
  first = s.find("{")
  last = s.rfind("}")
  if first >= 0 and last >= 0 and last > first:
    return json.loads(s[first : last + 1])
  raise ValueError("no json object found")


def _extract_fenced_json(text: str) -> str | None:
  s = text.strip()
  if "```" not in s:
    return None
  parts = s.split("```")
  for block in parts[1::2]:
    b = block.strip()
    if b.lower().startswith("json"):
      b = b[4:].strip()
    if b.startswith("{") and b.endswith("}"):
      return b
  return None


def _extract_largest_brace_object(text: str) -> str | None:
  # Extract the largest balanced {...} chunk; robust against prose before/after.
  best: tuple[int, int] | None = None
  stack = 0
  start = -1
  for i, ch in enumerate(text):
    if ch == "{":
      if stack == 0:
        start = i
      stack += 1
    elif ch == "}":
      if stack > 0:
        stack -= 1
        if stack == 0 and start >= 0:
          if best is None or (i - start) > (best[1] - best[0]):
            best = (start, i)
  if best is None:
    return None
  a, b = best
  return text[a : b + 1]


def _repair_json_text(candidate: str) -> str:
  # Minimal, conservative repairs to reduce parse failures.
  s = candidate.strip()
  # remove trailing commas before } or ]
  s = s.replace(",\n}", "\n}").replace(",\n]", "\n]")
  s = s.replace(",}", "}").replace(",]", "]")
  return s


def _extract_json_object_robust(text: str) -> dict[str, Any]:
  errs: list[Exception] = []

  # Attempt 1: original extractor
  try:
    return _extract_json_object(text)
  except Exception as e:
    errs.append(e)

  # Attempt 2: fenced ```json ... ``` block
  fenced = _extract_fenced_json(text)
  if fenced is not None:
    try:
      return json.loads(fenced)
    except Exception as e:
      errs.append(e)
      try:
        return json.loads(_repair_json_text(fenced))
      except Exception as e2:
        errs.append(e2)

  # Attempt 3: largest balanced brace object
  largest = _extract_largest_brace_object(text)
  if largest is not None:
    try:
      return json.loads(largest)
    except Exception as e:
      errs.append(e)
      try:
        return json.loads(_repair_json_text(largest))
      except Exception as e2:
        errs.append(e2)

  # Attempt 4: partial field extraction from raw text.
  # Even if the JSON is malformed, we can often recover key fields via regex.
  import re
  partial: dict[str, Any] = {}
  verdict_m = re.search(r'"verdict"\s*:\s*"(AFFECTED|NOT_AFFECTED)"', text)
  if verdict_m:
    partial["verdict"] = verdict_m.group(1)
  conf_m = re.search(r'"confidence"\s*:\s*([\d.]+)', text)
  if conf_m:
    try:
      partial["confidence"] = float(conf_m.group(1))
    except ValueError:
      pass
  tag_m = re.search(r'"tag"\s*:\s*"([^"]+)"', text)
  if tag_m:
    partial["tag"] = tag_m.group(1)
  reason_m = re.search(r'"reasoning_summary"\s*:\s*"([^"]*)"', text)
  if reason_m:
    partial["reasoning_summary"] = reason_m.group(1)
  run_status_m = re.search(r'"run_status"\s*:\s*"([^"]+)"', text)
  if run_status_m:
    partial["run_status"] = run_status_m.group(1)
  if partial.get("verdict"):
    partial.setdefault("run_status", "PARTIAL_PARSE")
    return partial

  # Keep the last parse error message for diagnostics.
  last = errs[-1] if errs else ValueError("no json object found")
  raise ValueError(str(last))


class OpenCodeAgent:
  def __init__(
    self,
    *,
    client: OpenCodeClient,
    provider_id: str | None = None,
    model_id: str | None = None,
    agent: str | None = None,
    max_retries: int = 2,
    retry_delay_s: float = 2.0,
  ) -> None:
    self._client = client
    self._provider_id = provider_id
    self._model_id = model_id
    self._agent = agent
    self._max_retries = max(0, int(max_retries))
    self._retry_delay_s = max(0.0, float(retry_delay_s))

  def create_readonly_session(self, *, title: str | None = None) -> str:
    session = self._client.create_session(title=title, permission=readonly_permission_rules())
    session_id = session.get("id")
    if not isinstance(session_id, str) or not session_id:
      raise RuntimeError("failed to create session")
    return session_id

  def run_json(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str | None = None,
    tools: dict[str, bool] | None = None,
    timeout_s: float | None = None,
  ) -> dict[str, Any]:
    if tools is None:
      tools = {}

    # Only disable known-broken duplicate wrapper tools (git_git_*),
    # NOT the standard git tools which agents need for navigation.
    for t in ["git_git_show", "git_git_diff"]:
      tools.setdefault(t, False)

    last_err: Exception | None = None
    last_text: str = ""
    attempts = self._max_retries + 1
    deadline: float | None = None
    if timeout_s is not None:
      timeout_s = float(timeout_s)
      if timeout_s <= 0:
        raise TimeoutError(f"tag_timeout_s={timeout_s}")
      deadline = time.monotonic() + timeout_s

    for i in range(attempts):
      try:
        request_timeout: float | None = None
        if deadline is not None:
          remaining = deadline - time.monotonic()
          if remaining <= 0:
            raise TimeoutError(f"tag_timeout_s={timeout_s}")
          request_timeout = remaining

        before = self._client.list_messages(session_id=session_id)

        msg = self._client.send_message(
          session_id=session_id,
          text=prompt,
          provider_id=self._provider_id,
          model_id=self._model_id,
          agent=self._agent,
          system=system,
          tools=tools,
          timeout_s=request_timeout,
        )

        text = _extract_text_from_parts(msg) if isinstance(msg, dict) else ""

        # Some OpenCode versions return HTTP 200 with an empty body from
        # /session/{id}/message. Fallback to polling /message list for assistant reply.
        if not text:
          start = len(before)
          poll_sleep_s = 0.75
          for _ in range(120):
            if deadline is not None and (deadline - time.monotonic()) <= 0:
              raise TimeoutError(f"tag_timeout_s={timeout_s}")
            messages = self._client.list_messages(session_id=session_id)
            candidate = _pick_latest_assistant(messages, start)
            if candidate is not None:
              err_text = _message_error_text(candidate)
              if err_text:
                raise RuntimeError(f"opencode_assistant_error: {err_text}")
              polled_text = _extract_text_from_parts(candidate)
              if polled_text:
                text = polled_text
                break
            time.sleep(poll_sleep_s)

        if not text:
          raise RuntimeError("opencode_no_assistant_reply")

        last_text = text
        return _extract_json_object_robust(text)
      except Exception as e:
        if isinstance(e, TimeoutError):
          raise
        # Connection-refused means server is down — retrying is pointless
        if _is_connection_error(e):
          raise OpenCodeServerDownError(
            f"opencode_server_down: {e}"
          ) from e
        last_err = e
        if i >= attempts - 1:
          break
        if deadline is not None and (deadline - time.monotonic()) <= 0:
          raise TimeoutError(f"tag_timeout_s={timeout_s}")
        if self._retry_delay_s > 0:
          time.sleep(self._retry_delay_s)
    if last_err is not None:
      raise OpenCodeJSONParseError(
        f"opencode_run_json_failed_after_retries: {last_err}",
        raw_text=last_text,
      )
    raise RuntimeError("opencode_run_json_failed_after_retries: unknown_error")
