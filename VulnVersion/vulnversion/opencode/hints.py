from __future__ import annotations


DEFAULT_OPENCODE_BASE_URL = "http://127.0.0.1:4096"
DEFAULT_OPENCODE_SERVE_CMD = "opencode serve --hostname 127.0.0.1 --port 4096"


def opencode_start_hint(base_url: str = DEFAULT_OPENCODE_BASE_URL) -> str:
  return (
    f"please start OpenCode server on {base_url} using ./start_opencode.sh, "
    f".\\start_opencode.cmd, or `{DEFAULT_OPENCODE_SERVE_CMD}`"
  )


def opencode_restart_hint(base_url: str = DEFAULT_OPENCODE_BASE_URL) -> str:
  return (
    f"please restart the OpenCode server on {base_url} using ./start_opencode.sh, "
    f".\\start_opencode.cmd, or `{DEFAULT_OPENCODE_SERVE_CMD}`"
  )
