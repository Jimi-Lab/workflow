from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Sequence


@dataclass(frozen=True)
class RunResult:
  args: list[str]
  returncode: int
  stdout: str
  stderr: str


class RunError(RuntimeError):
  def __init__(self, result: RunResult):
    super().__init__(f"command failed: {result.args} (code={result.returncode})")
    self.result = result


def run(
  args: Sequence[str],
  *,
  cwd: str | None = None,
  timeout_s: float | None = None,
  env: dict[str, str] | None = None,
) -> RunResult:
  completed = subprocess.run(
    list(args),
    cwd=cwd,
    env=env,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
    timeout=timeout_s,
  )
  result = RunResult(
    args=list(args),
    returncode=completed.returncode,
    stdout=completed.stdout,
    stderr=completed.stderr,
  )
  if result.returncode != 0:
    raise RunError(result)
  return result

