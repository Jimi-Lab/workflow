from __future__ import annotations

import os
import subprocess
from pathlib import Path


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    command_env = os.environ.copy()
    command_env.update(
        {
            "GIT_AUTHOR_NAME": "VulnGraph Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "VulnGraph Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
    )
    if env:
        command_env.update(env)
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=command_env,
    )
    return completed.stdout.strip()


def commit(repo: Path, name: str, content: str | None = None) -> str:
    path = repo / f"{name}.txt"
    path.write_text(content or name, encoding="utf-8")
    git(repo, "add", path.name)
    git(repo, "commit", "-m", name)
    return git(repo, "rev-parse", "HEAD")


def make_linear_repo(tmp_path: Path) -> tuple[Path, list[str]]:
    repo = tmp_path / "openjpeg"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    commits = [commit(repo, "root"), commit(repo, "second"), commit(repo, "third")]
    git(repo, "tag", "v1.0.0", commits[0])
    git(repo, "tag", "-a", "v1.1.0", "-m", "release", commits[1])
    git(repo, "tag", "v1.1.0-alias", commits[1])
    git(repo, "tag", "test-internal", commits[2])
    return repo, commits
