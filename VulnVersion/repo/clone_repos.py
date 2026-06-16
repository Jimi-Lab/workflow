from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def _project_root() -> Path:
  return Path(__file__).resolve().parents[1]


REPO_ROOT = _project_root() / "repo"

REPO_SPECS: dict[str, dict[str, object]] = {
  "FFmpeg": {
    "canonical_url": "https://git.ffmpeg.org/ffmpeg.git",
    "fallback_urls": ["https://github.com/FFmpeg/FFmpeg.git"],
    "required_paths": ["libavcodec", "configure"],
    "min_tag_count": 1,
  },
  "ImageMagick": {
    "canonical_url": "https://github.com/ImageMagick/ImageMagick.git",
    "fallback_urls": [],
    "required_paths": ["MagickCore", "MagickWand", "configure.ac"],
    "min_tag_count": 1,
  },
  "curl": {
    "canonical_url": "https://github.com/curl/curl.git",
    "fallback_urls": [],
    "required_paths": ["lib", "src/tool_main.c"],
    "min_tag_count": 1,
  },
  "httpd": {
    "canonical_url": "https://github.com/apache/httpd.git",
    "fallback_urls": ["https://gitbox.apache.org/repos/asf/httpd.git"],
    "required_paths": ["server", "modules", "configure.in"],
    "min_tag_count": 1,
  },
  "linux": {
    "canonical_url": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
    "fallback_urls": ["https://github.com/torvalds/linux.git"],
    "required_paths": ["kernel", "init/main.c", "drivers"],
    "min_tag_count": 1,
  },
  "openjpeg": {
    "canonical_url": "https://github.com/uclouvain/openjpeg.git",
    "fallback_urls": [],
    "required_paths": ["src/lib/openjp2", "CMakeLists.txt"],
    "min_tag_count": 1,
  },
  "openssl": {
    "canonical_url": "https://github.com/openssl/openssl.git",
    "fallback_urls": [],
    "required_paths": ["crypto", "ssl", "Configure"],
    "min_tag_count": 1,
  },
  "qemu": {
    "canonical_url": "https://gitlab.com/qemu-project/qemu.git",
    "fallback_urls": ["https://github.com/qemu/qemu.git"],
    "required_paths": ["hw", "softmmu", "meson.build"],
    "min_tag_count": 1,
  },
  "wireshark": {
    "canonical_url": "https://gitlab.com/wireshark/wireshark.git",
    "fallback_urls": ["https://github.com/wireshark/wireshark.git"],
    "required_paths": ["epan", "wiretap", "CMakeLists.txt"],
    "min_tag_count": 1,
  },
}

REPO_NAME_LOOKUP = {name.lower(): name for name in REPO_SPECS}


class GitCommandError(RuntimeError):
  pass


def _normalize_url(url: str) -> str:
  value = url.strip()
  if value.endswith("/"):
    value = value[:-1]
  if value.endswith(".git"):
    value = value[:-4]
  return value.lower()


def _run_git(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
  try:
    return subprocess.run(
      ["git", *args],
      cwd=str(cwd) if cwd is not None else None,
      check=True,
      capture_output=True,
      text=True,
      encoding="utf-8",
      errors="ignore",
    )
  except subprocess.CalledProcessError as e:
    detail = (e.stderr or e.stdout or "").strip()
    cmd = "git " + " ".join(args)
    if detail:
      raise GitCommandError(f"{cmd} failed: {detail}") from e
    raise GitCommandError(f"{cmd} failed with exit code {e.returncode}") from e


def _git_output(args: list[str], *, cwd: Path | None = None) -> str:
  return _run_git(args, cwd=cwd).stdout.strip()


def _resolve_repo_selection(raw: str | None) -> list[str]:
  if raw is None or not raw.strip():
    return []
  value = raw.strip()
  if value.lower() == "all":
    return sorted(REPO_SPECS.keys())

  resolved: list[str] = []
  unknown: list[str] = []
  for token in [x.strip() for x in value.split(",") if x.strip()]:
    match = REPO_NAME_LOOKUP.get(token.lower())
    if match is None:
      unknown.append(token)
      continue
    if match not in resolved:
      resolved.append(match)
  if unknown:
    supported = ", ".join(sorted(REPO_SPECS.keys()))
    raise SystemExit(f"Unsupported repo(s): {', '.join(unknown)}. Supported: {supported}, or use --repos all")
  return resolved


def _validate_existing_repo(repo_name: str, repo_dir: Path) -> None:
  spec = REPO_SPECS[repo_name]
  if not (repo_dir / ".git").exists():
    raise RuntimeError(f"{repo_name}: missing .git directory at {repo_dir}")

  inside = _git_output(["rev-parse", "--is-inside-work-tree"], cwd=repo_dir)
  if inside != "true":
    raise RuntimeError(f"{repo_name}: {repo_dir} is not a valid Git working tree")

  origin = _git_output(["remote", "get-url", "origin"], cwd=repo_dir)
  allowed = {_normalize_url(str(spec["canonical_url"]))}
  allowed.update(_normalize_url(str(x)) for x in spec.get("fallback_urls", []))
  if _normalize_url(origin) not in allowed:
    allowed_text = ", ".join(sorted(allowed))
    raise RuntimeError(f"{repo_name}: unexpected origin URL {origin!r}; expected one of: {allowed_text}")

  tags = [x for x in _git_output(["tag", "-l"], cwd=repo_dir).splitlines() if x.strip()]
  if len(tags) < int(spec.get("min_tag_count", 1)):
    raise RuntimeError(f"{repo_name}: repository has too few tags ({len(tags)})")

  missing_paths: list[str] = []
  for rel_path in spec.get("required_paths", []):
    try:
      _run_git(["cat-file", "-e", f"HEAD:{rel_path}"], cwd=repo_dir)
    except GitCommandError:
      missing_paths.append(str(rel_path))
  if missing_paths:
    raise RuntimeError(f"{repo_name}: missing expected paths at HEAD: {', '.join(missing_paths)}")


def _clone_repo(repo_name: str, *, repo_root: Path) -> None:
  spec = REPO_SPECS[repo_name]
  target_dir = repo_root / repo_name

  if target_dir.exists():
    if (target_dir / ".git").exists():
      _validate_existing_repo(repo_name, target_dir)
      print(f"[SKIP] {repo_name} already present and validated at {target_dir}")
      return
    raise SystemExit(f"{repo_name}: target path exists but is not a Git repo: {target_dir}")

  repo_root.mkdir(parents=True, exist_ok=True)
  clone_url = str(spec["canonical_url"])
  print(f"[CLONE] {repo_name} <- {clone_url}")
  _run_git(["clone", clone_url, str(target_dir)])
  _run_git(["fetch", "--tags", "--force", "origin"], cwd=target_dir)
  _validate_existing_repo(repo_name, target_dir)
  print(f"[OK] {repo_name} validated at {target_dir}")


def main(argv: list[str] | None = None) -> int:
  ap = argparse.ArgumentParser(description="Clone and validate VulnVersion target repositories.")
  ap.add_argument("--repos", default="", help="Comma-separated repo names or 'all'. Default: download nothing.")
  ap.add_argument("--repo-root", default=None, help="Override repo root. Default: <project>/repo")
  ap.add_argument("--list", action="store_true", help="List supported repos and exit.")
  args = ap.parse_args(argv)

  if args.list:
    for repo_name in sorted(REPO_SPECS.keys()):
      print(f"{repo_name}: {REPO_SPECS[repo_name]['canonical_url']}")
    return 0

  selected = _resolve_repo_selection(args.repos)
  if not selected:
    print("No repos selected. Use --repos all or --repos curl,openssl,...")
    return 0

  repo_root = Path(args.repo_root) if args.repo_root else REPO_ROOT
  if not repo_root.is_absolute():
    repo_root = (_project_root() / repo_root).resolve()

  print(f"Repo root: {repo_root}")
  try:
    for repo_name in selected:
      _clone_repo(repo_name, repo_root=repo_root)
  except (GitCommandError, RuntimeError) as e:
    raise SystemExit(str(e))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
