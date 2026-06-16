from __future__ import annotations

from dataclasses import dataclass
import fnmatch
from functools import lru_cache
from pathlib import Path
import re
from typing import Any

from vulnversion.utils.subprocess import run


def _parse_oneline_log_output(out: str) -> list[dict[str, str]]:
  commits: list[dict[str, str]] = []
  for line in out.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
    t = line.strip()
    if not t:
      continue
    parts = t.split(maxsplit=1)
    if len(parts) != 2:
      continue
    commits.append({"hash": parts[0], "subject": parts[1]})
  return commits


def _extract_commit_summaries_from_patch_log(out: str) -> list[dict[str, str]]:
  lines = out.replace("\r\n", "\n").replace("\r", "\n").split("\n")
  commits: list[dict[str, str]] = []
  i = 0
  while i < len(lines):
    line = lines[i]
    if line.startswith("commit "):
      parts = line.split()
      commit = parts[1] if len(parts) > 1 else ""
      subject = ""
      j = i + 1
      while j < len(lines):
        probe = lines[j]
        if probe.startswith("commit "):
          break
        if probe.startswith("    ") and probe.strip():
          subject = probe.strip()
          break
        j += 1
      commits.append({"hash": commit, "subject": subject})
    i += 1
  return commits


def _git_base_cmd(repo_path: str) -> list[str]:
  """Return a repo-local git command stable under safe.directory checks."""

  return ["git", "-c", f"safe.directory={repo_path}", "-C", repo_path]


def _is_cacheable_git(args: tuple[str, ...]) -> bool:
  if not args:
    return False
  cmd = args[0]
  if cmd in {"rev-parse", "tag", "rev-list", "diff-tree", "branch"}:
    return True
  if cmd == "show" and "--no-patch" in args:
    return True
  return False


@lru_cache(maxsize=200_000)
def _run_git_cached(repo_path: str, args: tuple[str, ...]) -> str:
  return run([*_git_base_cmd(repo_path), *args]).stdout


def _run_git_uncached(repo_path: str, args: tuple[str, ...]) -> str:
  return run([*_git_base_cmd(repo_path), *args]).stdout


@lru_cache(maxsize=20_000)
def _patch_id_cached(repo_path: str, commit_resolved: str) -> str:
  out = run([
    "python",
    "-c",
    (
      "import subprocess,sys;"
      f"p1=subprocess.run(['git','-c',r'safe.directory={repo_path}','-C',r'{repo_path}','show','--pretty=email','{commit_resolved}'],capture_output=True,text=False,check=True);"
      "p2=subprocess.run(['git','patch-id','--stable'],input=p1.stdout,capture_output=True,text=True,check=True);"
      "sys.stdout.write(p2.stdout)"
    ),
  ]).stdout.strip()
  return out.split()[0] if out else ""


@dataclass(frozen=True)
class GitRepo:
  repo_path: Path

  @staticmethod
  def open(repo_path: str | Path) -> "GitRepo":
    return GitRepo(repo_path=Path(repo_path).resolve())

  def _git(self, args: list[str]) -> str:
    args_tuple = tuple(args)
    repo_path = str(self.repo_path)
    if _is_cacheable_git(args_tuple):
      return _run_git_cached(repo_path, args_tuple)
    return _run_git_uncached(repo_path, args_tuple)

  def rev_parse(self, rev: str) -> str:
    return self._git(["rev-parse", "--verify", f"{rev}^{{}}"]).strip()

  def show(self, ref: str, path: str) -> str:
    ref_resolved = self.rev_parse(ref)
    return self._git(["show", f"{ref_resolved}:{path}"])

  def grep(self, ref: str, pattern: str, path_glob: str | None = None, *, fixed: bool = False) -> list[dict[str, Any]]:
    ref_resolved = self.rev_parse(ref)
    args = ["grep", "-n", "--no-color"]
    if fixed:
      args.append("-F")
    args.extend(["-e", pattern, ref_resolved])
    if path_glob:
      args.extend(["--", path_glob])
    out = self._git(args)
    matches: list[dict[str, Any]] = []
    for line in out.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
      if not line:
        continue
      # Format is typically: <ref>:<path>:<line_no>:<content>
      parts = line.split(":", 3)
      if len(parts) < 4:
        continue
      ref_out, path, line_no_str, text = parts
      try:
        line_no = int(line_no_str)
      except ValueError:
        continue
      matches.append({"ref": ref_out, "path": path, "line": line_no, "text": text})
    return matches

  def show_patch(self, commit: str) -> str:
    commit_resolved = self.rev_parse(commit)
    patch = self._git(["show", "--patch", "--no-color", "--format=", commit_resolved])
    if patch.strip():
      return patch
    if len(self.commit_parents(commit_resolved)) > 1:
      # git-show does not emit a normal patch for many merge commits unless the
      # merge is diffed against a parent. Use the first-parent view because the
      # dataset's fixing commit is the merge object users see on GitHub.
      return self._git(["show", "-m", "--first-parent", "--patch", "--no-color", "--format=", commit_resolved])
    return patch

  def blame(
    self,
    ref: str,
    path: str,
    *,
    start_line: int | None = None,
    end_line: int | None = None,
  ) -> list[dict[str, Any]]:
    ref_resolved = self.rev_parse(ref)
    args = ["blame", "--line-porcelain"]
    if start_line and end_line and start_line > 0 and end_line >= start_line:
      args.extend(["-L", f"{start_line},{end_line}"])
    args.extend([ref_resolved, "--", path])
    out = self._git(args)

    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    header_re = re.compile(r"^([0-9a-f]{7,40})\s+(\d+)\s+(\d+)\s+(\d+)$")

    for line in out.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
      if not line:
        continue
      m = header_re.match(line)
      if m:
        if current is not None and "text" in current:
          entries.append(current)
        current = {
          "commit": m.group(1),
          "orig_line": int(m.group(2)),
          "final_line": int(m.group(3)),
          "group_lines": int(m.group(4)),
        }
        continue
      if current is None:
        continue
      if line.startswith("author "):
        current["author"] = line[7:]
      elif line.startswith("author-mail "):
        current["author_mail"] = line[12:]
      elif line.startswith("author-time "):
        try:
          current["author_time"] = int(line[12:])
        except ValueError:
          current["author_time"] = line[12:]
      elif line.startswith("author-tz "):
        current["author_tz"] = line[10:]
      elif line.startswith("summary "):
        current["summary"] = line[8:]
      elif line.startswith("filename "):
        current["filename"] = line[9:]
      elif line.startswith("\t"):
        current["text"] = line[1:]

    if current is not None and "text" in current:
      entries.append(current)
    return entries

  def log_pickaxe(
    self,
    *,
    range_or_ref: str,
    needle: str,
    regex: bool = False,
    path_glob: str | None = None,
    max_commits: int | None = None,
    pickaxe_all: bool = False,
  ) -> list[dict[str, str]]:
    max_count = max_commits if max_commits and max_commits > 0 else 50
    args = ["log", "--oneline", "--decorate", f"--max-count={max_count}"]
    args.extend(["-G" if regex else "-S", needle])
    if pickaxe_all:
      args.append("--pickaxe-all")
    args.append(range_or_ref)
    if path_glob:
      args.extend(["--", path_glob])
    out = self._git(args)
    return _parse_oneline_log_output(out)

  def log_line_history(
    self,
    *,
    range_or_ref: str,
    path: str,
    function_name: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
    max_commits: int | None = None,
    max_chars: int | None = None,
  ) -> dict[str, Any]:
    if function_name:
      locator = f":{function_name}:{path}"
    elif start_line and end_line and start_line > 0 and end_line >= start_line:
      locator = f"{start_line},{end_line}:{path}"
    else:
      raise ValueError("line_history_requires_function_or_range")

    max_count = max_commits if max_commits and max_commits > 0 else 20
    args = ["log", f"--max-count={max_count}", f"-L{locator}", range_or_ref]
    out = self._git(args)
    limited = out[:max_chars] if max_chars and max_chars > 0 else out
    return {
      "range_or_ref": range_or_ref,
      "locator": locator,
      "commits": _extract_commit_summaries_from_patch_log(limited),
      "output": limited,
    }

  def list_tags(self, tags_glob: str | None = None, max_tags: int | None = None) -> list[str]:
    args = ["tag", "-l", "--sort=-creatordate"]
    if tags_glob:
      args.append(tags_glob)
    out = self._git(args)
    tags = [t.strip() for t in out.replace("\r\n", "\n").replace("\r", "\n").split("\n") if t.strip()]
    if max_tags and max_tags > 0:
      return tags[:max_tags]
    return tags

  def list_tags_sorted_version(self, tags_glob: str | None = None, max_tags: int | None = None) -> list[str]:
    args = ["tag", "-l", "--sort=version:refname"]
    if tags_glob:
      args.append(tags_glob)
    out = self._git(args)
    tags = [t.strip() for t in out.replace("\r\n", "\n").replace("\r", "\n").split("\n") if t.strip()]
    if max_tags and max_tags > 0:
      return tags[:max_tags]
    return tags

  def list_tags_not_containing(
    self,
    commit: str,
    *,
    tags_glob: str | None = None,
    max_tags: int | None = None,
  ) -> list[str]:
    """Return tags that do NOT contain the given commit (i.e. pre-fix tags),
    sorted from newest to oldest by creation date (closest to fix first)."""
    commit_resolved = self.rev_parse(commit)
    args = ["tag", "-l", "--sort=-creatordate", "--no-contains", commit_resolved]
    if tags_glob:
      args.append(tags_glob)
    out = self._git(args)
    tags = [t.strip() for t in out.replace("\r\n", "\n").replace("\r", "\n").split("\n") if t.strip()]
    if max_tags and max_tags > 0:
      return tags[:max_tags]
    return tags

  def list_tags_containing(
    self,
    commit: str,
    *,
    tags_glob: str | None = None,
  ) -> list[str]:
    """Return tags that contain the given commit, sorted oldest-first by creation date.
    The first element is the earliest tag that includes this commit (the 'fix tag')."""
    commit_resolved = self.rev_parse(commit)
    args = ["tag", "-l", "--sort=creatordate", "--contains", commit_resolved]
    if tags_glob:
      args.append(tags_glob)
    out = self._git(args)
    return [t.strip() for t in out.replace("\r\n", "\n").replace("\r", "\n").split("\n") if t.strip()]

  def tag_commit(self, tag: str) -> str:
    """Return the commit object pointed to by a tag."""
    return self._git(["rev-list", "-n", "1", tag]).strip()

  def commit_parents(self, commit: str) -> list[str]:
    commit_resolved = self.rev_parse(commit)
    out = self._git(["show", "--no-patch", "--format=%P", commit_resolved]).strip()
    return [p for p in out.split() if p]

  def commit_message(self, commit: str) -> str:
    commit_resolved = self.rev_parse(commit)
    return self._git(["show", "--no-patch", "--format=%B", commit_resolved]).strip()

  def changed_files(self, commit: str) -> list[str]:
    commit_resolved = self.rev_parse(commit)
    out = self._git(["diff-tree", "--no-commit-id", "--name-only", "-r", commit_resolved])
    return [t.strip() for t in out.replace("\r\n", "\n").replace("\r", "\n").split("\n") if t.strip()]

  def log_commits_touching_paths(self, paths: list[str], *, max_count: int = 1000) -> list[str]:
    clean = [p for p in paths if p and p.strip()]
    if not clean:
      return []
    args = ["log", "--all", f"--max-count={max_count}", "--format=%H", "--"]
    args.extend(clean)
    out = self._git(args)
    seen: set[str] = set()
    commits: list[str] = []
    for line in out.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
      sha = line.strip()
      if not sha or sha in seen:
        continue
      seen.add(sha)
      commits.append(sha)
    return commits

  def log_commits_matching_message(self, text: str, *, max_count: int = 120) -> list[str]:
    needle = text.strip()
    if not needle:
      return []
    out = self._git([
      "log", "--all", f"--max-count={max_count}", "--format=%H",
      "--fixed-strings", f"--grep={needle}",
    ])
    seen: set[str] = set()
    commits: list[str] = []
    for line in out.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
      sha = line.strip()
      if not sha or sha in seen:
        continue
      seen.add(sha)
      commits.append(sha)
    return commits

  def list_tags_merged_into(
    self,
    commit: str,
    *,
    tags_glob: str | None = None,
    max_tags: int | None = None,
  ) -> list[str]:
    commit_resolved = self.rev_parse(commit)
    args = ["tag", "-l"]
    if tags_glob:
      args.append(tags_glob)
    args.extend(["--sort=-creatordate", "--merged", commit_resolved])
    out = self._git(args)
    tags = [t.strip() for t in out.replace("\r\n", "\n").replace("\r", "\n").split("\n") if t.strip()]
    if max_tags and max_tags > 0:
      return tags[:max_tags]
    return tags

  def show_ref(self, ref_glob: str | None = None, max_refs: int | None = None) -> list[dict[str, str]]:
    args = ["show-ref"]
    if ref_glob:
      args.append(ref_glob)
    out = self._git(args)
    refs: list[dict[str, str]] = []
    for line in out.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
      if not line:
        continue
      parts = line.split()
      if len(parts) != 2:
        continue
      oid, ref = parts
      refs.append({"oid": oid, "ref": ref})
      if max_refs and max_refs > 0 and len(refs) >= max_refs:
        break
    return refs

  def merge_base(self, ref_a: str, ref_b: str) -> str:
    a = self.rev_parse(ref_a)
    b = self.rev_parse(ref_b)
    return self._git(["merge-base", a, b]).strip()

  def is_ancestor(self, older: str, newer: str) -> bool:
    a = self.rev_parse(older)
    b = self.rev_parse(newer)
    try:
      self._git(["merge-base", "--is-ancestor", a, b])
      return True
    except Exception:
      return False

  def rev_list_ancestry_path(
    self,
    older: str,
    newer: str,
    *,
    max_count: int | None = None,
    reverse: bool = False,
  ) -> list[str]:
    older_resolved = self.rev_parse(older)
    newer_resolved = self.rev_parse(newer)
    args = ["rev-list", "--ancestry-path"]
    if reverse:
      args.append("--reverse")
    if max_count and max_count > 0:
      args.append(f"--max-count={max_count}")
    args.append(f"{older_resolved}..{newer_resolved}")
    out = self._git(args)
    return [t.strip() for t in out.replace("\r\n", "\n").replace("\r", "\n").split("\n") if t.strip()]

  def list_remote_branches_containing(self, commit: str) -> list[str]:
    commit_resolved = self.rev_parse(commit)
    out = self._git(["branch", "-r", "--contains", commit_resolved])
    return [t.strip().lstrip("* ").strip() for t in out.replace("\r\n", "\n").replace("\r", "\n").split("\n") if t.strip()]

  def patch_id(self, commit: str) -> str:
    commit_resolved = self.rev_parse(commit)
    # Use a helper process because patch-id consumes stdin.
    return _patch_id_cached(str(self.repo_path), commit_resolved)

  def ls_tree(
    self,
    ref: str,
    path: str | None = None,
    recursive: bool = False,
    max_entries: int | None = None,
  ) -> list[dict[str, str]]:
    ref_resolved = self.rev_parse(ref)
    args = ["ls-tree"]
    if recursive:
      args.append("-r")
    args.append(ref_resolved)
    if path:
      args.extend(["--", path])
    out = self._git(args)
    entries: list[dict[str, str]] = []
    for line in out.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
      if not line:
        continue
      try:
        left, p = line.split("\t", 1)
      except ValueError:
        continue
      parts = left.split()
      if len(parts) != 3:
        continue
      mode, typ, oid = parts
      entries.append({"mode": mode, "type": typ, "object": oid, "path": p})
      if max_entries and max_entries > 0 and len(entries) >= max_entries:
        break
    return entries

  def cat_file(self, obj: str, pretty: bool = False, max_chars: int | None = None) -> dict[str, Any]:
    obj_resolved = self.rev_parse(obj)
    typ = self._git(["cat-file", "-t", obj_resolved]).strip()
    size_str = self._git(["cat-file", "-s", obj_resolved]).strip()
    try:
      size = int(size_str)
    except ValueError:
      size = None
    content: str | None = None
    if pretty:
      raw = self._git(["cat-file", "-p", obj_resolved])
      content = raw[:max_chars] if max_chars and max_chars > 0 else raw
    return {"object_resolved": obj_resolved, "type": typ, "size": size, "content": content}


def normalize_tag(tag: str) -> str:
  return tag.strip()


def _strip_dev_suffix(tag: str) -> str:
  """Remove common development suffixes: -dev, -rc1, -beta, -alpha, etc."""
  import re
  return re.sub(r'-(dev|rc\d*|beta\d*|alpha\d*|pre\d*)$', '', tag, flags=re.IGNORECASE)


def _version_core(tag: str) -> str:
  """Extract version core for fuzzy matching.
  
  Examples:
    n4.3       -> n4.3
    n4.3-dev   -> n4.3
    curl-7_75_0 -> curl-7_75_0
    v1.2.3     -> 1.2.3
  """
  s = _strip_dev_suffix(tag.strip())
  if s.startswith("v") and len(s) > 1 and (s[1].isdigit()):
    s = s[1:]
  return s.lower()


def map_gt_tags_to_repo_tags(
  gt_tags: list[str],
  repo_tags: list[str],
  *,
  mode: str = "strict",
) -> tuple[list[str], list[str]]:
  repo_set = {normalize_tag(t) for t in repo_tags}
  mapped: list[str] = []
  unmapped: list[str] = []

  if mode == "strict":
    for t in gt_tags:
      nt = normalize_tag(t)
      if nt in repo_set:
        mapped.append(nt)
      else:
        unmapped.append(t)
    return mapped, unmapped

  # --- loose mode: multi-strategy matching ---

  # Build index: version_core -> list of repo tags
  core_to_repo: dict[str, list[str]] = {}
  for rt in repo_set:
    core = _version_core(rt)
    core_to_repo.setdefault(core, []).append(rt)

  def _try_match(gt: str) -> str | None:
    nt = normalize_tag(gt)
    # 1) exact match
    if nt in repo_set:
      return nt
    # 2) case-insensitive + v-prefix
    for cand in {nt, nt.lower(), nt.upper()}:
      if cand in repo_set:
        return cand
      if cand.startswith("v") and cand[1:] in repo_set:
        return cand[1:]
      if ("v" + cand) in repo_set:
        return "v" + cand
    # 3) version-core match (handles n4.3 ↔ n4.3-dev)
    gt_core = _version_core(nt)
    candidates = core_to_repo.get(gt_core, [])
    if candidates:
      # prefer exact over -dev; shortest name first
      return sorted(candidates, key=lambda x: (len(x), x))[0]
    # 4) version-number extraction match (safe replacement for fnmatch)
    #    Extract all digit groups from GT tag, match against repo tags with
    #    identical digit groups. This avoids fnmatch's "2.4.2*" matching "2.4.62".
    import re
    gt_nums = tuple(int(x) for x in re.findall(r"\d+", nt))
    if gt_nums:
      for rt in sorted(repo_set, key=lambda x: (len(x), x)):
        rt_nums = tuple(int(x) for x in re.findall(r"\d+", rt))
        if rt_nums == gt_nums:
          return rt
    return None

  for t in gt_tags:
    found = _try_match(t)
    if found is not None:
      mapped.append(found)
    else:
      unmapped.append(t)
  return mapped, unmapped
