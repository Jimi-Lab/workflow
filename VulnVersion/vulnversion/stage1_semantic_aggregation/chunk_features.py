from __future__ import annotations

import hashlib
import re

from vulnversion.stage1_semantic_aggregation.schema import EvidenceRef, PatchType


_GUARD_RE = re.compile(
  r"\b(if|return|goto|break|continue|assert|av_assert|BUG_ON|WARN_ON)\b|"
  r"(<|>|<=|>=|==|!=)\s*0|"
  r"\b(check|valid|invalid|error|fail|overflow|bounds?|length|size|null)\b",
  re.IGNORECASE,
)
_DANGEROUS_RE = re.compile(
  r"\b(memcpy|memmove|memset|strcpy|strncpy|sprintf|snprintf|malloc|free|realloc|"
  r"copy_from_user|copy_to_user|read|write|parse|decode|encode)\b|"
  r"\[[^\]]+\]|\b\w+->\w+\b",
  re.IGNORECASE,
)
_DECLARATION_RE = re.compile(
  r"^\s*(?:const\s+)?(?:static\s+)?(?:unsigned\s+|signed\s+)?"
  r"(?:char|short|int|long|size_t|ssize_t|bool|void|struct\s+\w+|enum\s+\w+|[A-Za-z_]\w*_t)\s+\*?\w+\s*(?:=|;|,)",
  re.IGNORECASE,
)
_SECURITY_MESSAGE_RE = re.compile(r"\b(CVE|security|vulnerab|overflow|bounds?|oob|crash|fix)\b", re.IGNORECASE)


def classify_patch_type(*, added: list[str], removed: list[str]) -> PatchType:
  has_added = any(x.strip() for x in added)
  has_removed = any(x.strip() for x in removed)
  if has_added and has_removed:
    return "mixed"
  if has_added:
    return "add_only"
  if has_removed:
    return "del_only"
  return "empty_or_merge"


def guard_candidates(lines: list[str]) -> list[str]:
  return [line for line in lines if _GUARD_RE.search(line)]


def dangerous_candidates(lines: list[str]) -> list[str]:
  return [line for line in lines if _DANGEROUS_RE.search(line) and not _DECLARATION_RE.search(line)]


def message_signals(subject: str) -> list[str]:
  signals: list[str] = []
  if _SECURITY_MESSAGE_RE.search(subject):
    signals.append("security_keyword_in_message")
  return signals


def source_ref(
  *,
  cve_id: str,
  commit: str,
  file_path: str,
  kind: str,
  index: int,
  snippet: str,
  change_type: str | None = None,
  hunk_header: str | None = None,
  function_context: str | None = None,
  old_line_no: int | None = None,
  new_line_no: int | None = None,
  strength_hint: str = "medium",
) -> EvidenceRef:
  digest = hashlib.sha256(snippet.encode("utf-8")).hexdigest()
  return EvidenceRef(
    ref_id=f"src:{cve_id}:{commit}:{file_path}:{kind}:{index}",
    kind="git_diff",
    change_type=change_type,  # type: ignore[arg-type]
    commit=commit,
    file_path=file_path,
    function_context=function_context,
    hunk_header=hunk_header,
    old_line_no=old_line_no,
    new_line_no=new_line_no,
    snippet=snippet,
    snippet_hash=f"sha256:{digest}",
    strength_hint=strength_hint,  # type: ignore[arg-type]
  )
