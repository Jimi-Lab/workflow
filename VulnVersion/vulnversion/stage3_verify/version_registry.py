from __future__ import annotations

import re
from pathlib import Path
from typing import Any


RC_EXCLUDE = re.compile(r"(rc|beta|alpha|pre|dev|snapshot|candidate)", re.IGNORECASE)
_INTERNAL_EXCLUDE = re.compile(
    r"(backups/|reformat|CLANG|FIPS_TEST|BEN_FIPS|STATE_|LEVITTE_|BEFORE_|AFTER_|master-)",
    re.IGNORECASE,
)


REPO_RELEASE_FILTERS: dict[str, str] = {
    "ImageMagick": r"^\d+\.\d+\.\d+[\.-]\d+$",
    "FFmpeg": r"^(n\d+\.\d+(\.\d+)?|v\d+\.\d+(\.\d+)?|ffmpeg-\d+(\.\d+)*)$",
    "curl": r"^curl-\d+_\d+(?:_\d+)?$",
    "openssl": (
        r"^(OpenSSL_\d+_\d+_\d+\w*"
        r"|openssl-\d+\.\d+\.\d+"
        r"|OpenSSL-fips-\d+_\d+[\w-]*"
        r"|OpenSSL-engine-\d+_\d+_\d+\w*"
        r"|OpenSSL_FIPS_\d+_\d+)$"
    ),
    "wireshark": r"^(v\d+\.\d+\.\d+|wireshark-\d+\.\d+\.\d+|NCP_sync.*)$",
    "httpd": r"^\d+\.\d+\.\d+$",
    "qemu": r"^v\d+\.\d+(?:\.\d+(?:\.\d+)?)?$",
    "openjpeg": r"^(v\d+\.\d+\.\d+|version\.\d+\.\d+(?:\.\d+)?)$",
    "linux": r"^v\d+\.\d+(?:\.\d+)?$",
}


SINGLE_LINE_REPOS = {"curl"}


def infer_repo_name(repo_path: str) -> str:
    try:
        return Path(repo_path).name
    except Exception:
        return ""


def is_release_tag(repo: str, tag: str) -> bool:
    pat = REPO_RELEASE_FILTERS.get(repo)
    if pat is None:
        if RC_EXCLUDE.search(tag) or _INTERNAL_EXCLUDE.search(tag):
            return False
        return bool(re.search(r"(\d+\.)+\d+", tag))

    if re.match(pat, tag) is None:
        return False
    if RC_EXCLUDE.search(tag) or _INTERNAL_EXCLUDE.search(tag):
        return False
    return True


def filter_release_tags(repo: str, tags: list[str]) -> list[str]:
    return [t for t in tags if is_release_tag(repo, t)]


def _letters_value(s: str) -> int:
    if not s:
        return 0
    val = 0
    for ch in s.lower():
        if "a" <= ch <= "z":
            val = val * 26 + (ord(ch) - ord("a") + 1)
    return val


def line_key(repo: str, tag: str) -> str:
    if repo in SINGLE_LINE_REPOS:
        return "main"

    if repo == "ImageMagick":
        m = re.match(r"^(\d+\.\d+)\.", tag)
        return m.group(1) if m else "main"

    if repo == "FFmpeg":
        m = re.match(r"^n(\d+\.\d+)", tag)
        if m:
            return m.group(1)
        m = re.match(r"^v(\d+\.\d+)", tag)
        if m:
            return m.group(1)
        m = re.match(r"^ffmpeg-(\d+\.\d+)", tag)
        if m:
            return m.group(1)
        return "main"

    if repo == "openssl":
        m = re.match(r"^openssl-(\d+\.\d+)", tag)
        if m:
            return m.group(1)
        m = re.match(r"^OpenSSL_(\d+)_(\d+)_(\d+)", tag)
        if m:
            if m.group(1) == "0" and m.group(2) == "9":
                return "0.9"
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
        m = re.match(r"^OpenSSL-fips-(\d+)_(\d+)", tag)
        if m:
            return f"fips-{m.group(1)}.{m.group(2)}"
        m = re.match(r"^OpenSSL-engine-(\d+)_(\d+)_(\d+)", tag)
        if m:
            return f"engine-{m.group(1)}.{m.group(2)}.{m.group(3)}"
        m = re.match(r"^OpenSSL_FIPS_(\d+)_(\d+)", tag)
        if m:
            return f"fips-{m.group(1)}.{m.group(2)}"
        return "main"

    if repo == "wireshark":
        m = re.match(r"^(?:v|wireshark-)(\d+\.\d+)\.", tag)
        return m.group(1) if m else "main"

    if repo == "httpd":
        m = re.match(r"^(\d+\.\d+)\.", tag)
        return m.group(1) if m else "main"

    if repo == "qemu":
        m = re.match(r"^v(\d+\.\d+)", tag)
        return m.group(1) if m else "main"

    if repo == "openjpeg":
        m = re.match(r"^v(\d+\.\d+)\.", tag)
        if m:
            return m.group(1)
        m = re.match(r"^version\.(\d+\.\d+)", tag)
        if m:
            return m.group(1)
        return "main"

    if repo == "linux":
        m = re.match(r"^v(\d+\.\d+)", tag)
        return m.group(1) if m else "main"

    return "main"


def line_family_key(repo: str, line_or_tag: str) -> str:
    """Return the comparable release-line family for a line key or tag.

    Most target repositories use a single comparable release-line family, so
    their default partition is ``<repo>-mainline``.  OpenSSL is different:
    historical FIPS and ENGINE release streams are not ordered relative to the
    mainline 0.9.x/1.x/3.x releases and must not be linked by newer/older edges.
    """

    value = str(line_or_tag or "")
    if repo == "openssl":
        if value.startswith("fips-") or value.startswith("OpenSSL-fips-") or value.startswith("OpenSSL_FIPS_"):
            return "openssl-fips"
        if value.startswith("engine-") or value.startswith("OpenSSL-engine-"):
            return "openssl-engine"
        return "openssl-mainline"
    return f"{repo}-mainline"


def line_partition_key(repo: str, line_or_tag: str) -> str:
    """Compatibility alias for the current family-level partition key."""

    return line_family_key(repo, line_or_tag)


def branch_model(repo: str) -> str:
    return "single" if repo in SINGLE_LINE_REPOS else "multi"


def parse_version(repo: str, tag: str) -> tuple[Any, ...]:
    if repo == "ImageMagick":
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)[\.-](\d+)$", tag)
        if m:
            return tuple(int(x) for x in m.groups())

    if repo == "FFmpeg":
        m = re.match(r"^n(\d+)\.(\d+)(?:\.(\d+))?$", tag)
        if m:
            return (0, int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
        m = re.match(r"^ffmpeg-(\d+)(?:\.(\d+))?(?:\.(\d+))?$", tag)
        if m:
            return (1, int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))
        m = re.match(r"^v(\d+)(?:\.(\d+))?(?:\.(\d+))?$", tag)
        if m:
            return (2, int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))

    if repo == "curl":
        m = re.match(r"^curl-(\d+)_(\d+)(?:_(\d+))?$", tag)
        if m:
            return tuple(int(x or 0) for x in m.groups())

    if repo == "openssl":
        m = re.match(r"^openssl-(\d+)\.(\d+)\.(\d+)$", tag)
        if m:
            return (0, int(m.group(1)), int(m.group(2)), int(m.group(3)), 0)
        m = re.match(r"^OpenSSL_(\d+)_(\d+)_(\d+)([a-z]*)$", tag, re.IGNORECASE)
        if m:
            return (1, int(m.group(1)), int(m.group(2)), int(m.group(3)), _letters_value(m.group(4)))
        m = re.match(r"^OpenSSL-fips-(\d+)_(\d+)(.*)$", tag)
        if m:
            return (2, int(m.group(1)), int(m.group(2)), 0, _letters_value(m.group(3)))

    if repo == "wireshark":
        m = re.match(r"^(?:v|wireshark-)(\d+)\.(\d+)\.(\d+)$", tag)
        if m:
            return tuple(int(x) for x in m.groups())

    if repo == "httpd":
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", tag)
        if m:
            return tuple(int(x) for x in m.groups())

    if repo == "qemu":
        m = re.match(r"^v(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?$", tag)
        if m:
            return tuple(int(x or 0) for x in m.groups())

    if repo == "openjpeg":
        m = re.match(r"^v(\d+)\.(\d+)\.(\d+)$", tag)
        if m:
            return (0, int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = re.match(r"^version\.(\d+)\.(\d+)(?:\.(\d+))?$", tag)
        if m:
            return (1, int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))

    if repo == "linux":
        m = re.match(r"^v(\d+)\.(\d+)(?:\.(\d+))?$", tag)
        if m:
            return tuple(int(x or 0) for x in m.groups())

    nums = [int(x) for x in re.findall(r"\d+", tag)]
    return tuple(nums) if nums else (tag,)


def sort_tags_for_line(repo: str, tags: list[str], *, reverse: bool = False) -> list[str]:
    return sorted(tags, key=lambda t: parse_version(repo, t), reverse=reverse)


def branch_key(repo: str, tag: str) -> str:
    return line_key(repo, tag)
