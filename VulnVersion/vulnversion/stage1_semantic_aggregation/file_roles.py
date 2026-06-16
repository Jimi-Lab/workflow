from __future__ import annotations

from pathlib import PurePosixPath

from vulnversion.stage1_semantic_aggregation.schema import FileRole


SOURCE_EXTENSIONS = {
  ".c",
  ".cc",
  ".cpp",
  ".cxx",
  ".h",
  ".hh",
  ".hpp",
  ".hxx",
}


def classify_file_role(path: str) -> FileRole:
  normalized = path.replace("\\", "/").lower()
  parts = set(PurePosixPath(normalized).parts)
  name = PurePosixPath(normalized).name
  suffix = PurePosixPath(normalized).suffix

  if parts & {"test", "tests", "fuzz", "fuzzer"} or name.endswith(("_test.c", "_test.cc", "_test.cpp")):
    return "test"
  if parts & {"doc", "docs", "documentation"} or suffix in {".md", ".rst", ".txt"}:
    return "doc"
  if name in {"makefile", "cmakelists.txt"} or parts & {".github", ".gitlab", "ci"}:
    return "build"
  if "generated" in parts or name.endswith((".pb.c", ".pb.h")):
    return "generated"
  if suffix in SOURCE_EXTENSIONS:
    return "source"
  return "unknown"
