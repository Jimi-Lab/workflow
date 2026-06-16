from tests.build_scheduler_failure_corpus import _classify_fn_sources, _primary_reason


def test_primary_reason_uses_first_activation_reason():
  assert _primary_reason(["scout_stride", "positive_neighbor"]) == "scout_stride"
  assert _primary_reason([]) == "unknown"


def test_classify_fn_sources_splits_skipped_and_active_misses():
  lines = {
    "1.0": {
      "tags": ["v1.0.0", "v1.0.1"],
      "visited": False,
      "predicted_affected": [],
      "gt_affected": ["v1.0.0"],
    },
    "1.1": {
      "tags": ["v1.1.0", "v1.1.1"],
      "visited": True,
      "predicted_affected": ["v1.1.0"],
      "gt_affected": ["v1.1.0", "v1.1.1"],
    },
  }

  out = _classify_fn_sources(lines)

  assert out["skipped_affected_line_tags"] == ["v1.0.0"]
  assert out["active_line_missed_tags"] == ["v1.1.1"]
  assert out["source_counts"] == {
    "skipped_affected_line": 1,
    "active_line_missed_asbs_or_sparse": 1,
  }

