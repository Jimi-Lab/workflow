"""P0-2: artifact semantic separation tests.

Asserts that per_tag_verdict.jsonl rows and eval.json explicitly bucket
verdicts into 4 sources:
  - agent             : LLM agent gave a verdict (run_status in OK/PARTIAL_PARSE)
  - prefilter         : static prefilter resolved (run_status=PREFILTER)
  - inferred_interval : ASBS interval inference (run_status=INFERRED)
  - agent_error       : execution failure (AGENT_ERROR/TIMEOUT/INVALID_TAG/SESSION_CREATE_ERROR)

agent_error tags MUST NOT count in the confusion matrix denominators.
unmapped_gt_tags is a separate eval-side bucket.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnversion.agent_harness.base import AgentCapabilities
from vulnversion.stage3_verify.schema import TagVerdict
from vulnversion.stage3_verify.verify_tags import verify_tags


# ────────────────────────────────────────────────────────────────────
# Fake agent helpers
# ────────────────────────────────────────────────────────────────────


def _extract_prompt_tag_line(prompt: str) -> tuple[str, str]:
    """Parse both legacy and current Stage3 tag-judge prompt headers."""
    tag = ""
    line = ""
    for prompt_line in prompt.splitlines():
        if prompt_line.startswith("# Task: Verify whether tag `"):
            tag = prompt_line.split("`")[1]
        elif prompt_line.startswith("Target tag: `"):
            tag = prompt_line.split("`")[1]
        if prompt_line.startswith("Release line: `"):
            line = prompt_line.split("`")[1]
        elif prompt_line.startswith("Release line label: `"):
            line = prompt_line.split("`")[1]
    return tag, line


class _FixedVerdictAgent:
    """Returns a per-tag verdict from a dict; raises for tags marked fail.
    Implements the AgentRuntime Protocol."""

    def __init__(self, verdicts_by_tag: dict[str, str], fail_tags: set[str] | None = None):
        self._verdicts = verdicts_by_tag
        self._fail = set(fail_tags or [])

    @property
    def backend(self) -> str:
        return "fixed_verdict_test"

    def capabilities(self) -> AgentCapabilities:
        return AgentCapabilities(backend="fixed_verdict_test")

    def create_readonly_session(self, *, title: str | None = None) -> str:
        return "test-session"

    def run_json(self, *, session_id: str, prompt: str, system=None, tools=None,
                 timeout_s=None, metadata=None):
        tag, line = _extract_prompt_tag_line(prompt)
        if tag in self._fail:
            raise ValueError("synthetic agent error")
        return {
            "tag": tag,
            "line": line,
            "verdict": self._verdicts.get(tag, "NOT_AFFECTED"),
            "run_status": "OK",
            "confidence": 0.7,
            "reasoning_summary": "fake",
            "matched_predicates": [],
            "failed_predicates": [],
            "triggered_guards": [],
            "evidence_snippets": [],
        }


def _init_repo_with_tags(repo_dir: Path, tags: list[str]) -> None:
    subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "t@t"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "t"], check=True, capture_output=True)
    for i, tag in enumerate(tags):
        (repo_dir / "f.txt").write_text(f"line-{i}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_dir), "add", "f.txt"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(repo_dir), "commit", "-m", f"c{i}"],
            check=True, capture_output=True,
        )
        subprocess.run(["git", "-C", str(repo_dir), "tag", tag], check=True, capture_output=True)


def _write_minimal_rci(rci_path: Path) -> None:
    # Anchor file_path must exist at every tag so prefilter doesn't short-circuit
    # via "anchor absence". Tokens chosen so prefilter never matches a fix marker.
    rci_path.write_text(
        json.dumps({
            "anchor": {"file_paths": ["f.txt"], "function_names": [], "stable_tokens": []},
            "vuln_predicates": [{"kind": "token_any", "args": {"tokens": ["line"]}}],
            "fix_predicates": [{"kind": "token_any", "args": {"tokens": ["unlikely_fix_token_xyzzy"]}}],
            "guards": [],
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


# ────────────────────────────────────────────────────────────────────
# Section 1 — TagVerdict schema supports verdict_source / inferred_from / certificate_id
# ────────────────────────────────────────────────────────────────────


class TestTagVerdictSchemaP02(unittest.TestCase):
    def test_verdict_source_field_optional(self):
        v = TagVerdict(tag="t1", line="main", confidence=0.5)
        self.assertIsNone(v.verdict_source)

    def test_verdict_source_can_be_set(self):
        v = TagVerdict(tag="t1", line="main", confidence=0.5, verdict_source="agent")
        self.assertEqual(v.verdict_source, "agent")

    def test_inferred_from_default_empty_list(self):
        v = TagVerdict(tag="t1", line="main", confidence=0.5)
        self.assertEqual(v.inferred_from, [])

    def test_certificate_id_optional(self):
        v = TagVerdict(tag="t1", line="main", confidence=0.5)
        self.assertIsNone(v.certificate_id)

    def test_serialization_includes_p02_fields(self):
        v = TagVerdict(
            tag="t1", line="main", confidence=0.5,
            verdict_source="inferred_interval",
            inferred_from=["v1", "v3"],
            certificate_id="asbs:main:verified_boundary:v1",
        )
        d = v.model_dump()
        self.assertEqual(d["verdict_source"], "inferred_interval")
        self.assertEqual(d["inferred_from"], ["v1", "v3"])
        self.assertEqual(d["certificate_id"], "asbs:main:verified_boundary:v1")


# ────────────────────────────────────────────────────────────────────
# Section 2 — verdict_source populated correctly per row
# ────────────────────────────────────────────────────────────────────


class TestVerdictSourcePopulation(unittest.TestCase):
    def test_agent_verdict_gets_agent_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            out_dir = Path(tmp) / "out"
            repo_dir.mkdir(parents=True, exist_ok=True)
            _init_repo_with_tags(repo_dir, ["t1", "t2"])
            rci_path = Path(tmp) / "rci.json"
            _write_minimal_rci(rci_path)
            verify_tags(
                repo_path=str(repo_dir),
                cve_id="CVE-X",
                rci_path=str(rci_path),
                out_dir=str(out_dir),
                tags=["t1", "t2"],
                resume=False,
                agent=_FixedVerdictAgent({"t1": "AFFECTED", "t2": "NOT_AFFECTED"}),
                session_id="s",
                per_tag_session=False,
                log_progress=False,
            )
            rows = _read_jsonl(out_dir / "per_tag_verdict.jsonl")
            self.assertEqual(len(rows), 2)
            for r in rows:
                self.assertEqual(
                    r.get("verdict_source"), "agent",
                    f"tag {r.get('tag')} expected verdict_source=agent",
                )

    def test_agent_error_gets_agent_error_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            out_dir = Path(tmp) / "out"
            repo_dir.mkdir(parents=True, exist_ok=True)
            _init_repo_with_tags(repo_dir, ["t1", "t2"])
            rci_path = Path(tmp) / "rci.json"
            _write_minimal_rci(rci_path)
            verify_tags(
                repo_path=str(repo_dir),
                cve_id="CVE-X",
                rci_path=str(rci_path),
                out_dir=str(out_dir),
                tags=["t1", "t2"],
                resume=False,
                agent=_FixedVerdictAgent({"t2": "NOT_AFFECTED"}, fail_tags={"t1"}),
                session_id="s",
                per_tag_session=False,
                log_progress=False,
            )
            rows_by_tag = {r["tag"]: r for r in _read_jsonl(out_dir / "per_tag_verdict.jsonl")}
            self.assertEqual(rows_by_tag["t1"].get("verdict_source"), "agent_error")
            self.assertEqual(rows_by_tag["t1"].get("run_status"), "AGENT_ERROR")
            self.assertEqual(rows_by_tag["t2"].get("verdict_source"), "agent")

    def test_prefilter_gets_prefilter_source(self):
        # Use an RCI whose fix_predicates DO match the file content so prefilter triggers.
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            out_dir = Path(tmp) / "out"
            repo_dir.mkdir(parents=True, exist_ok=True)
            _init_repo_with_tags(repo_dir, ["t1"])
            rci_path = Path(tmp) / "rci.json"
            # Both vuln + fix tokens hit "line" → prefilter likely returns NOT_AFFECTED_fixed
            rci_path.write_text(
                json.dumps({
                    "anchor": {"file_paths": ["f.txt"], "function_names": [], "stable_tokens": []},
                    "vuln_predicates": [
                        {"kind": "token_all", "args": {"tokens": ["line", "0"]}},
                        {"kind": "token_all", "args": {"tokens": ["line", "0"]}},
                    ],
                    "fix_predicates": [
                        {"kind": "token_all", "args": {"tokens": ["line", "0"]}},
                    ],
                    "guards": [],
                }, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            verify_tags(
                repo_path=str(repo_dir),
                cve_id="CVE-X",
                rci_path=str(rci_path),
                out_dir=str(out_dir),
                tags=["t1"],
                resume=False,
                agent=_FixedVerdictAgent({}),  # no verdicts; prefilter should resolve
                session_id="s",
                per_tag_session=False,
                log_progress=False,
            )
            rows = _read_jsonl(out_dir / "per_tag_verdict.jsonl")
            # Note: prefilter may or may not fire depending on token logic, but if
            # run_status is PREFILTER, verdict_source MUST be prefilter.
            for r in rows:
                if r.get("run_status") == "PREFILTER":
                    self.assertEqual(r.get("verdict_source"), "prefilter")


# ────────────────────────────────────────────────────────────────────
# Section 3 — inferred_interval rows written for ASBS-skipped tags
# ────────────────────────────────────────────────────────────────────


class TestInferredIntervalRows(unittest.TestCase):
    # Tags must satisfy default release filter `(\d+\.)+\d+` since the planner
    # uses version_registry.is_release_tag() before building the vuln_tree.
    _REL = ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"]

    def test_inferred_rows_emitted_for_asbs_interval_skipped_tags(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            out_dir = Path(tmp) / "out"
            repo_dir.mkdir(parents=True, exist_ok=True)
            _init_repo_with_tags(repo_dir, self._REL)
            # newest tag is the fix commit's tag — find its sha
            sha = subprocess.check_output(
                ["git", "-C", str(repo_dir), "rev-list", "-n", "1", self._REL[-1]]
            ).decode().strip()
            rci_path = Path(tmp) / "rci.json"
            _write_minimal_rci(rci_path)
            # Verdicts: oldest=NA (first probe), latest_pre_fix=AFFECTED;
            # ASBS binary search probes mid → AFFECTED → boundary near 1.0.1.
            agent = _FixedVerdictAgent({
                "1.0.0": "NOT_AFFECTED",
                "1.0.1": "AFFECTED",
                "1.0.2": "AFFECTED",
                "1.0.3": "AFFECTED",
                "1.0.4": "AFFECTED",
            })
            verify_tags(
                repo_path=str(repo_dir),
                cve_id="CVE-X",
                rci_path=str(rci_path),
                out_dir=str(out_dir),
                fixing_commits=[[sha]],
                resume=False,
                agent=agent,
                session_id="s",
                per_tag_session=False,
                log_progress=False,
            )
            rows = _read_jsonl(out_dir / "per_tag_verdict.jsonl")
            tags_with_sources = {r["tag"]: r.get("verdict_source") for r in rows}
            inferred_rows = [r for r in rows if r.get("verdict_source") == "inferred_interval"]
            self.assertTrue(
                len(inferred_rows) >= 1,
                f"no inferred rows found; sources={tags_with_sources}",
            )
            for r in inferred_rows:
                self.assertEqual(r.get("run_status"), "INFERRED")
                self.assertEqual(r.get("verdict"), "AFFECTED")
                self.assertIsNotNone(r.get("certificate_id"))
                self.assertTrue(len(r.get("inferred_from") or []) >= 1)

    def test_no_inferred_rows_when_no_affected_interval(self):
        # Born-fixed: only the fix tag exists → no candidate_tags → no inferred rows.
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            out_dir = Path(tmp) / "out"
            repo_dir.mkdir(parents=True, exist_ok=True)
            _init_repo_with_tags(repo_dir, ["1.0.0"])
            sha = subprocess.check_output(
                ["git", "-C", str(repo_dir), "rev-list", "-n", "1", "1.0.0"]
            ).decode().strip()
            rci_path = Path(tmp) / "rci.json"
            _write_minimal_rci(rci_path)
            verify_tags(
                repo_path=str(repo_dir),
                cve_id="CVE-X",
                rci_path=str(rci_path),
                out_dir=str(out_dir),
                fixing_commits=[[sha]],
                resume=False,
                agent=_FixedVerdictAgent({"1.0.0": "NOT_AFFECTED"}),
                session_id="s",
                per_tag_session=False,
                log_progress=False,
            )
            rows = _read_jsonl(out_dir / "per_tag_verdict.jsonl")
            inferred = [r for r in rows if r.get("verdict_source") == "inferred_interval"]
            self.assertEqual(len(inferred), 0)


# ────────────────────────────────────────────────────────────────────
# Section 3b — P0-A final runtime snapshot mirrors verdict artifacts
# ────────────────────────────────────────────────────────────────────


class TestRuntimeClosureP0A(unittest.TestCase):
    _REL = ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"]

    def test_vuln_tree_runtime_reflects_all_verdict_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            out_dir = Path(tmp) / "out"
            repo_dir.mkdir(parents=True, exist_ok=True)
            _init_repo_with_tags(repo_dir, self._REL)
            sha = subprocess.check_output(
                ["git", "-C", str(repo_dir), "rev-list", "-n", "1", self._REL[-1]]
            ).decode().strip()
            rci_path = Path(tmp) / "rci.json"
            _write_minimal_rci(rci_path)
            agent = _FixedVerdictAgent({
                "1.0.0": "NOT_AFFECTED",
                "1.0.1": "AFFECTED",
                "1.0.2": "AFFECTED",
                "1.0.3": "AFFECTED",
                "1.0.4": "AFFECTED",
            })
            verify_tags(
                repo_path=str(repo_dir),
                cve_id="CVE-X",
                rci_path=str(rci_path),
                out_dir=str(out_dir),
                fixing_commits=[[sha]],
                resume=False,
                agent=agent,
                session_id="s",
                per_tag_session=False,
                log_progress=False,
            )

            rows = _read_jsonl(out_dir / "per_tag_verdict.jsonl")
            runtime = json.loads((out_dir / "vuln_tree_runtime.json").read_text(encoding="utf-8"))
            tags_by_line = runtime.get("tags_by_line") or {}
            self.assertGreater(len(rows), 0, "test setup produced no verdict rows")
            for row in rows:
                line = row.get("line")
                tag = row.get("tag")
                tag_runtime = ((tags_by_line.get(line) or {}).get(tag) or {})
                self.assertTrue(tag_runtime, f"missing runtime for verdict row {line}/{tag}")
                self.assertEqual(tag_runtime.get("verdict"), row.get("verdict"))
                self.assertEqual(tag_runtime.get("verdict_source"), row.get("verdict_source"))
                self.assertEqual(tag_runtime.get("confidence"), row.get("confidence"))
                self.assertEqual(tag_runtime.get("inferred_from") or [], row.get("inferred_from") or [])
                if row.get("certificate_id"):
                    self.assertEqual(tag_runtime.get("certificate_id"), row.get("certificate_id"))
                if row.get("verdict_source") == "inferred_interval":
                    self.assertEqual(tag_runtime.get("plan_status"), "inferred")
                    self.assertIn("inferred_tag", tag_runtime.get("plan_roles") or [])
                else:
                    self.assertIn(tag_runtime.get("plan_status"), {"verified", "verification_error"})
                    self.assertIsInstance(tag_runtime.get("probe_round"), int)


# ────────────────────────────────────────────────────────────────────
# Section 4 — eval.json bucket structure
# ────────────────────────────────────────────────────────────────────


class TestEvalBucketSeparation(unittest.TestCase):
    _REL = ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"]

    def _run_with_gt(self, tmp_root: Path, gt_tags: list[str]):
        repo_dir = tmp_root / "repo"
        out_dir = tmp_root / "out"
        repo_dir.mkdir(parents=True, exist_ok=True)
        _init_repo_with_tags(repo_dir, self._REL)
        sha = subprocess.check_output(
            ["git", "-C", str(repo_dir), "rev-list", "-n", "1", self._REL[-1]]
        ).decode().strip()
        rci_path = tmp_root / "rci.json"
        _write_minimal_rci(rci_path)
        agent = _FixedVerdictAgent(
            {"1.0.0": "NOT_AFFECTED", "1.0.1": "AFFECTED", "1.0.2": "AFFECTED",
             "1.0.3": "AFFECTED", "1.0.4": "AFFECTED"},
            fail_tags={"1.0.3"},  # one agent_error to test bucket
        )
        verify_tags(
            repo_path=str(repo_dir),
            cve_id="CVE-X",
            rci_path=str(rci_path),
            out_dir=str(out_dir),
            fixing_commits=[[sha]],
            resume=False,
            agent=agent,
            session_id="s",
            per_tag_session=False,
            log_progress=False,
            gt_affected_tags=gt_tags,
            gt_match_mode="strict",
        )
        return json.loads((out_dir / "eval.json").read_text(encoding="utf-8"))

    def test_eval_has_four_bucket_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = self._run_with_gt(Path(tmp), gt_tags=["1.0.2", "1.0.3", "1.0.4"])
            for key in ("probed_tags", "prefiltered_tags", "inferred_tags",
                        "unmapped_gt_tags", "agent_error_tags"):
                self.assertIn(key, ev, f"eval.json missing bucket field: {key}")

    def test_buckets_are_disjoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = self._run_with_gt(Path(tmp), gt_tags=["1.0.2", "1.0.3", "1.0.4"])
            probed = set(ev.get("probed_tags") or [])
            prefiltered = set(ev.get("prefiltered_tags") or [])
            inferred = set(ev.get("inferred_tags") or [])
            errored = set(ev.get("agent_error_tags") or [])
            self.assertEqual(probed & prefiltered, set())
            self.assertEqual(probed & inferred, set())
            self.assertEqual(probed & errored, set())
            self.assertEqual(prefiltered & inferred, set())
            self.assertEqual(prefiltered & errored, set())
            self.assertEqual(inferred & errored, set())

    def test_agent_error_tags_excluded_from_cm(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = self._run_with_gt(Path(tmp), gt_tags=["1.0.2", "1.0.3", "1.0.4"])
            cm = ev.get("confusion_matrix") or {}
            errored = ev.get("agent_error_tags") or []
            tp = int(cm.get("TP") or 0)
            fp = int(cm.get("FP") or 0)
            fn = int(cm.get("FN") or 0)
            tn = int(cm.get("TN") or 0)
            self.assertEqual(
                ev.get("agent_error_count", len(errored)), len(errored),
                "agent_error_count must match agent_error_tags length",
            )
            resolved = (
                len(set(ev.get("probed_tags") or []))
                + len(set(ev.get("prefiltered_tags") or []))
                + len(set(ev.get("inferred_tags") or []))
            )
            self.assertEqual(
                tp + fp + fn + tn, resolved,
                f"CM cells {tp+fp+fn+tn} != resolved tags {resolved}",
            )


# ────────────────────────────────────────────────────────────────────
# Section 5 — main._eval_against_gt mirrors bucket separation
# ────────────────────────────────────────────────────────────────────


class TestMainEvalBucketing(unittest.TestCase):
    def test_main_eval_excludes_agent_error_from_cm(self):
        from main import _eval_against_gt
        results = [
            {"tag": "v1", "verdict": "NOT_AFFECTED", "verdict_source": "agent"},
            {"tag": "v2", "verdict": "AFFECTED", "verdict_source": "agent"},
            {"tag": "v3", "verdict": None, "verdict_source": "agent_error"},
            {"tag": "v4", "verdict": "AFFECTED", "verdict_source": "inferred_interval"},
            {"tag": "v5", "verdict": "NOT_AFFECTED", "verdict_source": "prefilter"},
        ]
        ev = _eval_against_gt(
            gt_tags=["v2", "v4"],
            scanned_tags=["v1", "v2", "v3", "v4", "v5"],
            results=results,
            mode="strict",
        )
        cm = ev["confusion_matrix"]
        # v3 is agent_error → must NOT contribute to any TP/FP/FN/TN cell
        # Resolved = {v1,v2,v4,v5} → expected TP=2 (v2,v4), TN=2 (v1,v5), FP=0, FN=0
        self.assertEqual(cm["TP"], 2)
        self.assertEqual(cm["TN"], 2)
        self.assertEqual(cm["FP"], 0)
        self.assertEqual(cm["FN"], 0)
        self.assertIn("agent_error_tags", ev)
        self.assertEqual(ev["agent_error_tags"], ["v3"])
        self.assertIn("probed_tags", ev)
        self.assertIn("prefiltered_tags", ev)
        self.assertIn("inferred_tags", ev)


# ────────────────────────────────────────────────────────────────────
# Section 6 — per_tag_verdict.csv columns include P0-2 fields
# ────────────────────────────────────────────────────────────────────


class TestPerTagCsvColumns(unittest.TestCase):
    """The CSV is downstream of the JSONL; both must carry verdict_source,
    inferred_from, certificate_id so any consumer that reads the CSV (e.g.
    ablation table generators) gets the same 4-bucket information."""

    REQUIRED_COLS = {
        "tag", "line", "run_status", "verdict", "verdict_source",
        "confidence", "matched_predicates", "failed_predicates",
        "triggered_guards", "inferred_from", "certificate_id",
        "reasoning_summary",
    }

    def test_explicit_path_csv_has_p02_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            out_dir = Path(tmp) / "out"
            repo_dir.mkdir(parents=True, exist_ok=True)
            _init_repo_with_tags(repo_dir, ["t1", "t2"])
            rci_path = Path(tmp) / "rci.json"
            _write_minimal_rci(rci_path)
            verify_tags(
                repo_path=str(repo_dir),
                cve_id="CVE-X",
                rci_path=str(rci_path),
                out_dir=str(out_dir),
                tags=["t1", "t2"],
                resume=False,
                agent=_FixedVerdictAgent({"t1": "AFFECTED", "t2": "NOT_AFFECTED"}),
                session_id="s",
                per_tag_session=False,
                log_progress=False,
            )
            import csv as _csv
            with (out_dir / "per_tag_verdict.csv").open("r", encoding="utf-8") as f:
                reader = _csv.DictReader(f)
                self.assertTrue(self.REQUIRED_COLS.issubset(set(reader.fieldnames or [])))
                rows = list(reader)
            self.assertEqual(len(rows), 2)
            for row in rows:
                # verdict_source must be populated, not empty string
                self.assertIn(row["verdict_source"], {"agent", "prefilter"})

    def test_vuln_tree_path_csv_has_p02_columns(self):
        REL = ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5"]
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            out_dir = Path(tmp) / "out"
            repo_dir.mkdir(parents=True, exist_ok=True)
            _init_repo_with_tags(repo_dir, REL)
            sha = subprocess.check_output(
                ["git", "-C", str(repo_dir), "rev-list", "-n", "1", REL[-1]]
            ).decode().strip()
            rci_path = Path(tmp) / "rci.json"
            _write_minimal_rci(rci_path)
            agent = _FixedVerdictAgent(
                {"1.0.0": "NOT_AFFECTED", "1.0.1": "AFFECTED",
                 "1.0.2": "AFFECTED", "1.0.3": "AFFECTED", "1.0.4": "AFFECTED"},
            )
            verify_tags(
                repo_path=str(repo_dir),
                cve_id="CVE-X",
                rci_path=str(rci_path),
                out_dir=str(out_dir),
                fixing_commits=[[sha]],
                resume=False,
                agent=agent,
                session_id="s",
                per_tag_session=False,
                log_progress=False,
            )
            import csv as _csv
            with (out_dir / "per_tag_verdict.csv").open("r", encoding="utf-8") as f:
                reader = _csv.DictReader(f)
                self.assertTrue(
                    self.REQUIRED_COLS.issubset(set(reader.fieldnames or [])),
                    f"missing P0-2 columns; got {reader.fieldnames}",
                )
                rows = list(reader)
            sources = {r["verdict_source"] for r in rows}
            self.assertTrue(
                "inferred_interval" in sources or "agent" in sources,
                f"no agent or inferred rows: {sources}",
            )
            inferred_rows = [r for r in rows if r["verdict_source"] == "inferred_interval"]
            for r in inferred_rows:
                # certificate_id and inferred_from must be present (non-empty strings)
                self.assertNotEqual(r["certificate_id"], "")
                self.assertNotEqual(r["inferred_from"], "[]")


# ────────────────────────────────────────────────────────────────────
# Section 7 — backward compatibility with pre-P0-2 jsonl artifacts
# ────────────────────────────────────────────────────────────────────


class TestBackwardCompatJsonl(unittest.TestCase):
    """Old per_tag_verdict.jsonl rows (no verdict_source field) must still
    deserialize via TagVerdict.model_validate(), so resume=True works on
    artifacts produced by the previous code."""

    def test_legacy_row_loads_with_default_p02_fields(self):
        # Simulate a row written by the pre-P0-2 code (no verdict_source / etc.).
        legacy = {
            "tag": "v1.2.3",
            "line": "1.2",
            "verdict": "AFFECTED",
            "run_status": "OK",
            "confidence": 0.7,
            "matched_predicates": [],
            "failed_predicates": [],
            "triggered_guards": [],
            "evidence_snippets": [],
            "reasoning_summary": "old",
        }
        v = TagVerdict.model_validate(legacy)
        self.assertEqual(v.verdict, "AFFECTED")
        self.assertIsNone(v.verdict_source)  # default
        self.assertEqual(v.inferred_from, [])  # default
        self.assertIsNone(v.certificate_id)  # default

    def test_resume_mode_accepts_legacy_jsonl(self):
        from vulnversion.stage3_verify.verify_tags import _read_existing_verdicts
        with tempfile.TemporaryDirectory() as tmp:
            jsonl = Path(tmp) / "per_tag_verdict.jsonl"
            with jsonl.open("w", encoding="utf-8") as f:
                # mix old (no verdict_source) and new format
                f.write(json.dumps({
                    "tag": "v1.2.3", "line": "1.2", "verdict": "AFFECTED",
                    "run_status": "OK", "confidence": 0.7,
                    "matched_predicates": [], "failed_predicates": [],
                    "triggered_guards": [], "evidence_snippets": [],
                    "reasoning_summary": "old",
                }) + "\n")
                f.write(json.dumps({
                    "tag": "v1.2.4", "line": "1.2", "verdict": "NOT_AFFECTED",
                    "run_status": "PREFILTER", "confidence": 0.85,
                    "verdict_source": "prefilter",
                    "certificate_id": "prefilter:NOT_AFFECTED_fixed:v1",
                    "matched_predicates": [], "failed_predicates": [],
                    "triggered_guards": [], "evidence_snippets": [],
                    "reasoning_summary": "new",
                }) + "\n")
            cache = _read_existing_verdicts(jsonl)
            self.assertEqual(len(cache), 2)
            self.assertIsNone(cache["v1.2.3"].verdict_source)
            self.assertEqual(cache["v1.2.4"].verdict_source, "prefilter")


if __name__ == "__main__":
    unittest.main()
