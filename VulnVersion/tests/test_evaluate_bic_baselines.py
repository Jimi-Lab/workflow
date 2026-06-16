import importlib.util
import json
import os
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_bic_baselines.py"


def load_module():
    spec = importlib.util.spec_from_file_location("evaluate_bic_baselines", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def commit(repo: Path, text: str, message: str, date: str | None = None) -> str:
    (repo / "code.c").write_text(text, encoding="utf-8")
    git(repo, "add", "code.c")
    env = os.environ.copy()
    if date:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", message],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )
    return git(repo, "rev-parse", "HEAD")


def test_collect_affected_tags_uses_git_topology_and_release_filter(tmp_path: Path) -> None:
    module = load_module()
    repo = tmp_path / "curl"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Test")
    git(repo, "config", "user.email", "test@example.invalid")

    commit(repo, "safe\n", "initial", "2020-01-01T00:00:00Z")
    git(repo, "tag", "curl-0_9")
    bic = commit(repo, "vulnerable\n", "introduce bug", "2020-01-02T00:00:00Z")
    commit(repo, "vulnerable still\n", "release preparation", "2020-01-03T00:00:00Z")
    git(repo, "tag", "curl-1_0")
    git(repo, "tag", "curl-1_1-rc1")
    legacy_point = git(repo, "rev-parse", "HEAD")
    fic = commit(repo, "fixed\n", "fix bug", "2020-01-04T00:00:00Z")
    commit(repo, "fixed release\n", "release fixed version", "2020-01-05T00:00:00Z")
    git(repo, "tag", "curl-1_1")
    git(repo, "checkout", "-b", "legacy", legacy_point)
    commit(repo, "legacy vulnerable\n", "late legacy release", "2020-01-06T00:00:00Z")
    git(repo, "tag", "curl-2_0")

    result = module.collect_affected_tags(
        repo_path=repo,
        repo_name="curl",
        predicted_bics=[bic],
        fixing_commits=[fic],
    )

    assert result["release_tags"] == ["curl-0_9", "curl-1_0", "curl-1_1", "curl-2_0"]
    assert result["affected_tags"] == ["curl-1_0"]
    assert result["excluded_tag_count"] == 1
    assert result["missing_bics"] == []
    assert result["missing_fics"] == []


def test_compute_metrics_separates_version_f1_from_exact_cve_accuracy() -> None:
    module = load_module()
    cases = [
        {"cve": "CVE-1", "ground_truth": ["v1", "v2"], "predicted": ["v1", "v2"]},
        {"cve": "CVE-2", "ground_truth": ["v1", "v2"], "predicted": ["v1", "v3"]},
    ]

    metrics = module.compute_metrics(cases)

    assert metrics["micro"]["tp"] == 3
    assert metrics["micro"]["fp"] == 1
    assert metrics["micro"]["fn"] == 1
    assert metrics["micro"]["precision"] == 0.75
    assert metrics["micro"]["recall"] == 0.75
    assert metrics["micro"]["f1"] == 0.75
    assert metrics["vulnerability_level_accuracy"] == 0.5
    assert metrics["macro"]["f1"] == 0.75


def test_parsers_normalize_agentic_and_mas_outputs(tmp_path: Path) -> None:
    module = load_module()
    agentic = tmp_path / "agentic.json"
    agentic.write_text(
        json.dumps(
            [
                {
                    "case_id": "curl_deadbeef",
                    "project": "curl",
                    "bfc": "deadbeef",
                    "predicted": "abc123",
                    "confidence": 0.9,
                }
            ]
        ),
        encoding="utf-8",
    )
    mas_root = tmp_path / "mas"
    result_dir = mas_root / "curl" / "deadbeef"
    result_dir.mkdir(parents=True)
    (result_dir / "result.json").write_text(
        json.dumps(
            {
                "cveid": "CVE-1",
                "repo_name": "curl",
                "fix_commit_hashes": ["deadbeef"],
                "predicted_bic": ["abc123", "def456"],
                "llm_calls": 4,
                "llm_tokens": 100,
                "error": "",
            }
        ),
        encoding="utf-8",
    )

    agentic_rows = module.parse_agentic_results(agentic)
    mas_rows = module.parse_mas_results(mas_root)

    assert agentic_rows[("curl", "deadbeef")]["predicted_bics"] == ["abc123"]
    assert mas_rows[("curl", "deadbeef")]["predicted_bics"] == ["abc123", "def456"]
    assert mas_rows[("curl", "deadbeef")]["llm_tokens"] == 100
