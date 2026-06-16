import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "setup_baseline_repos_ubuntu.sh"


def bash_path(path: Path) -> str:
    if os.name != "nt":
        return str(path)
    result = run("cygpath", "-u", str(path))
    return result.stdout.strip()


def run(*args: str, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [*args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


@pytest.fixture()
def git_fixture(tmp_path: Path) -> dict[str, Path | str]:
    if shutil.which("bash") is None or shutil.which("git") is None:
        pytest.skip("bash and git are required")

    source = tmp_path / "source"
    remote = tmp_path / "demo.git"
    source.mkdir()
    run("git", "init", "-b", "main", cwd=source)
    run("git", "config", "user.name", "Baseline Test", cwd=source)
    run("git", "config", "user.email", "baseline@example.test", cwd=source)

    (source / "README.md").write_text("initial\n", encoding="utf-8")
    run("git", "add", "README.md", cwd=source)
    run("git", "commit", "-m", "initial", cwd=source)
    run("git", "tag", "v1.0", cwd=source)

    (source / "README.md").write_text("fixed\n", encoding="utf-8")
    run("git", "commit", "-am", "fix vulnerability", cwd=source)
    fix = run("git", "rev-parse", "HEAD", cwd=source).stdout.strip()
    run("git", "clone", "--bare", str(source), str(remote))

    dataset = tmp_path / "BaseDataOrder.json"
    dataset.write_text(
        json.dumps(
            {
                "CVE-TEST-0001": {
                    "affected_version": ["v1.0"],
                    "fixing_commits": [[fix]],
                    "repo": "demo",
                    "CWE": ["CWE-TEST"],
                }
            }
        ),
        encoding="utf-8",
    )

    return {
        "tmp": tmp_path,
        "remote": remote,
        "dataset": dataset,
        "fix": fix,
    }


def write_spec(path: Path, canonical: str, fallback: str = "") -> None:
    path.write_text(
        "# name<TAB>canonical<TAB>fallback<TAB>required_paths\n"
        f"demo\t{canonical}\t{fallback}\tREADME.md\n",
        encoding="utf-8",
    )


def test_clones_fallback_and_validates_dataset_commits(git_fixture: dict[str, Path | str]) -> None:
    tmp = Path(git_fixture["tmp"])
    remote = Path(git_fixture["remote"])
    spec = tmp / "repos.tsv"
    repo_root = tmp / "repos"
    report = tmp / "audit.json"
    write_spec(spec, bash_path(tmp / "missing.git"), bash_path(remote))

    result = run(
        "bash",
        bash_path(SCRIPT),
        "--spec-file",
        bash_path(spec),
        "--dataset",
        bash_path(Path(git_fixture["dataset"])),
        "--repo-root",
        bash_path(repo_root),
        "--report",
        bash_path(report),
        "--repos",
        "all",
    )

    audit = json.loads(report.read_text(encoding="utf-8"))
    assert result.returncode == 0
    assert (repo_root / "demo" / ".git").is_dir()
    assert audit["summary"]["failed_repos"] == 0
    assert audit["repositories"][0]["missing_fics"] == []
    assert audit["repositories"][0]["missing_parents"] == []
    assert audit["repositories"][0]["origin"].replace("\\", "/") == remote.as_posix()


def test_missing_fic_fails_verification(git_fixture: dict[str, Path | str]) -> None:
    tmp = Path(git_fixture["tmp"])
    remote = Path(git_fixture["remote"])
    spec = tmp / "repos.tsv"
    repo_root = tmp / "repos"
    report = tmp / "audit.json"
    write_spec(spec, bash_path(remote))

    dataset = json.loads(Path(git_fixture["dataset"]).read_text(encoding="utf-8"))
    dataset["CVE-TEST-0001"]["fixing_commits"] = [["0" * 40]]
    Path(git_fixture["dataset"]).write_text(json.dumps(dataset), encoding="utf-8")

    result = run(
        "bash",
        bash_path(SCRIPT),
        "--spec-file",
        bash_path(spec),
        "--dataset",
        bash_path(Path(git_fixture["dataset"])),
        "--repo-root",
        bash_path(repo_root),
        "--report",
        bash_path(report),
        "--repos",
        "all",
        check=False,
    )

    audit = json.loads(report.read_text(encoding="utf-8"))
    assert result.returncode != 0
    assert audit["summary"]["failed_repos"] == 1
    assert audit["repositories"][0]["missing_fics"] == ["0" * 40]


def test_verify_only_does_not_clone_missing_repository(git_fixture: dict[str, Path | str]) -> None:
    tmp = Path(git_fixture["tmp"])
    remote = Path(git_fixture["remote"])
    spec = tmp / "repos.tsv"
    repo_root = tmp / "repos"
    report = tmp / "audit.json"
    write_spec(spec, bash_path(remote))

    result = run(
        "bash",
        bash_path(SCRIPT),
        "--spec-file",
        bash_path(spec),
        "--dataset",
        bash_path(Path(git_fixture["dataset"])),
        "--repo-root",
        bash_path(repo_root),
        "--report",
        bash_path(report),
        "--repos",
        "all",
        "--verify-only",
        check=False,
    )

    audit = json.loads(report.read_text(encoding="utf-8"))
    assert result.returncode != 0
    assert not (repo_root / "demo").exists()
    assert audit["repositories"][0]["operation"]["message"] == "repository is missing in verify-only mode"
