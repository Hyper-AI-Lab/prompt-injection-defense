"""Hermetic dry-run failure modes of scripts/cut_release.sh (no network, no gate run).

Each case builds a throwaway repo copy holding only the files the early checks read,
so the script fails before it ever reaches git fetch, the release gate, or gh.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "cut_release.sh"

CHANGELOG = """# Changelog

## [Unreleased]

## [2.0.0] - 2026-10-11

### Added
- Something real.

## [1.9.0] - 2026-10-01

[2.0.0]: https://example.invalid/compare/v1.9.0...v2.0.0
"""


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    (root / "src" / "containment").mkdir(parents=True)
    shutil.copy2(SCRIPT, root / "scripts" / "cut_release.sh")
    (root / "pyproject.toml").write_text('[project]\nname = "containment"\nversion = "2.0.0"\n')
    (root / "src" / "containment" / "__init__.py").write_text('__version__ = "2.0.0"\n')
    (root / "CHANGELOG.md").write_text(CHANGELOG)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(root / "scripts" / "cut_release.sh"), *args],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_help_exits_zero(fake_repo: Path) -> None:
    proc = _run(fake_repo, "--help")
    assert proc.returncode == 0
    assert "Usage: scripts/cut_release.sh X.Y.Z [--execute]" in proc.stdout


def test_missing_version_fails(fake_repo: Path) -> None:
    proc = _run(fake_repo)
    assert proc.returncode == 1
    assert "cut_release: FAIL: version argument required" in proc.stderr


def test_unknown_option_fails(fake_repo: Path) -> None:
    proc = _run(fake_repo, "2.0.0", "--force")
    assert proc.returncode == 1
    assert "cut_release: FAIL: unknown option: --force" in proc.stderr


def test_non_semver_fails(fake_repo: Path) -> None:
    proc = _run(fake_repo, "2.0")
    assert proc.returncode == 1
    assert "cut_release: FAIL: version '2.0' is not MAJOR.MINOR.PATCH" in proc.stderr


def test_pyproject_version_mismatch_fails(fake_repo: Path) -> None:
    proc = _run(fake_repo, "2.0.1")
    assert proc.returncode == 1
    assert (
        "cut_release: FAIL: version mismatch: pyproject.toml=2.0.0, requested=2.0.1"
        in proc.stderr
    )


def test_dunder_version_mismatch_fails(fake_repo: Path) -> None:
    (fake_repo / "src" / "containment" / "__init__.py").write_text('__version__ = "1.9.0"\n')
    proc = _run(fake_repo, "2.0.0")
    assert proc.returncode == 1
    assert (
        "cut_release: FAIL: version mismatch: containment.__version__=1.9.0, requested=2.0.0"
        in proc.stderr
    )


def test_empty_changelog_section_fails(fake_repo: Path) -> None:
    (fake_repo / "pyproject.toml").write_text('[project]\nversion = "1.9.0"\n')
    (fake_repo / "src" / "containment" / "__init__.py").write_text('__version__ = "1.9.0"\n')
    proc = _run(fake_repo, "1.9.0")
    assert proc.returncode == 1
    assert "cut_release: FAIL: CHANGELOG.md has no non-empty '## [1.9.0]' section" in proc.stderr


def test_existing_local_tag_fails(fake_repo: Path) -> None:
    _git(fake_repo, "tag", "-a", "v2.0.0", "-m", "x")
    proc = _run(fake_repo, "2.0.0")
    assert proc.returncode == 1
    assert "cut_release: FAIL: tag v2.0.0 already exists locally" in proc.stderr


def test_dirty_tree_fails(fake_repo: Path) -> None:
    (fake_repo / "stray.txt").write_text("uncommitted\n")
    proc = _run(fake_repo, "2.0.0")
    assert proc.returncode == 1
    assert "cut_release: FAIL: working tree is dirty (commit or stash first)" in proc.stderr


def test_missing_origin_fails_before_gate(fake_repo: Path) -> None:
    proc = _run(fake_repo, "2.0.0")
    assert proc.returncode == 1
    assert "release notes extracted from CHANGELOG.md (4 lines)" in proc.stdout
    assert "cut_release: FAIL: git fetch origin main failed" in proc.stderr
