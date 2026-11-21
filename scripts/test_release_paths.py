"""Tests for scripts/ci/release_paths.py."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

_PATH = Path(__file__).with_name("ci") / "release_paths.py"
_SPEC = importlib.util.spec_from_file_location("release_paths", _PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
rp = importlib.util.module_from_spec(_SPEC)
sys.modules["release_paths"] = rp
_SPEC.loader.exec_module(rp)

CONFIG = yaml.safe_load(rp.CONFIG.read_text(encoding="utf-8"))


def test_patterns() -> None:
    assert rp.pattern_regex("*.md").match("README.md")
    assert not rp.pattern_regex("*.md").match("python/dcert-mcp/README.md")
    assert rp.pattern_regex("**/*.md").match("README.md")
    assert rp.pattern_regex("**/*.md").match("a/b/c.md")
    assert rp.pattern_regex("docs/**").match("docs/plans/x.md")
    assert not rp.pattern_regex("docs/**").match("docs")
    assert not rp.pattern_regex("docs/**").match("docsx/a")


def test_documentation_only_push_does_not_release() -> None:
    paths = ["README.md", "CHANGELOG.md", "docs/plans/2026-11-post-split-consistency.md"]
    release, reason = rp.decide(paths, "docs: x", CONFIG)
    assert release is False
    assert "documentation only" in reason


def test_package_readmes_and_code_release() -> None:
    for path in [
        "python/dcert-mcp/README.md",
        "python/dcert-cli/README.md",
        "src/main.rs",
        "kb/diagnostics.yaml",
        ".github/workflows/ci.yml",
        "Cargo.toml",
    ]:
        release, _ = rp.decide(["README.md", path], "fix: x", CONFIG)
        assert release is True, path


def test_skip_marker_overrides_code_changes() -> None:
    release, reason = rp.decide(["src/main.rs"], "fix: x [skip release]", CONFIG)
    assert release is False
    assert "[skip release]" in reason


def test_unknown_paths_release() -> None:
    assert rp.decide(None, "docs: x", CONFIG)[0] is True
    assert rp.decide([], "docs: x", CONFIG) == (False, "nothing changed since the last release")
    assert rp.changed_paths("0" * 40, "HEAD") is None


def test_changed_paths_from_git(tmp_path: Path) -> None:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(tmp_path), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "-q")
    git("config", "user.email", "t@example.invalid")
    git("config", "user.name", "t")
    (tmp_path / "README.md").write_text("a\n")
    git("add", ".")
    git("commit", "-qm", "one")
    first = git("rev-parse", "HEAD")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("b\n")
    git("add", ".")
    git("commit", "-qm", "two")
    import os

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert rp.changed_paths(first, "HEAD") == ["docs/a.md"]
        assert rp.changed_paths("deadbeef" * 5, "HEAD") is None
    finally:
        os.chdir(cwd)
