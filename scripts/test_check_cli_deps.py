"""Tests for scripts/check_cli_deps.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

_spec = importlib.util.spec_from_file_location(
    "check_cli_deps", Path(__file__).with_name("check_cli_deps.py")
)
assert _spec is not None
assert _spec.loader is not None
check_cli_deps = importlib.util.module_from_spec(_spec)
sys.modules["check_cli_deps"] = check_cli_deps
_spec.loader.exec_module(check_cli_deps)

TREE = """dcert v3.0.80 (/work/dcert)
clap v4.6.1
clap_derive v4.6.1 (proc-macro)
serde v1.0.230
serde v1.0.230 (*)
rmcp v3.11.0
serde v1.0.229
"""

BUDGET = {"max_crates": 10, "banned_crates": ["rmcp", "rsa"]}


def test_parse_tree_counts_unique_name_and_version_pairs() -> None:
    crates = check_cli_deps.parse_tree(TREE)
    assert ("serde", "1.0.230") in crates
    assert ("serde", "1.0.229") in crates
    assert len(crates) == 6  # dcert, clap, clap_derive, two serde versions, rmcp


def test_parse_tree_ignores_blank_and_noise_lines() -> None:
    assert check_cli_deps.parse_tree("\n   \nnot a crate line\n") == set()


def test_banned_crate_is_reported() -> None:
    problems = check_cli_deps.violations(check_cli_deps.parse_tree(TREE), BUDGET)
    assert problems == ["banned crate in the CLI tree: rmcp"]


def test_crate_count_over_budget_is_reported() -> None:
    problems = check_cli_deps.violations({("a", "1"), ("b", "1"), ("c", "1")}, {"max_crates": 2})
    assert problems == ["3 crates, budget is 2"]


def test_tree_within_budget_has_no_violations() -> None:
    assert check_cli_deps.violations({("a", "1")}, BUDGET) == []


def _run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, enforce_in_file: bool, flag: list[str]
) -> tuple[int, str]:
    budget = tmp_path / "budget.yaml"
    budget.write_text(
        f"max_crates: 10\nenforce: {str(enforce_in_file).lower()}\nbanned_crates: [rmcp]\n"
    )
    monkeypatch.setattr(check_cli_deps, "cargo_tree", lambda _args: TREE)
    result = CliRunner().invoke(check_cli_deps.main, ["--budget", str(budget), *flag])
    return result.exit_code, result.output


def test_report_only_mode_does_not_fail(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    code, output = _run(monkeypatch, tmp_path, False, [])
    assert code == 0
    assert "report only" in output


def test_budget_file_can_enforce(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    code, _ = _run(monkeypatch, tmp_path, True, [])
    assert code == 1


def test_enforce_flag_overrides_report_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, _ = _run(monkeypatch, tmp_path, False, ["--enforce"])
    assert code == 1
