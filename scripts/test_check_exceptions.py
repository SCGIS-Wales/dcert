"""Tests for scripts/check_exceptions.py."""

from __future__ import annotations

import datetime
import importlib.util
import sys
from pathlib import Path

from click.testing import CliRunner

_spec = importlib.util.spec_from_file_location(
    "check_exceptions", Path(__file__).with_name("check_exceptions.py")
)
assert _spec is not None
assert _spec.loader is not None
check_exceptions = importlib.util.module_from_spec(_spec)
sys.modules["check_exceptions"] = check_exceptions
_spec.loader.exec_module(check_exceptions)

TODAY = datetime.date(2026, 11, 20)


def test_empty_list_passes() -> None:
    assert check_exceptions.problems("[advisories]\nignore = []\n", TODAY) == []


def test_entry_with_future_expiry_passes() -> None:
    comment = "# No fix upstream. owner: dg expires: 2026-12-10"
    text = f'[advisories]\nignore = [\n    {comment}\n    "RUSTSEC-2026-1",\n]\n'
    assert check_exceptions.problems(text, TODAY) == []


def test_entry_without_expiry_fails() -> None:
    text = '[advisories]\nignore = [\n    # reason only\n    "RUSTSEC-2026-1",\n]\n'
    assert check_exceptions.problems(text, TODAY) == [
        "RUSTSEC-2026-1: no 'expires: YYYY-MM-DD' comment"
    ]


def test_expired_entry_fails() -> None:
    text = '[advisories]\nignore = [\n    # expires: 2026-11-19\n    "RUSTSEC-2026-1",\n]\n'
    assert check_exceptions.problems(text, TODAY) == ["RUSTSEC-2026-1: expired on 2026-11-19"]


def test_trailing_comment_counts() -> None:
    text = '[advisories]\nignore = [\n    "RUSTSEC-2026-1", # expires: 2026-12-01\n]\n'
    assert check_exceptions.problems(text, TODAY) == []


def test_comment_for_one_entry_does_not_cover_the_next() -> None:
    text = '[advisories]\nignore = [\n    # expires: 2026-12-01\n    "A-1",\n    "B-2",\n]\n'
    assert check_exceptions.problems(text, TODAY) == ["B-2: no 'expires: YYYY-MM-DD' comment"]


def test_table_entry_is_recognised() -> None:
    text = '[advisories]\nignore = [\n    { id = "RUSTSEC-2026-1", reason = "x" },\n]\n'
    assert check_exceptions.problems(text, TODAY) == [
        "RUSTSEC-2026-1: no 'expires: YYYY-MM-DD' comment"
    ]


def test_cli_exit_codes(tmp_path: Path) -> None:
    good = tmp_path / "good.toml"
    good.write_text("[advisories]\nignore = []\n")
    bad = tmp_path / "bad.toml"
    bad.write_text('[advisories]\nignore = [\n    "X-1",\n]\n')
    runner = CliRunner()
    assert runner.invoke(check_exceptions.main, [str(good)]).exit_code == 0
    assert runner.invoke(check_exceptions.main, [str(bad)]).exit_code == 1


def test_repository_files_pass_today() -> None:
    result = CliRunner().invoke(check_exceptions.main, [])
    assert result.exit_code == 0, result.output


def test_openssl_exception_expiry_is_checked() -> None:
    text = "exceptions:\n  - branch: '3.6'\n    expires: 2026-11-19\n"
    assert check_exceptions.yaml_problems(text, TODAY) == ["OpenSSL 3.6: expired on 2026-11-19"]
    assert check_exceptions.yaml_problems("exceptions: []\n", TODAY) == []
    assert check_exceptions.yaml_problems("exceptions:\n  - branch: '3.6'\n", TODAY) == [
        "OpenSSL 3.6: no expires date"
    ]
