"""Tests for scripts/check_openssl_floor.py."""

from __future__ import annotations

import datetime
import importlib.util
import sys
from pathlib import Path
from typing import Any

import click
import pytest

_spec = importlib.util.spec_from_file_location(
    "check_openssl_floor", Path(__file__).with_name("check_openssl_floor.py")
)
assert _spec is not None
assert _spec.loader is not None
floor = importlib.util.module_from_spec(_spec)
sys.modules["check_openssl_floor"] = floor
_spec.loader.exec_module(floor)

D = datetime.date
SPEC: dict[str, Any] = {
    "floors": {"3.5": "3.5.9", "4.0": "4.0.3"},
    "scheduled": [{"date": D(2026, 12, 1), "floors": {"3.5": "3.5.10", "4.0": "4.0.4"}}],
    "distro_managed": ["3.0"],
    "exceptions": [{"branch": "3.6", "owner": "o", "reason": "r", "expires": D(2026, 12, 18)}],
}
NOV = D(2026, 11, 20)


def test_parse_version_line() -> None:
    out = "dcert 3.0.86\nOpenSSL 3.5.9 7 Jul 2026 (post quantum key exchange: available)\n"
    assert floor.parse_openssl_version(out) == (3, 5, 9)


def test_parse_version_without_openssl_line_is_an_error() -> None:
    with pytest.raises(click.ClickException):
        floor.parse_openssl_version("dcert 3.0.86\n")


def test_at_floor_passes() -> None:
    assert floor.verdict((3, 5, 9), SPEC, NOV) is None


def test_below_floor_fails() -> None:
    assert "below the 3.5 floor 3.5.9" in floor.verdict((3, 5, 8), SPEC, NOV)


def test_scheduled_floor_applies_after_its_date() -> None:
    assert floor.verdict((3, 5, 9), SPEC, D(2026, 11, 30)) is None
    assert "3.5.10" in floor.verdict((3, 5, 9), SPEC, D(2026, 12, 1))


def test_distro_managed_branch_passes() -> None:
    assert floor.verdict((3, 0, 2), SPEC, NOV) is None


def test_newer_branch_passes() -> None:
    assert floor.verdict((4, 1, 0), SPEC, NOV) is None


def test_unknown_older_branch_fails() -> None:
    assert "no floor and no exception" in floor.verdict((3, 4, 1), SPEC, NOV)


def test_excepted_branch_passes_within_window() -> None:
    assert floor.verdict((3, 6, 3), SPEC, NOV) is None


def test_expired_exception_fails() -> None:
    assert "expired" in floor.verdict((3, 6, 3), SPEC, D(2026, 12, 19))


def test_exception_too_far_ahead_fails() -> None:
    assert "more than 30 days" in floor.verdict((3, 6, 3), SPEC, D(2026, 11, 1))


def test_exception_without_owner_fails() -> None:
    spec = dict(SPEC, exceptions=[{"branch": "3.6", "reason": "r", "expires": D(2026, 12, 18)}])
    assert "lacks owner" in floor.verdict((3, 6, 3), spec, NOV)


def test_report_only_does_not_fail_below_the_floor(tmp_path: Path) -> None:
    from click.testing import CliRunner

    binary = tmp_path / "fake"
    binary.write_text("#!/bin/sh\necho 'dcert 1'\necho 'OpenSSL 3.4.1 1 Jan 2026'\n")
    binary.chmod(0o755)
    runner = CliRunner()
    assert runner.invoke(floor.main, [str(binary)]).exit_code == 1
    assert runner.invoke(floor.main, ["--report-only", str(binary)]).exit_code == 0
