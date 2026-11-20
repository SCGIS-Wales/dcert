"""Tests for scripts/ci/extras_requirements.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).with_name("ci") / "extras_requirements.py"
_SPEC = importlib.util.spec_from_file_location("extras_requirements", _PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
extras_requirements = importlib.util.module_from_spec(_SPEC)
sys.modules["extras_requirements"] = extras_requirements
_SPEC.loader.exec_module(extras_requirements)


def test_proxy_requirements_include_fastmcp_and_the_security_floors() -> None:
    reqs = extras_requirements.requirements(["proxy"])
    assert any(r.startswith("fastmcp") for r in reqs)
    assert any(r.startswith("authlib") for r in reqs)


def test_extras_are_combined_without_duplicates() -> None:
    reqs = extras_requirements.requirements(["proxy", "otel", "proxy"])
    assert len(reqs) == len(set(reqs))
    assert any(r.startswith("opentelemetry-sdk") for r in reqs)


def test_unknown_extra() -> None:
    with pytest.raises(KeyError):
        extras_requirements.requirements(["nope"])


def test_main_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert extras_requirements.main([]) == 2
    assert extras_requirements.main(["nope"]) == 1
    assert extras_requirements.main(["otel"]) == 0
    assert "opentelemetry" in capsys.readouterr().out
