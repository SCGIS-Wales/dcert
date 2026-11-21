"""Tests for scripts/ci/openssl_upstream.py (no network)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import click
import pytest
import yaml

_PATH = Path(__file__).with_name("ci") / "openssl_upstream.py"
_SPEC = importlib.util.spec_from_file_location("openssl_upstream", _PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
upstream = importlib.util.module_from_spec(_SPEC)
sys.modules["openssl_upstream"] = upstream
_SPEC.loader.exec_module(upstream)

TAGS = [
    "openssl-4.0.3",
    "openssl-3.5.9",
    "openssl-4.0.4-beta1",
    "openssl-3.5.10",
    "openssl-3.6.3",
    "OpenSSL_1_1_1w",
    "openssl-3.5.2",
]

SPEC_TEXT = """\
floors:
  "3.5": "3.5.9"   # keep this comment
  "4.0": "4.0.3"

windows_source:
  # pinned source
  version: "3.5.9"
  sha256: "aaaa"
  url: "https://example.invalid/{version}"
"""


def test_latest_patches_ignores_prereleases_other_branches_and_old_tags() -> None:
    assert upstream.latest_patches(TAGS, ["3.5", "4.0"]) == {"3.5": (3, 5, 10), "4.0": (4, 0, 3)}


def test_lagging_names_the_floor_and_the_pin() -> None:
    spec = yaml.safe_load(SPEC_TEXT)
    problems = upstream.lagging(spec, {"3.5": (3, 5, 10), "4.0": (4, 0, 3)})
    assert problems == [
        "OpenSSL 3.5.10 is released; the 3.5 floor is still 3.5.9",
        "OpenSSL 3.5.10 is released; the Windows build still pins 3.5.9",
    ]


def test_lagging_is_empty_when_current() -> None:
    spec = yaml.safe_load(SPEC_TEXT)
    assert upstream.lagging(spec, {"3.5": (3, 5, 9), "4.0": (4, 0, 3)}) == []


def test_rewrite_raises_floors_and_pin_and_keeps_comments() -> None:
    latest = {"3.5": (3, 5, 10), "4.0": (4, 0, 3)}
    out = upstream.rewrite(SPEC_TEXT, latest, "3.5.10", "b" * 64)
    assert '"3.5": "3.5.10"   # keep this comment' in out
    assert '"4.0": "4.0.3"' in out
    assert '  version: "3.5.10"' in out
    assert f'  sha256: "{"b" * 64}"' in out
    assert "# pinned source" in out
    assert upstream.lagging(yaml.safe_load(out), latest) == []


def test_rewrite_never_lowers_a_floor() -> None:
    out = upstream.rewrite(SPEC_TEXT, {"4.0": (4, 0, 1)}, None, None)
    assert '"4.0": "4.0.3"' in out


def test_sha256_line_accepts_both_formats() -> None:
    digest = "c" * 64
    assert upstream.sha256_line(digest + "\n") == digest
    assert upstream.sha256_line(f"{digest.upper()}  openssl-3.5.10.tar.gz\n") == digest
    with pytest.raises(click.ClickException):
        upstream.sha256_line("not a digest")


def test_the_repository_file_parses_and_has_a_floor_for_the_pinned_branch() -> None:
    spec = yaml.safe_load(upstream.FLOORS.read_text(encoding="utf-8"))
    pin_branch = ".".join(str(spec["windows_source"]["version"]).split(".")[:2])
    assert pin_branch in spec["floors"]
    assert len(str(spec["windows_source"]["sha256"])) == 64
