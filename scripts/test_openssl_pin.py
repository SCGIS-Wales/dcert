"""Tests for scripts/ci/openssl_pin.py and the pin in scripts/openssl_floor.yaml."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import click
import pytest
import yaml

_path = Path(__file__).with_name("ci") / "openssl_pin.py"
_spec = importlib.util.spec_from_file_location("openssl_pin", _path)
assert _spec is not None
assert _spec.loader is not None
openssl_pin = importlib.util.module_from_spec(_spec)
sys.modules["openssl_pin"] = openssl_pin
_spec.loader.exec_module(openssl_pin)

TEXT = """
windows_source:
  version: "3.5.9"
  sha256: "ab"
  url: "https://example.test/openssl-{version}.tar.gz"
"""


def test_url_has_the_version_filled_in() -> None:
    assert openssl_pin.pinned("url", TEXT) == "https://example.test/openssl-3.5.9.tar.gz"


def test_plain_fields_are_returned() -> None:
    assert openssl_pin.pinned("version", TEXT) == "3.5.9"
    assert openssl_pin.pinned("sha256", TEXT) == "ab"


def test_missing_field_is_an_error() -> None:
    with pytest.raises(click.ClickException):
        openssl_pin.pinned("nope", TEXT)


def test_repository_pin_is_a_full_sha256_and_meets_the_floor() -> None:
    spec = yaml.safe_load((Path(__file__).with_name("openssl_floor.yaml")).read_text())
    pin = spec["windows_source"]
    assert re.fullmatch(r"[0-9a-f]{64}", pin["sha256"])
    major_minor = ".".join(pin["version"].split(".")[:2])
    floor = spec["floors"][major_minor]
    assert tuple(map(int, pin["version"].split("."))) >= tuple(map(int, floor.split(".")))
