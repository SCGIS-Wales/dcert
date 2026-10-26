"""Tests for scripts/sync_defaults.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import click
import pytest

_spec = importlib.util.spec_from_file_location(
    "sync_defaults", Path(__file__).with_name("sync_defaults.py")
)
assert _spec is not None
assert _spec.loader is not None
sync_defaults = importlib.util.module_from_spec(_spec)
sys.modules["sync_defaults"] = sync_defaults
_spec.loader.exec_module(sync_defaults)

RUST = """
/// Days.
pub const DEFAULT_EXPIRY_WARN_DAYS: u64 = 30;
pub const BIG: usize = 16_384;
pub const DEFAULT_OUTPUT_DIR: &str = ".";
pub const RANGE: RangeInclusive<u64> = 1..=300;
"""

YAML = """tools:
  # Comment kept.
  expiry_days: 7
  output_dir: "/tmp"
other:
  expiry_days: 99
"""


def test_reads_string_and_integer_constants_only() -> None:
    assert sync_defaults.rust_constants(RUST) == {
        "DEFAULT_EXPIRY_WARN_DAYS": 30,
        "BIG": 16384,
        "DEFAULT_OUTPUT_DIR": ".",
    }


def test_rewrites_only_the_mapped_keys_in_their_section() -> None:
    keys = {
        "tools.expiry_days": "DEFAULT_EXPIRY_WARN_DAYS",
        "tools.output_dir": "DEFAULT_OUTPUT_DIR",
    }
    out = sync_defaults.synced(YAML, keys, sync_defaults.rust_constants(RUST))
    assert "  expiry_days: 30\n" in out
    assert '  output_dir: "."\n' in out
    assert "  # Comment kept.\n" in out
    assert "  expiry_days: 99\n" in out, "another section's key is untouched"


def test_unknown_constant_or_key_is_an_error() -> None:
    constants = sync_defaults.rust_constants(RUST)
    with pytest.raises(click.ClickException):
        sync_defaults.synced(YAML, {"tools.expiry_days": "MISSING"}, constants)
    with pytest.raises(click.ClickException):
        sync_defaults.synced(YAML, {"tools.absent": "BIG"}, constants)


def test_the_repository_is_in_sync() -> None:
    root = Path(__file__).resolve().parent.parent
    mapping = root / "scripts" / "sync_defaults.yaml"
    spec = sync_defaults.yaml.safe_load(mapping.read_text(encoding="utf-8"))
    target = (root / spec["target"]).read_text(encoding="utf-8")
    constants = sync_defaults.rust_constants((root / spec["source"]).read_text(encoding="utf-8"))
    assert sync_defaults.synced(target, spec["keys"], constants) == target
