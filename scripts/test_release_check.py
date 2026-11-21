"""Tests for scripts/ci/release_check.py (no network)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_PATH = Path(__file__).with_name("ci") / "release_check.py"
_SPEC = importlib.util.spec_from_file_location("release_check", _PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
rc = importlib.util.module_from_spec(_SPEC)
sys.modules["release_check"] = rc
_SPEC.loader.exec_module(rc)


def test_expected_assets_cover_archives_wheels_sboms_and_sums() -> None:
    names = rc.expected_assets("4.0.9")
    assert len(names) == 4 + 8 + 3
    assert "dcert_mcp-4.0.9-py3-none-win_amd64.whl" in names
    assert "dcert-4.0.9-py3-none-manylinux_2_34_x86_64.whl" in names
    assert rc.missing_assets([*names, "dcert.rb"], "4.0.9") == []
    assert rc.missing_assets([n for n in names if n != "SHA256SUMS"], "4.0.9") == ["SHA256SUMS"]


def release(project: str, version: str, yanked: bool = False, drop: str = "") -> dict[str, object]:
    dist = project.replace("-", "_")
    files = [
        {"filename": f"{dist}-{version}-py3-none-{p}.whl", "yanked": yanked}
        for p in rc.WHEEL_PLATFORMS
        if p != drop
    ]
    return {"urls": files}


def test_pypi_problems() -> None:
    assert rc.pypi_problems("dcert", "4.0.9", release("dcert", "4.0.9")) == []
    assert rc.pypi_problems("dcert", "4.0.4", None) == ["dcert 4.0.4 is not on PyPI"]
    assert rc.pypi_problems("dcert-mcp", "4.0.3", release("dcert-mcp", "4.0.3", yanked=True)) == [
        "dcert-mcp 4.0.3 is yanked"
    ]
    assert rc.pypi_problems("dcert", "4.0.9", release("dcert", "4.0.9", drop="win_amd64")) == [
        "dcert 4.0.9 has no win_amd64 wheel"
    ]


def test_formula_version_and_tool_table() -> None:
    assert rc.formula_version('class Dcert < Formula\n  version "4.0.9"\n') == "4.0.9"
    assert rc.formula_version("no version") is None
    readme = (
        "x\n### Tools\n\n| Tool | D |\n|--|--|\n| `a` | x |\n| `b_c` | y |\n\n## Next\n| `z` | q |"
    )
    assert rc.tool_table(readme) == ["a", "b_c"]


def test_newest_installable_skips_yanked_and_prereleases() -> None:
    releases = {
        "4.0.3": [{"yanked": True}],
        "4.0.10": [{"yanked": False}],
        "4.0.9": [{"yanked": False}],
        "4.1.0rc1": [{"yanked": False}],
        "4.0.11": [],
    }
    assert rc.newest_installable(releases) == "4.0.10"
    assert rc.newest(["v4.0.9", "v4.0.10", "v4.0.0-beta"]) == "4.0.10"


def test_parity_problems() -> None:
    assert rc.parity_problems("4.0.9", {"dcert": "4.0.9", "dcert-mcp": "4.0.9"}) == []
    assert rc.parity_problems("4.0.9", {"dcert": "4.0.8", "dcert-mcp": None}) == [
        "the newest release tag is v4.0.9 but the newest installable dcert on PyPI is 4.0.8",
        "the newest release tag is v4.0.9 but the newest installable dcert-mcp on PyPI is none",
    ]
    assert rc.parity_problems(None, {}) == ["no v* release tag found"]


def test_summary_table_and_optional_channels() -> None:
    channels = [
        rc.Channel("PyPI dcert", True, ()),
        rc.Channel("Homebrew tap", True, ("the tap formula is at 4.0.8",)),
        rc.Channel("Chocolatey push", False, ("the publish-chocolatey job result is failure",)),
    ]
    table = rc.summary_table("4.0.9", channels)
    assert "| PyPI dcert | ok | - |" in table
    assert "| Homebrew tap | missing | the tap formula is at 4.0.8 |" in table
    assert "| Chocolatey push | warning |" in table
    assert rc.chocolatey("skipped") == []
    assert rc.chocolatey("cancelled") == ["the publish-chocolatey job result is cancelled"]
