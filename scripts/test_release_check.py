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


def test_installable_skips_yanked_and_empty_releases() -> None:
    releases = {
        "4.0.3": [{"yanked": True}],
        "4.0.10": [{"yanked": False}],
        "4.0.11": [],
    }
    assert rc.installable(releases) == {"4.0.10"}
    assert rc.newest(["v4.0.9", "v4.0.10", "v4.0.0-beta"]) == "4.0.10"


def test_parity_problems() -> None:
    assert rc.parity_problems("4.0.9", {"dcert": {"4.0.9", "4.0.10"}, "dcert-mcp": {"4.0.9"}}) == []
    assert rc.parity_problems("4.0.4", {"dcert": {"4.0.5"}, "dcert-mcp": {"4.0.4"}}) == [
        "release v4.0.4 is not installable from PyPI as dcert"
    ]
    assert rc.parity_problems(None, {}) == ["no settled v* release found"]


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


def test_settled_tags_ignore_young_drafts_and_prereleases() -> None:
    now = 1_000_000.0
    releases = [
        {"tag_name": "v4.0.10", "published_at": "1970-01-12T13:46:00Z"},  # 40 s before now
        {"tag_name": "v4.0.9", "published_at": "1970-01-12T10:00:00Z"},
        {"tag_name": "v4.1.0-rc1", "published_at": "1970-01-01T00:00:00Z", "prerelease": True},
        {"tag_name": "v4.2.0", "draft": True, "published_at": None},
    ]
    assert rc.settled_tags(releases, now, 90 * 60) == ["v4.0.9"]


def test_simple_index_problems_name_the_missing_wheels() -> None:
    files = [
        f"dcert_mcp-4.0.11-py3-none-{p}.whl" for p in rc.WHEEL_PLATFORMS if p != "macosx_11_0_arm64"
    ]
    assert rc.simple_index_problems("dcert-mcp", "4.0.11", files) == [
        "the simple index does not list dcert_mcp-4.0.11-py3-none-macosx_11_0_arm64.whl yet"
    ]
    full = [f"dcert-4.0.11-py3-none-{p}.whl" for p in rc.WHEEL_PLATFORMS]
    assert rc.simple_index_problems("dcert", "4.0.11", full) == []
