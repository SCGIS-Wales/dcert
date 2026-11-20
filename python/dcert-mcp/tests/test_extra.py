"""The package imports without the ``proxy`` extra and explains what is missing."""

import importlib
import sys

import pytest

import dcert_mcp
from dcert_mcp import proxy


@pytest.fixture
def without_fastmcp(monkeypatch):
    """Make ``import fastmcp`` fail and forget modules that already imported it."""
    for name in [m for m in sys.modules if m.startswith("fastmcp.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "fastmcp", None)
    for name in [m for m in sys.modules if m.startswith("dcert_mcp.")]:
        if name != "dcert_mcp.proxy":
            monkeypatch.delitem(sys.modules, name)
    for name in list(vars(dcert_mcp)):
        if name in dcert_mcp._EXPORTS:
            monkeypatch.delattr(dcert_mcp, name)


def test_bare_import_needs_no_third_party_package():
    assert dcert_mcp.__version__
    assert "PROXY_EXTRA_HINT" in dir(dcert_mcp)


def test_unknown_attribute():
    with pytest.raises(AttributeError, match="no attribute 'nope'"):
        dcert_mcp.nope  # noqa: B018


def test_helper_names_the_extra_when_fastmcp_is_missing(without_fastmcp):
    with pytest.raises(ImportError) as info:
        dcert_mcp.create_server  # noqa: B018
    message = str(info.value)
    assert "\n" not in message
    assert 'pip install "dcert-mcp[proxy]"' in message
    assert "fastmcp" in message


def test_unrelated_import_error_is_not_masked(monkeypatch):
    def boom(name):
        raise ModuleNotFoundError("No module named 'other'", name="other")

    monkeypatch.setattr(importlib, "import_module", boom)
    with pytest.raises(ModuleNotFoundError, match="other"):
        dcert_mcp.__getattr__("create_server")


def test_proxy_command_prints_one_line_when_extra_missing(without_fastmcp, capsys):
    with pytest.raises(SystemExit) as info:
        proxy.main()
    assert info.value.code == 1
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert 'pip install "dcert-mcp[proxy]"' in err


def test_proxy_command_runs_the_click_command(monkeypatch):
    called = []
    monkeypatch.setattr("dcert_mcp.cli.main", lambda: called.append(True))
    proxy.main()
    assert called == [True]
