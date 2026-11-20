"""Tests for dcert_mcp.binary."""

from pathlib import Path
from unittest.mock import patch

import pytest

from dcert_mcp import binary as binary_mod
from dcert_mcp.binary import (
    find_binary,
    is_python_script,
    is_running_script,
)
from dcert_mcp.config import load_config


@pytest.fixture
def no_path(clean_env, monkeypatch):
    """No override variables and nothing on PATH."""
    monkeypatch.setenv("PATH", "/nonexistent")


@pytest.fixture
def package_dir(tmp_path, monkeypatch):
    """Point the module at a temporary package directory with a bin/ folder."""
    monkeypatch.setattr(binary_mod, "__file__", str(tmp_path / "binary.py"))
    (tmp_path / "bin").mkdir()
    return tmp_path


def _write_binary(path: Path, mode: int = 0o755) -> Path:
    path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 120)
    path.chmod(mode)
    return path


# ---------------------------------------------------------------------------
# is_python_script
# ---------------------------------------------------------------------------


def test_detects_python_shebang(tmp_path):
    wrapper = tmp_path / "dcert-mcp"
    wrapper.write_bytes(b"#!/usr/bin/env python3\nimport sys\n")
    assert is_python_script(str(wrapper)) is True


def test_rejects_elf_binary(tmp_path):
    assert is_python_script(str(_write_binary(tmp_path / "dcert-mcp"))) is False


def test_rejects_mach_o_binary(tmp_path):
    path = tmp_path / "dcert-mcp"
    path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 124)
    assert is_python_script(str(path)) is False


def test_shebang_without_python(tmp_path):
    path = tmp_path / "dcert-mcp"
    path.write_bytes(b"#!/bin/bash\necho hello\n")
    assert is_python_script(str(path)) is False


def test_nonexistent_path():
    assert is_python_script("/nonexistent/path/xyz") is False


def test_probe_reads_configured_number_of_bytes(tmp_path):
    """Only the configured head is inspected, so a huge first line is not read whole."""
    probe = load_config().binaries.wrapper_probe_bytes
    path = tmp_path / "dcert-mcp"
    path.write_bytes(b"#!" + b" " * probe + b"python\n")
    assert is_python_script(str(path)) is False


# ---------------------------------------------------------------------------
# is_running_script / is_wrapper
# ---------------------------------------------------------------------------


def test_is_running_script_matches_argv0_by_identity(tmp_path):
    launcher = _write_binary(tmp_path / "dcert-mcp.exe")
    link = tmp_path / "link"
    link.symlink_to(launcher)
    with patch("dcert_mcp.binary.sys.argv", [str(launcher), "--version"]):
        assert is_running_script(str(launcher)) is True
        assert is_running_script(str(link)) is True
        assert is_running_script(str(_write_binary(tmp_path / "other"))) is False
        assert is_running_script("/nonexistent/dcert-mcp") is False


def test_find_binary_unknown_name_uses_fallback_variable(no_path, package_dir):
    with pytest.raises(FileNotFoundError, match=load_config().binaries.fallback_env):
        find_binary("dcert-other")
