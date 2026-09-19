"""Tests for dcert.binary."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from dcert import binary as binary_mod
from dcert.binary import (
    binary_filename,
    ensure_executable,
    find_binary,
    find_bundled_binary,
    is_python_script,
)


@pytest.fixture
def clean_env(monkeypatch):
    """Remove the binary override variables and neutralise PATH."""
    monkeypatch.delenv("DCERT_MCP_BINARY", raising=False)
    monkeypatch.delenv("DCERT_PATH", raising=False)
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


# ---------------------------------------------------------------------------
# ensure_executable / binary_filename
# ---------------------------------------------------------------------------


def test_ensure_executable_sets_bits(tmp_path):
    path = _write_binary(tmp_path / "dcert", mode=0o644)
    assert ensure_executable(path) is True
    assert os.access(path, os.X_OK)


def test_ensure_executable_already_executable(tmp_path):
    path = _write_binary(tmp_path / "dcert")
    with patch.object(Path, "chmod") as chmod:
        assert ensure_executable(path) is True
    chmod.assert_not_called()


def test_ensure_executable_chmod_failure(tmp_path):
    path = _write_binary(tmp_path / "dcert", mode=0o644)
    with patch.object(Path, "chmod", side_effect=OSError("read only")):
        assert ensure_executable(path) is False


def test_binary_filename_posix():
    with patch("dcert.binary.sys.platform", "linux"):
        assert binary_filename("dcert") == "dcert"


def test_binary_filename_windows():
    with patch("dcert.binary.sys.platform", "win32"):
        assert binary_filename("dcert-mcp") == "dcert-mcp.exe"
        assert binary_filename("dcert-mcp.exe") == "dcert-mcp.exe"


# ---------------------------------------------------------------------------
# find_bundled_binary
# ---------------------------------------------------------------------------


def test_find_bundled_binary_found_and_made_executable(package_dir):
    bundled = _write_binary(package_dir / "bin" / "dcert", mode=0o644)
    assert find_bundled_binary("dcert") == str(bundled)
    assert os.access(bundled, os.X_OK)


def test_find_bundled_binary_not_found(package_dir):
    assert find_bundled_binary("dcert") is None


def test_find_bundled_binary_chmod_failure(package_dir):
    _write_binary(package_dir / "bin" / "dcert", mode=0o644)
    with patch.object(Path, "chmod", side_effect=OSError("read only")):
        assert find_bundled_binary("dcert") is None


def test_find_bundled_binary_windows_exe(package_dir):
    bundled = _write_binary(package_dir / "bin" / "dcert-mcp.exe")
    with patch("dcert.binary.sys.platform", "win32"):
        assert find_bundled_binary("dcert-mcp") == str(bundled)


# ---------------------------------------------------------------------------
# find_binary search order
# ---------------------------------------------------------------------------


def test_find_binary_explicit_env(tmp_path, clean_env, monkeypatch):
    explicit = _write_binary(tmp_path / "dcert-mcp")
    monkeypatch.setenv("DCERT_MCP_BINARY", str(explicit))
    assert find_binary("dcert-mcp") == str(explicit)


def test_find_binary_dcert_uses_dcert_path(tmp_path, clean_env, monkeypatch):
    explicit = _write_binary(tmp_path / "dcert")
    monkeypatch.setenv("DCERT_PATH", str(explicit))
    assert find_binary("dcert") == str(explicit)


def test_find_binary_explicit_env_missing(clean_env, monkeypatch):
    monkeypatch.setenv("DCERT_MCP_BINARY", "/nonexistent/dcert-mcp")
    with pytest.raises(FileNotFoundError, match="DCERT_MCP_BINARY"):
        find_binary("dcert-mcp")


def test_find_binary_explicit_env_not_executable(tmp_path, clean_env, monkeypatch):
    explicit = _write_binary(tmp_path / "dcert-mcp", mode=0o644)
    monkeypatch.setenv("DCERT_MCP_BINARY", str(explicit))
    with pytest.raises(FileNotFoundError, match="not executable"):
        find_binary("dcert-mcp")


def test_find_binary_bundled_before_path(tmp_path, clean_env, package_dir, monkeypatch):
    bundled = _write_binary(package_dir / "bin" / "dcert-mcp")
    (tmp_path / "path").mkdir()
    _write_binary(tmp_path / "path" / "dcert-mcp")
    monkeypatch.setenv("PATH", str(tmp_path / "path"))
    assert find_binary("dcert-mcp") == str(bundled)


def test_find_binary_path_lookup(tmp_path, clean_env, package_dir, monkeypatch):
    on_path = _write_binary(tmp_path / "dcert-mcp")
    monkeypatch.setenv("PATH", str(tmp_path))
    with patch("dcert.download.ensure_binary") as download:
        assert find_binary("dcert-mcp") == str(on_path)
    download.assert_not_called()


def test_find_binary_skips_python_wrapper(tmp_path, clean_env, package_dir, monkeypatch):
    wrapper = tmp_path / "dcert-mcp"
    wrapper.write_bytes(b"#!/usr/bin/env python3\nimport sys\n")
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    with (
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(FileNotFoundError, match="dcert-mcp binary not found"),
    ):
        find_binary("dcert-mcp")


def test_find_binary_download_fallback(tmp_path, clean_env, package_dir):
    (tmp_path / "install").mkdir()
    installed = _write_binary(tmp_path / "install" / "dcert-mcp")
    with (
        patch("dcert.download.ensure_binary", return_value=str(installed)) as download,
        patch("dcert.download.get_install_dir", return_value=tmp_path / "install"),
    ):
        assert find_binary("dcert-mcp") == str(installed)
    download.assert_called_once()


def test_find_binary_download_resolves_requested_name(tmp_path, clean_env, package_dir):
    """A download installs both binaries; the requested one is returned."""
    install = tmp_path / "install"
    install.mkdir()
    mcp = _write_binary(install / "dcert-mcp")
    cli = _write_binary(install / "dcert", mode=0o644)
    with (
        patch("dcert.download.ensure_binary", return_value=str(mcp)),
        patch("dcert.download.get_install_dir", return_value=install),
    ):
        assert find_binary("dcert") == str(cli)
    assert os.access(cli, os.X_OK)


def test_find_binary_download_missing_requested_name(tmp_path, clean_env, package_dir):
    install = tmp_path / "install"
    install.mkdir()
    mcp = _write_binary(install / "dcert-mcp")
    with (
        patch("dcert.download.ensure_binary", return_value=str(mcp)),
        patch("dcert.download.get_install_dir", return_value=install),
        pytest.raises(FileNotFoundError, match="dcert binary not found"),
    ):
        find_binary("dcert")


def test_find_binary_download_none(clean_env, package_dir):
    with (
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(FileNotFoundError, match="DCERT_MCP_BINARY"),
    ):
        find_binary("dcert-mcp")


def test_find_binary_download_network_failure(clean_env, package_dir, caplog):
    with (
        patch("dcert.download.ensure_binary", side_effect=OSError("network down")),
        pytest.raises(FileNotFoundError, match="dcert-mcp binary not found"),
    ):
        find_binary("dcert-mcp")
    assert "network down" in caplog.text


def test_find_binary_checksum_failure_propagates(clean_env, package_dir):
    with (
        patch("dcert.download.ensure_binary", side_effect=RuntimeError("Checksum mismatch")),
        pytest.raises(RuntimeError, match="integrity verification: Checksum mismatch"),
    ):
        find_binary("dcert-mcp")
