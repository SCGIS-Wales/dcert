"""Tests for dcert.binary."""

import os
import tarfile
import zipfile
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
    is_running_script,
    is_wrapper,
)
from dcert.config import load_config
from dcert.download import IntegrityError


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
    with patch("dcert.binary.sys.argv", [str(launcher), "--version"]):
        assert is_running_script(str(launcher)) is True
        assert is_running_script(str(link)) is True
        assert is_running_script(str(_write_binary(tmp_path / "other"))) is False
        assert is_running_script("/nonexistent/dcert-mcp") is False


@pytest.mark.parametrize("argv", [[], [""], ["-c"]])
def test_is_running_script_without_a_script(tmp_path, argv):
    with patch("dcert.binary.sys.argv", argv):
        assert is_running_script(str(_write_binary(tmp_path / "dcert-mcp"))) is False


def test_is_wrapper(tmp_path):
    wrapper = tmp_path / "wrapper"
    wrapper.write_bytes(b"#!/usr/bin/env python3\n")
    binary = _write_binary(tmp_path / "binary")
    with patch("dcert.binary.sys.argv", [str(binary)]):
        assert is_wrapper(str(wrapper)) is True
        assert is_wrapper(str(binary)) is True
    with patch("dcert.binary.sys.argv", ["unrelated"]):
        assert is_wrapper(str(binary)) is False


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


def test_find_binary_explicit_env(tmp_path, no_path, monkeypatch):
    explicit = _write_binary(tmp_path / "dcert-mcp")
    monkeypatch.setenv("DCERT_MCP_BINARY", str(explicit))
    assert find_binary("dcert-mcp") == str(explicit)


def test_find_binary_dcert_uses_dcert_path(tmp_path, no_path, monkeypatch):
    explicit = _write_binary(tmp_path / "dcert")
    monkeypatch.setenv("DCERT_PATH", str(explicit))
    assert find_binary("dcert") == str(explicit)


def test_find_binary_explicit_relative_path_is_made_absolute(tmp_path, no_path, monkeypatch):
    """A relative DCERT_MCP_BINARY must never be resolved through PATH by exec."""
    _write_binary(tmp_path / "dcert-mcp")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DCERT_MCP_BINARY", "dcert-mcp")
    found = find_binary("dcert-mcp")
    assert Path(found).is_absolute()
    assert Path(found) == (tmp_path / "dcert-mcp").resolve()


def test_find_binary_explicit_env_missing(no_path, monkeypatch):
    monkeypatch.setenv("DCERT_MCP_BINARY", "/nonexistent/dcert-mcp")
    with pytest.raises(FileNotFoundError, match="DCERT_MCP_BINARY"):
        find_binary("dcert-mcp")


def test_find_binary_explicit_env_not_executable(tmp_path, no_path, monkeypatch):
    explicit = _write_binary(tmp_path / "dcert-mcp", mode=0o644)
    monkeypatch.setenv("DCERT_MCP_BINARY", str(explicit))
    with pytest.raises(FileNotFoundError, match="not executable"):
        find_binary("dcert-mcp")


def test_find_binary_bundled_before_path(tmp_path, no_path, package_dir, monkeypatch):
    bundled = _write_binary(package_dir / "bin" / "dcert-mcp")
    (tmp_path / "path").mkdir()
    _write_binary(tmp_path / "path" / "dcert-mcp")
    monkeypatch.setenv("PATH", str(tmp_path / "path"))
    assert find_binary("dcert-mcp") == str(bundled)


def test_find_binary_path_lookup(tmp_path, no_path, package_dir, monkeypatch):
    on_path = _write_binary(tmp_path / "dcert-mcp")
    monkeypatch.setenv("PATH", str(tmp_path))
    with patch("dcert.download.ensure_binary") as download:
        assert find_binary("dcert-mcp") == str(on_path)
    download.assert_not_called()


def test_find_binary_skips_python_wrapper(tmp_path, no_path, package_dir, monkeypatch):
    wrapper = tmp_path / "dcert-mcp"
    wrapper.write_bytes(b"#!/usr/bin/env python3\nimport sys\n")
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    with (
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(FileNotFoundError, match="dcert-mcp binary not found"),
    ):
        find_binary("dcert-mcp")


def test_find_binary_skips_running_launcher(tmp_path, no_path, package_dir, monkeypatch):
    """On Windows pip's launcher is a native .exe: it is skipped by file identity."""
    launcher = _write_binary(tmp_path / "dcert-mcp")
    monkeypatch.setenv("PATH", str(tmp_path))
    with (
        patch("dcert.binary.sys.argv", [str(launcher), "--version"]),
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(FileNotFoundError, match="dcert-mcp binary not found"),
    ):
        find_binary("dcert-mcp")


def test_find_binary_download_fallback(tmp_path, no_path, package_dir):
    (tmp_path / "install").mkdir()
    installed = _write_binary(tmp_path / "install" / "dcert-mcp")
    with (
        patch("dcert.download.ensure_binary", return_value=str(installed)) as download,
        patch("dcert.download.get_install_dir", return_value=tmp_path / "install"),
    ):
        assert find_binary("dcert-mcp") == str(installed)
    download.assert_called_once()


def test_find_binary_download_resolves_requested_name(tmp_path, no_path, package_dir):
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


def test_find_binary_download_missing_requested_name(tmp_path, no_path, package_dir):
    install = tmp_path / "install"
    install.mkdir()
    mcp = _write_binary(install / "dcert-mcp")
    with (
        patch("dcert.download.ensure_binary", return_value=str(mcp)),
        patch("dcert.download.get_install_dir", return_value=install),
        pytest.raises(FileNotFoundError, match="dcert binary not found"),
    ):
        find_binary("dcert")


def test_find_binary_download_none(no_path, package_dir):
    with (
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(FileNotFoundError, match="DCERT_MCP_BINARY"),
    ):
        find_binary("dcert-mcp")


@pytest.mark.parametrize(
    "exc",
    [OSError("network down"), tarfile.TarError("bad tar"), zipfile.BadZipFile("bad zip")],
)
def test_find_binary_download_failures_are_masked(no_path, package_dir, caplog, exc):
    with (
        patch("dcert.download.ensure_binary", side_effect=exc),
        pytest.raises(FileNotFoundError, match="dcert-mcp binary not found"),
    ):
        find_binary("dcert-mcp")
    assert str(exc) in caplog.text


def test_find_binary_integrity_failure_propagates(no_path, package_dir):
    with (
        patch("dcert.download.ensure_binary", side_effect=IntegrityError("Checksum mismatch")),
        pytest.raises(IntegrityError, match="integrity verification: Checksum mismatch"),
    ):
        find_binary("dcert-mcp")


def test_find_binary_malformed_archive_is_not_an_integrity_failure(no_path, package_dir):
    """A verified archive without the binary is a packaging error, reported as such."""
    with (
        patch("dcert.download.ensure_binary", side_effect=RuntimeError("not found in archive")),
        pytest.raises(RuntimeError, match="^not found in archive$"),
    ):
        find_binary("dcert")


def test_find_binary_unknown_name_uses_fallback_variable(no_path, package_dir):
    with (
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(FileNotFoundError, match=load_config().binaries.fallback_env),
    ):
        find_binary("dcert-other")
