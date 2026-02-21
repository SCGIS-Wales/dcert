"""Tests for dcert.download module."""

import hashlib
import io
import json
import os
import tarfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from dcert.download import (
    _extract_binaries,
    _get_archive_name,
    _get_install_dir,
    _get_target_triple,
    _load_checksums,
    _verify_checksum,
    ensure_binary,
)


def _mock_urlopen(data: bytes, capture: dict | None = None):
    """Create a mock for urllib.request.urlopen that returns *data*.

    The mock behaves as a context-manager (``with urlopen(...) as resp``)
    and records the URL via *capture* dict (key ``"url"``), if provided.
    """

    @contextmanager
    def _urlopen(url, *, timeout=None):
        if capture is not None:
            capture["url"] = url
        yield io.BytesIO(data)

    return _urlopen


# ---------------------------------------------------------------------------
# _load_checksums
# ---------------------------------------------------------------------------


def test_load_checksums_exists(tmp_path):
    """Test loading checksums from a valid file."""
    checksums = {"version": "1.0.0", "archives": {"dcert-aarch64-apple-darwin.tar.gz": "abc123"}}
    checksums_file = tmp_path / "checksums.json"
    checksums_file.write_text(json.dumps(checksums))

    # Just verify it returns a dict (depends on whether checksums.json exists)
    result = _load_checksums()
    assert isinstance(result, dict)


def test_load_checksums_missing(tmp_path, monkeypatch):
    """Test loading checksums when file doesn't exist."""
    import dcert.download as dl_mod

    monkeypatch.setattr(dl_mod, "__file__", str(tmp_path / "download.py"))
    result = _load_checksums()
    assert result == {}


def test_load_checksums_valid(tmp_path, monkeypatch):
    """Test loading valid checksums file."""
    import dcert.download as dl_mod

    checksums = {"version": "1.0.0", "archives": {"dcert-aarch64-apple-darwin.tar.gz": "abc123"}}
    checksums_file = tmp_path / "checksums.json"
    checksums_file.write_text(json.dumps(checksums))

    monkeypatch.setattr(dl_mod, "__file__", str(tmp_path / "download.py"))
    result = _load_checksums()
    assert result == checksums
    assert result["version"] == "1.0.0"
    assert result["archives"]["dcert-aarch64-apple-darwin.tar.gz"] == "abc123"


# ---------------------------------------------------------------------------
# _get_target_triple
# ---------------------------------------------------------------------------


def test_get_target_triple_darwin_arm64():
    """Test target triple for macOS ARM."""
    with (
        patch("dcert.download.platform.system", return_value="Darwin"),
        patch("dcert.download.platform.machine", return_value="arm64"),
    ):
        assert _get_target_triple() == "aarch64-apple-darwin"


def test_get_target_triple_darwin_x86():
    """Test target triple for macOS Intel."""
    with (
        patch("dcert.download.platform.system", return_value="Darwin"),
        patch("dcert.download.platform.machine", return_value="x86_64"),
    ):
        assert _get_target_triple() == "x86_64-apple-darwin"


def test_get_target_triple_linux_x86():
    """Test target triple for Linux x86_64."""
    with (
        patch("dcert.download.platform.system", return_value="Linux"),
        patch("dcert.download.platform.machine", return_value="x86_64"),
    ):
        assert _get_target_triple() == "x86_64-unknown-linux-gnu"


def test_get_target_triple_unsupported():
    """Test target triple returns None for unsupported platform."""
    with (
        patch("dcert.download.platform.system", return_value="Linux"),
        patch("dcert.download.platform.machine", return_value="aarch64"),
    ):
        assert _get_target_triple() is None


def test_get_target_triple_windows():
    """Test target triple returns None for Windows."""
    with (
        patch("dcert.download.platform.system", return_value="Windows"),
        patch("dcert.download.platform.machine", return_value="AMD64"),
    ):
        assert _get_target_triple() is None


# ---------------------------------------------------------------------------
# _get_archive_name
# ---------------------------------------------------------------------------


def test_get_archive_name_darwin_arm64():
    """Test archive name for macOS ARM."""
    with (
        patch("dcert.download.platform.system", return_value="Darwin"),
        patch("dcert.download.platform.machine", return_value="arm64"),
    ):
        assert _get_archive_name() == "dcert-aarch64-apple-darwin.tar.gz"


def test_get_archive_name_linux_x86():
    """Test archive name for Linux x86_64."""
    with (
        patch("dcert.download.platform.system", return_value="Linux"),
        patch("dcert.download.platform.machine", return_value="x86_64"),
    ):
        assert _get_archive_name() == "dcert-x86_64-unknown-linux-gnu.tar.gz"


def test_get_archive_name_unsupported():
    """Test archive name returns None for unsupported platform."""
    with (
        patch("dcert.download.platform.system", return_value="FreeBSD"),
        patch("dcert.download.platform.machine", return_value="x86_64"),
    ):
        assert _get_archive_name() is None


# ---------------------------------------------------------------------------
# _get_install_dir
# ---------------------------------------------------------------------------


def test_get_install_dir_scripts_writable(tmp_path):
    """Test install dir uses scripts dir when writable."""
    with patch("dcert.download.sysconfig.get_path", return_value=str(tmp_path)):
        result = _get_install_dir()
        assert result == tmp_path


def test_get_install_dir_scripts_not_writable(tmp_path):
    """Test install dir falls back to ~/.local/bin."""
    non_writable = tmp_path / "no-write"
    non_writable.mkdir()
    non_writable.chmod(0o555)

    local_bin = tmp_path / "home" / ".local" / "bin"

    with (
        patch("dcert.download.sysconfig.get_path", return_value=str(non_writable)),
        patch("dcert.download.Path.home", return_value=tmp_path / "home"),
    ):
        result = _get_install_dir()
        assert result == local_bin
        assert local_bin.exists()

    # Restore permissions for cleanup
    non_writable.chmod(0o755)


# ---------------------------------------------------------------------------
# _verify_checksum
# ---------------------------------------------------------------------------


def test_verify_checksum_match(tmp_path):
    """Test checksum verification with matching hash."""
    content = b"hello world binary content"
    expected = hashlib.sha256(content).hexdigest()
    file_path = tmp_path / "binary"
    file_path.write_bytes(content)

    assert _verify_checksum(file_path, expected) is True


def test_verify_checksum_mismatch(tmp_path):
    """Test checksum verification with wrong hash."""
    file_path = tmp_path / "binary"
    file_path.write_bytes(b"actual content")

    wrong_hash = "0" * 64
    assert _verify_checksum(file_path, wrong_hash) is False


def test_verify_checksum_empty_file(tmp_path):
    """Test checksum verification with empty file."""
    file_path = tmp_path / "empty"
    file_path.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()

    assert _verify_checksum(file_path, expected) is True


# ---------------------------------------------------------------------------
# _extract_binaries
# ---------------------------------------------------------------------------


def _make_tar_gz(tmp_path, filenames):
    """Helper: create a tar.gz containing fake binaries."""
    archive_path = tmp_path / "test.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        for name in filenames:
            data = f"#!/bin/sh\necho {name}".encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return archive_path


def test_extract_binaries_success(tmp_path):
    """Test extracting dcert and dcert-mcp from archive."""
    archive = _make_tar_gz(tmp_path, ["dcert", "dcert-mcp"])
    install_dir = tmp_path / "install"
    install_dir.mkdir()

    result = _extract_binaries(archive, install_dir)
    assert result == install_dir / "dcert-mcp"
    assert (install_dir / "dcert").exists()
    assert (install_dir / "dcert-mcp").exists()
    assert os.access(str(install_dir / "dcert-mcp"), os.X_OK)
    assert os.access(str(install_dir / "dcert"), os.X_OK)


def test_extract_binaries_missing_mcp(tmp_path):
    """Test extraction raises when dcert-mcp not in archive."""
    archive = _make_tar_gz(tmp_path, ["dcert"])
    install_dir = tmp_path / "install"
    install_dir.mkdir()

    with pytest.raises(RuntimeError, match="dcert-mcp binary not found"):
        _extract_binaries(archive, install_dir)


def test_extract_binaries_strips_directory_prefix(tmp_path):
    """Test extraction strips directory prefix from archive members."""
    archive_path = tmp_path / "test.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        for name in ["release/dcert", "release/dcert-mcp"]:
            data = f"#!/bin/sh\necho {name}".encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))

    install_dir = tmp_path / "install"
    install_dir.mkdir()

    result = _extract_binaries(archive_path, install_dir)
    assert result == install_dir / "dcert-mcp"
    assert (install_dir / "dcert").exists()
    assert (install_dir / "dcert-mcp").exists()


# ---------------------------------------------------------------------------
# ensure_binary
# ---------------------------------------------------------------------------


def test_ensure_binary_already_installed(tmp_path):
    """Test ensure_binary returns existing binary path."""
    target = tmp_path / "dcert-mcp"
    target.write_text("#!/bin/sh\necho hello")
    target.chmod(0o755)

    with patch("dcert.download._get_install_dir", return_value=tmp_path):
        result = ensure_binary("1.0.0")
        assert result == str(target)


def test_ensure_binary_unsupported_platform(tmp_path):
    """Test ensure_binary returns None on unsupported platform."""
    with (
        patch("dcert.download._get_install_dir", return_value=tmp_path),
        patch("dcert.download._get_archive_name", return_value=None),
    ):
        result = ensure_binary("1.0.0")
        assert result is None


def test_ensure_binary_no_checksums(tmp_path):
    """Test ensure_binary returns None when no checksums available."""
    with (
        patch("dcert.download._get_install_dir", return_value=tmp_path),
        patch(
            "dcert.download._get_archive_name",
            return_value="dcert-aarch64-apple-darwin.tar.gz",
        ),
        patch("dcert.download._load_checksums", return_value={}),
    ):
        result = ensure_binary("1.0.0")
        assert result is None


def test_ensure_binary_no_checksum_for_platform(tmp_path):
    """Test ensure_binary returns None when no checksum for this platform."""
    checksums = {
        "version": "1.0.0",
        "archives": {"dcert-x86_64-unknown-linux-gnu.tar.gz": "abc123"},
    }

    with (
        patch("dcert.download._get_install_dir", return_value=tmp_path),
        patch("dcert.download._load_checksums", return_value=checksums),
        patch(
            "dcert.download._get_archive_name",
            return_value="dcert-aarch64-apple-darwin.tar.gz",
        ),
    ):
        result = ensure_binary("1.0.0")
        assert result is None


def test_ensure_binary_downloads_and_verifies(tmp_path):
    """Test ensure_binary downloads archive and verifies checksum."""
    # Create a real tar.gz with fake binaries
    archive_content = io.BytesIO()
    with tarfile.open(fileobj=archive_content, mode="w:gz") as tar:
        for name in ["dcert", "dcert-mcp"]:
            data = f"#!/bin/sh\necho {name}".encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    archive_bytes = archive_content.getvalue()

    expected_sha = hashlib.sha256(archive_bytes).hexdigest()
    checksums = {
        "version": "1.0.0",
        "archives": {"dcert-aarch64-apple-darwin.tar.gz": expected_sha},
    }

    with (
        patch("dcert.download._get_install_dir", return_value=tmp_path),
        patch("dcert.download._load_checksums", return_value=checksums),
        patch(
            "dcert.download._get_archive_name",
            return_value="dcert-aarch64-apple-darwin.tar.gz",
        ),
        patch("dcert.download.urllib.request.urlopen", _mock_urlopen(archive_bytes)),
    ):
        result = ensure_binary("1.0.0")

    assert result is not None
    target = Path(result)
    assert target.exists()
    assert target.name == "dcert-mcp"
    assert os.access(str(target), os.X_OK)
    # dcert should also be extracted
    assert (tmp_path / "dcert").exists()


def test_ensure_binary_checksum_mismatch_raises(tmp_path):
    """Test ensure_binary raises on checksum mismatch."""
    checksums = {
        "version": "1.0.0",
        "archives": {"dcert-aarch64-apple-darwin.tar.gz": "expected_hash"},
    }

    with (
        patch("dcert.download._get_install_dir", return_value=tmp_path),
        patch("dcert.download._load_checksums", return_value=checksums),
        patch(
            "dcert.download._get_archive_name",
            return_value="dcert-aarch64-apple-darwin.tar.gz",
        ),
        patch("dcert.download.urllib.request.urlopen", _mock_urlopen(b"tampered content")),
        pytest.raises(RuntimeError, match="Checksum mismatch"),
    ):
        ensure_binary("1.0.0")

    # Verify temp file was cleaned up
    remaining = list(tmp_path.glob(".dcert-*"))
    assert len(remaining) == 0


def test_ensure_binary_download_failure_cleans_up(tmp_path):
    """Test ensure_binary cleans up temp file on download failure."""
    checksums = {
        "version": "1.0.0",
        "archives": {"dcert-aarch64-apple-darwin.tar.gz": "abc123"},
    }

    with (
        patch("dcert.download._get_install_dir", return_value=tmp_path),
        patch("dcert.download._load_checksums", return_value=checksums),
        patch(
            "dcert.download._get_archive_name",
            return_value="dcert-aarch64-apple-darwin.tar.gz",
        ),
        patch(
            "dcert.download.urllib.request.urlopen",
            side_effect=ConnectionError("Network error"),
        ),
        pytest.raises(ConnectionError, match="Network error"),
    ):
        ensure_binary("1.0.0")

    # Verify temp file was cleaned up
    remaining = list(tmp_path.glob(".dcert-*"))
    assert len(remaining) == 0


def test_ensure_binary_url_format(tmp_path):
    """Test ensure_binary constructs correct download URL."""
    archive_content = io.BytesIO()
    with tarfile.open(fileobj=archive_content, mode="w:gz") as tar:
        for name in ["dcert", "dcert-mcp"]:
            data = b"fake"
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    archive_bytes = archive_content.getvalue()

    expected_sha = hashlib.sha256(archive_bytes).hexdigest()
    checksums = {
        "version": "3.0.12",
        "archives": {"dcert-aarch64-apple-darwin.tar.gz": expected_sha},
    }

    captured = {}

    with (
        patch("dcert.download._get_install_dir", return_value=tmp_path),
        patch("dcert.download._load_checksums", return_value=checksums),
        patch(
            "dcert.download._get_archive_name",
            return_value="dcert-aarch64-apple-darwin.tar.gz",
        ),
        patch("dcert.download.urllib.request.urlopen", _mock_urlopen(archive_bytes, captured)),
    ):
        ensure_binary("3.0.12")

    assert captured["url"] == (
        "https://github.com/SCGIS-Wales/dcert/releases/download/"
        "v3.0.12/dcert-aarch64-apple-darwin.tar.gz"
    )


# ---------------------------------------------------------------------------
# CLI --setup flag
# ---------------------------------------------------------------------------


def test_cli_setup_success(tmp_path, capsys):
    """Test CLI --setup downloads binary and exits."""
    from dcert.cli import main

    fake_path = str(tmp_path / "dcert-mcp")

    with (
        patch("sys.argv", ["dcert-python", "--setup"]),
        patch("dcert.download.ensure_binary", return_value=fake_path),
    ):
        main()

    captured = capsys.readouterr()
    assert fake_path in captured.out


def test_cli_setup_no_checksums(capsys):
    """Test CLI --setup exits 1 when no checksums available."""
    from dcert.cli import main

    with (
        patch("sys.argv", ["dcert-python", "--setup"]),
        patch("dcert.download.ensure_binary", return_value=None),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1


def test_cli_setup_download_error(capsys):
    """Test CLI --setup exits 1 on download error."""
    from dcert.cli import main

    with (
        patch("sys.argv", ["dcert-python", "--setup"]),
        patch(
            "dcert.download.ensure_binary",
            side_effect=RuntimeError("Checksum mismatch"),
        ),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()

    assert exc_info.value.code == 1
