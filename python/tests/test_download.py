"""Tests for dcert.download."""

import hashlib
import io
import json
import os
import sys
import tarfile
import zipfile
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.response import addinfourl

import pytest

import dcert.download as dl_mod
from dcert.download import (
    build_opener,
    download_to_file,
    ensure_binary,
    extract_binaries,
    get_archive_name,
    get_install_dir,
    get_target_triple,
    install_lock,
    is_allowed_url,
    load_checksums,
    stream_to_file,
    verify_checksum,
)

HOSTS = ("github.com", "githubusercontent.com")
ARCHIVE = "dcert-x86_64-unknown-linux-gnu.tar.gz"


def _make_tar_gz(path: Path, names, data=None) -> bytes:
    """Write a tar.gz with fake binaries to *path* and return its bytes."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name in names:
            payload = data or f"#!/bin/sh\necho {name}".encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(payload))
    path.write_bytes(buffer.getvalue())
    return buffer.getvalue()


def _response(data: bytes, url: str = "https://github.com/x", headers=None):
    message = Message()
    for key, value in (headers or {}).items():
        message[key] = value
    return addinfourl(io.BytesIO(data), message, url)


def _fake_opener(data: bytes, capture: dict | None = None, headers=None):
    """Return an object with the ``open`` method of an OpenerDirector."""

    def open_url(url, timeout=None):
        if capture is not None:
            capture["url"] = url
            capture["timeout"] = timeout
        return _response(data, url, headers)

    return SimpleNamespace(open=open_url)


@pytest.fixture
def install_dir(tmp_path):
    with patch("dcert.download.get_install_dir", return_value=tmp_path):
        yield tmp_path


@pytest.fixture
def linux_platform():
    with (
        patch("dcert.download.platform.system", return_value="Linux"),
        patch("dcert.download.platform.machine", return_value="x86_64"),
    ):
        yield


def _leftovers(directory: Path) -> list[Path]:
    """Temporary download files left behind (the lock file is expected)."""
    lock_name = dl_mod.load_config().download.lock_file_name
    return [p for p in directory.glob(".dcert-*") if p.name != lock_name]


def _checksums(sha: str, archive: str = ARCHIVE) -> dict:
    return {"version": "1.0.0", "archives": {archive: sha}}


# ---------------------------------------------------------------------------
# load_checksums
# ---------------------------------------------------------------------------


def test_load_checksums_packaged():
    result = load_checksums()
    assert isinstance(result, dict)
    assert "archives" in result


def test_load_checksums_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(dl_mod, "__file__", str(tmp_path / "download.py"))
    assert load_checksums() == {}


def test_load_checksums_valid(tmp_path, monkeypatch):
    checksums = _checksums("abc123")
    (tmp_path / "checksums.json").write_text(json.dumps(checksums))
    monkeypatch.setattr(dl_mod, "__file__", str(tmp_path / "download.py"))
    assert load_checksums() == checksums


def test_load_checksums_not_a_mapping(tmp_path, monkeypatch):
    (tmp_path / "checksums.json").write_text("[]")
    monkeypatch.setattr(dl_mod, "__file__", str(tmp_path / "download.py"))
    assert load_checksums() == {}


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("system", "machine", "triple", "archive"),
    [
        ("Darwin", "arm64", "aarch64-apple-darwin", "dcert-aarch64-apple-darwin.tar.gz"),
        ("Darwin", "x86_64", "x86_64-apple-darwin", "dcert-x86_64-apple-darwin.tar.gz"),
        ("Linux", "x86_64", "x86_64-unknown-linux-gnu", ARCHIVE),
        ("Windows", "AMD64", "x86_64-pc-windows-msvc", "dcert-x86_64-pc-windows-msvc.zip"),
    ],
)
def test_target_and_archive(system, machine, triple, archive):
    with (
        patch("dcert.download.platform.system", return_value=system),
        patch("dcert.download.platform.machine", return_value=machine),
    ):
        assert get_target_triple() == triple
        assert get_archive_name() == archive


@pytest.mark.parametrize(("system", "machine"), [("Linux", "aarch64"), ("FreeBSD", "x86_64")])
def test_unsupported_platform(system, machine):
    with (
        patch("dcert.download.platform.system", return_value=system),
        patch("dcert.download.platform.machine", return_value=machine),
    ):
        assert get_target_triple() is None
        assert get_archive_name() is None


# ---------------------------------------------------------------------------
# get_install_dir
# ---------------------------------------------------------------------------


def test_get_install_dir_scripts_writable(tmp_path):
    with patch("dcert.download.sysconfig.get_path", return_value=str(tmp_path)):
        assert get_install_dir() == tmp_path


def test_get_install_dir_scripts_not_writable(tmp_path):
    """Falls back to ~/.local/bin; os.access is patched so root can run this."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    home = tmp_path / "home"
    with (
        patch("dcert.download.sysconfig.get_path", return_value=str(scripts)),
        patch("dcert.download.os.access", return_value=False),
        patch("dcert.download.Path.home", return_value=home),
    ):
        assert get_install_dir() == home / ".local" / "bin"
    assert (home / ".local" / "bin").is_dir()


# ---------------------------------------------------------------------------
# verify_checksum
# ---------------------------------------------------------------------------


def test_verify_checksum_match(tmp_path):
    content = b"hello world binary content"
    path = tmp_path / "binary"
    path.write_bytes(content)
    assert verify_checksum(path, hashlib.sha256(content).hexdigest()) is True
    assert verify_checksum(path, hashlib.sha256(content).hexdigest().upper()) is True


def test_verify_checksum_mismatch(tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(b"actual content")
    assert verify_checksum(path, "0" * 64) is False


def test_verify_checksum_empty_file(tmp_path):
    path = tmp_path / "empty"
    path.write_bytes(b"")
    assert verify_checksum(path, hashlib.sha256(b"").hexdigest()) is True


# ---------------------------------------------------------------------------
# URL validation and redirects
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://github.com/SCGIS-Wales/dcert/releases/download/v1/x.tar.gz", True),
        ("https://objects.githubusercontent.com/abc", True),
        ("http://github.com/x", False),
        ("https://evil.example.com/github.com", False),
        ("https://github.com.evil.example/x", False),
        ("https://notgithub.com/x", False),
        ("ftp://github.com/x", False),
        ("https:///x", False),
    ],
)
def test_is_allowed_url(url, allowed):
    assert is_allowed_url(url, HOSTS) is allowed


def _redirect(handler, newurl):
    request = dl_mod.urllib.request.Request("https://github.com/start")
    return handler.redirect_request(request, io.BytesIO(), 302, "Found", Message(), newurl)


def test_redirect_handler_allows_https_on_allowed_host():
    handler = dl_mod._ValidatingRedirectHandler(HOSTS)
    request = _redirect(handler, "https://objects.githubusercontent.com/asset")
    assert request is not None
    assert request.full_url == "https://objects.githubusercontent.com/asset"


@pytest.mark.parametrize(
    "newurl", ["http://github.com/asset", "https://evil.example.com/asset", "file:///etc/passwd"]
)
def test_redirect_handler_refuses(newurl):
    handler = dl_mod._ValidatingRedirectHandler(HOSTS)
    with pytest.raises(RuntimeError, match="Refusing redirect"):
        _redirect(handler, newurl)


def test_build_opener_installs_validating_handler():
    opener = build_opener(HOSTS)
    assert any(isinstance(h, dl_mod._ValidatingRedirectHandler) for h in opener.handlers)


def test_download_to_file_refuses_disallowed_url(tmp_path):
    out = io.BytesIO()
    with pytest.raises(RuntimeError, match="Refusing to download"):
        download_to_file(
            "http://github.com/x", out, timeout=1, max_bytes=10, chunk_size=4, allowed_hosts=HOSTS
        )


def test_download_to_file_streams(tmp_path):
    out = io.BytesIO()
    capture = {}
    with patch("dcert.download.build_opener", return_value=_fake_opener(b"abcdef", capture)):
        written = download_to_file(
            "https://github.com/x",
            out,
            timeout=7,
            max_bytes=100,
            chunk_size=4,
            allowed_hosts=HOSTS,
        )
    assert written == 6
    assert out.getvalue() == b"abcdef"
    assert capture == {"url": "https://github.com/x", "timeout": 7}


# ---------------------------------------------------------------------------
# Size cap
# ---------------------------------------------------------------------------


def test_stream_to_file_within_limit():
    out = io.BytesIO()
    assert stream_to_file(_response(b"x" * 10), out, max_bytes=10, chunk_size=3) == 10
    assert out.getvalue() == b"x" * 10


def test_stream_to_file_rejects_large_content_length():
    out = io.BytesIO()
    response = _response(b"x", headers={"Content-Length": "1000"})
    with pytest.raises(RuntimeError, match="exceeds the 10 byte limit"):
        stream_to_file(response, out, max_bytes=10, chunk_size=4)
    assert out.getvalue() == b""


def test_stream_to_file_ignores_invalid_content_length():
    out = io.BytesIO()
    response = _response(b"abc", headers={"Content-Length": "many"})
    assert stream_to_file(response, out, max_bytes=10, chunk_size=4) == 3


def test_stream_to_file_aborts_when_body_exceeds_limit():
    out = io.BytesIO()
    with pytest.raises(RuntimeError, match="exceeded the 10 byte limit"):
        stream_to_file(_response(b"x" * 11), out, max_bytes=10, chunk_size=4)
    assert len(out.getvalue()) <= 10


# ---------------------------------------------------------------------------
# Lock file
# ---------------------------------------------------------------------------


def test_install_lock_creates_file_and_releases(tmp_path):
    lock_path = tmp_path / ".lock"
    with install_lock(lock_path):
        assert lock_path.exists()
    with install_lock(lock_path):
        pass


@pytest.mark.skipif(sys.platform == "win32", reason="fcntl is POSIX only")
def test_install_lock_is_exclusive(tmp_path):
    import fcntl

    lock_path = tmp_path / ".lock"
    with (
        install_lock(lock_path),
        lock_path.open("ab") as other,
        pytest.raises(BlockingIOError),
    ):
        fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    with lock_path.open("ab") as other:
        fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(other.fileno(), fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# extract_binaries
# ---------------------------------------------------------------------------


def test_extract_binaries_success(tmp_path):
    archive = tmp_path / "test.tar.gz"
    _make_tar_gz(archive, ["dcert", "dcert-mcp"])
    install = tmp_path / "install"
    install.mkdir()
    assert extract_binaries(archive, install) == install / "dcert-mcp"
    for name in ("dcert", "dcert-mcp"):
        assert os.access(install / name, os.X_OK)
    assert not list(install.glob(".*"))


def test_extract_binaries_missing_mcp(tmp_path):
    archive = tmp_path / "test.tar.gz"
    _make_tar_gz(archive, ["dcert"])
    install = tmp_path / "install"
    install.mkdir()
    with pytest.raises(RuntimeError, match="dcert-mcp binary not found"):
        extract_binaries(archive, install)


def test_extract_binaries_flattens_member_names(tmp_path):
    archive = tmp_path / "test.tar.gz"
    _make_tar_gz(archive, ["release/dcert", "../../escape/dcert-mcp"])
    install = tmp_path / "install"
    install.mkdir()
    assert extract_binaries(archive, install) == install / "dcert-mcp"
    assert (install / "dcert").exists()
    assert not (tmp_path / "escape").exists()


def test_extract_binaries_skips_directories(tmp_path):
    archive = tmp_path / "test.tar.gz"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        directory = tarfile.TarInfo(name="dcert-mcp")
        directory.type = tarfile.DIRTYPE
        tar.addfile(directory)
    archive.write_bytes(buffer.getvalue())
    install = tmp_path / "install"
    install.mkdir()
    with pytest.raises(RuntimeError, match="dcert-mcp binary not found"):
        extract_binaries(archive, install)


def test_extract_binaries_zip(tmp_path):
    archive = tmp_path / "dcert-x86_64-pc-windows-msvc.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("dcert", b"MZdcert")
        zf.writestr("sub/dcert-mcp", b"MZmcp")
        zf.writestr("README.md", b"docs")
    install = tmp_path / "install"
    install.mkdir()
    assert extract_binaries(archive, install) == install / "dcert-mcp"
    assert (install / "dcert-mcp").read_bytes() == b"MZmcp"
    assert not (install / "README.md").exists()


def test_extract_binaries_atomic_replace(tmp_path):
    """An existing binary is replaced in one step and no temp file is left."""
    archive = tmp_path / "test.tar.gz"
    _make_tar_gz(archive, ["dcert", "dcert-mcp"], data=b"new")
    install = tmp_path / "install"
    install.mkdir()
    (install / "dcert-mcp").write_bytes(b"old")
    extract_binaries(archive, install)
    assert (install / "dcert-mcp").read_bytes() == b"new"
    assert not list(install.glob(".dcert-mcp.*"))


def test_install_member_cleans_temp_on_failure(tmp_path):
    def broken_read(_size=-1):
        raise OSError("disk full")

    with pytest.raises(OSError, match="disk full"):
        dl_mod._install_member("dcert-mcp", SimpleNamespace(read=broken_read), tmp_path)
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# ensure_binary
# ---------------------------------------------------------------------------


def test_ensure_binary_already_installed(install_dir):
    target = install_dir / "dcert-mcp"
    target.write_text("#!/bin/sh\necho hello")
    target.chmod(0o755)
    assert ensure_binary("1.0.0") == str(target)


def test_ensure_binary_unsupported_platform(install_dir):
    with patch("dcert.download.get_archive_name", return_value=None):
        assert ensure_binary("1.0.0") is None


def test_ensure_binary_no_checksums(install_dir, linux_platform):
    with patch("dcert.download.load_checksums", return_value={}):
        assert ensure_binary("1.0.0") is None


def test_ensure_binary_no_checksum_for_platform(install_dir, linux_platform):
    other = _checksums("abc123", archive="dcert-aarch64-apple-darwin.tar.gz")
    with patch("dcert.download.load_checksums", return_value=other):
        assert ensure_binary("1.0.0") is None


def test_ensure_binary_downloads_and_verifies(install_dir, linux_platform, capsys):
    archive_bytes = _make_tar_gz(install_dir / "unused.tar.gz", ["dcert", "dcert-mcp"])
    (install_dir / "unused.tar.gz").unlink()
    checksums = _checksums(hashlib.sha256(archive_bytes).hexdigest())
    capture = {}
    with (
        patch("dcert.download.load_checksums", return_value=checksums),
        patch("dcert.download.build_opener", return_value=_fake_opener(archive_bytes, capture)),
    ):
        result = ensure_binary("3.0.12")
    assert result == str(install_dir / "dcert-mcp")
    assert os.access(install_dir / "dcert-mcp", os.X_OK)
    assert os.access(install_dir / "dcert", os.X_OK)
    assert capture["url"] == (
        "https://github.com/SCGIS-Wales/dcert/releases/download/v3.0.12/" + ARCHIVE
    )
    assert _leftovers(install_dir) == []
    assert "Installed dcert binaries" in capsys.readouterr().err


def test_ensure_binary_checksum_mismatch_raises(install_dir, linux_platform):
    with (
        patch("dcert.download.load_checksums", return_value=_checksums("0" * 64)),
        patch("dcert.download.build_opener", return_value=_fake_opener(b"tampered content")),
        pytest.raises(RuntimeError, match="Checksum mismatch"),
    ):
        ensure_binary("1.0.0")
    assert _leftovers(install_dir) == []
    assert not (install_dir / "dcert-mcp").exists()


def test_ensure_binary_size_cap(install_dir, linux_platform):
    oversized = _fake_opener(b"x", headers={"Content-Length": str(10**12)})
    with (
        patch("dcert.download.load_checksums", return_value=_checksums("0" * 64)),
        patch("dcert.download.build_opener", return_value=oversized),
        pytest.raises(RuntimeError, match="exceeds"),
    ):
        ensure_binary("1.0.0")
    assert _leftovers(install_dir) == []


def test_ensure_binary_download_failure_cleans_up(install_dir, linux_platform):
    def failing_open(_url, timeout=None):
        raise ConnectionError("Network error")

    with (
        patch("dcert.download.load_checksums", return_value=_checksums("abc")),
        patch("dcert.download.build_opener", return_value=SimpleNamespace(open=failing_open)),
        pytest.raises(ConnectionError, match="Network error"),
    ):
        ensure_binary("1.0.0")
    assert _leftovers(install_dir) == []


def test_ensure_binary_rechecks_after_lock(install_dir, linux_platform):
    """A concurrent installer that finished first short circuits the download."""
    target = install_dir / "dcert-mcp"

    def install_while_locked(*_args, **_kwargs):
        target.write_text("#!/bin/sh\necho hello")
        target.chmod(0o755)
        return _fake_opener(b"never used")

    with (
        patch("dcert.download.load_checksums", return_value=_checksums("abc")),
        patch("dcert.download.build_opener", side_effect=install_while_locked) as opener,
        patch("dcert.download._is_installed", side_effect=[False, True]),
    ):
        assert ensure_binary("1.0.0") == str(target)
    opener.assert_not_called()
