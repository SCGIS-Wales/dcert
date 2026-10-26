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

from dcert import download as dl_mod
from dcert.config import load_config
from dcert.download import (
    IntegrityError,
    build_opener,
    download_to_file,
    ensure_binary,
    extract_binaries,
    get_archive_name,
    get_install_dir,
    get_target,
    install_lock,
    is_allowed_url,
    iter_archive_members,
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


def test_load_checksums_missing(tmp_path):
    assert load_checksums(tmp_path / "checksums.json") == {}


def test_load_checksums_valid(tmp_path):
    checksums = _checksums("abc123")
    path = tmp_path / "checksums.json"
    path.write_text(json.dumps(checksums))
    assert load_checksums(path) == checksums


def test_load_checksums_without_archives(tmp_path):
    path = tmp_path / "checksums.json"
    path.write_text('{"version": "1.0.0"}')
    assert load_checksums(path) == {"version": "1.0.0"}


@pytest.mark.parametrize(
    "content", ["[]", '{"archives": []}', '{"archives": {"a.tar.gz": 1}}', '{"archives": {1: "x"}}']
)
def test_load_checksums_malformed(tmp_path, content):
    path = tmp_path / "checksums.json"
    path.write_text(content.replace("{1:", '{"1":') if "{1:" in content else content)
    if content == '{"archives": {1: "x"}}':
        return  # JSON keys are always strings; nothing to test beyond the parse.
    with pytest.raises(RuntimeError, match="malformed"):
        load_checksums(path)


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
        target = get_target()
        assert target is not None
        assert target.triple == triple
        assert get_archive_name() == archive


@pytest.mark.parametrize(("system", "machine"), [("Linux", "aarch64"), ("FreeBSD", "x86_64")])
def test_unsupported_platform(system, machine):
    with (
        patch("dcert.download.platform.system", return_value=system),
        patch("dcert.download.platform.machine", return_value=machine),
    ):
        assert get_target() is None
        assert get_archive_name() is None


# ---------------------------------------------------------------------------
# get_install_dir
# ---------------------------------------------------------------------------


def test_get_install_dir_default_is_owned_by_dcert(tmp_path, clean_env, monkeypatch):
    """The default lives under the home directory, never in pip's scripts directory."""
    monkeypatch.setenv("HOME", str(tmp_path))
    with patch("dcert.download.platform.system", return_value="Linux"):
        install_dir = get_install_dir()
    assert install_dir == tmp_path / ".local" / "share" / "dcert" / "bin"
    assert install_dir.is_dir()
    assert Path(sys.prefix) not in install_dir.parents


def test_get_install_dir_windows_uses_localappdata(tmp_path, clean_env, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    with patch("dcert.download.platform.system", return_value="Windows"):
        assert get_install_dir() == tmp_path / "AppData" / "Local" / "dcert" / "bin"


def test_get_install_dir_env_override(tmp_path, clean_env, monkeypatch):
    monkeypatch.setenv(load_config().install.env_override, str(tmp_path / "custom"))
    assert get_install_dir() == tmp_path / "custom"
    assert (tmp_path / "custom").is_dir()


def test_get_install_dir_rejects_relative_result(clean_env, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    with (
        patch("dcert.download.platform.system", return_value="Windows"),
        pytest.raises(RuntimeError, match="not absolute.*DCERT_INSTALL_DIR"),
    ):
        get_install_dir()


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
    with pytest.raises(IntegrityError, match="Refusing redirect"):
        _redirect(handler, newurl)


def test_integrity_error_is_a_runtime_error():
    assert issubclass(IntegrityError, RuntimeError)


def test_build_opener_installs_validating_handler():
    opener = build_opener(HOSTS)
    assert any(isinstance(h, dl_mod._ValidatingRedirectHandler) for h in opener.handlers)


def test_download_to_file_refuses_disallowed_url(tmp_path):
    out = io.BytesIO()
    with pytest.raises(IntegrityError, match="Refusing to download"):
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
    with pytest.raises(IntegrityError, match="exceeds the 10 byte limit"):
        stream_to_file(response, out, max_bytes=10, chunk_size=4)
    assert out.getvalue() == b""


def test_stream_to_file_enforces_total_deadline():
    clock = iter([0.0, 1.0, 2.5, 4.0, 6.0])
    out = io.BytesIO()
    with pytest.raises(TimeoutError, match="exceeded the 3.0 second limit"):
        stream_to_file(
            _response(b"x" * 100),
            out,
            max_bytes=1000,
            chunk_size=10,
            max_seconds=3.0,
            clock=lambda: next(clock),
        )
    assert len(out.getvalue()) < 100


def test_download_to_file_forwards_deadline():
    seen = {}

    def fake_stream(_response, _out, **kwargs):
        seen.update(kwargs)
        return 0

    with (
        patch("dcert.download.build_opener", return_value=_fake_opener(b"")),
        patch("dcert.download.stream_to_file", side_effect=fake_stream),
    ):
        download_to_file(
            "https://github.com/x",
            io.BytesIO(),
            timeout=1,
            max_bytes=10,
            chunk_size=4,
            allowed_hosts=HOSTS,
            max_seconds=42.0,
        )
    assert seen["max_seconds"] == 42.0


def test_stream_to_file_ignores_invalid_content_length():
    out = io.BytesIO()
    response = _response(b"abc", headers={"Content-Length": "many"})
    assert stream_to_file(response, out, max_bytes=10, chunk_size=4) == 3


def test_stream_to_file_aborts_when_body_exceeds_limit():
    out = io.BytesIO()
    with pytest.raises(IntegrityError, match="exceeded the 10 byte limit"):
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


def test_lock_handle_polls_until_acquired(tmp_path):
    """Windows cannot block indefinitely, so the lock is retried with a sleep between tries."""
    sleeps = []
    with (
        patch("dcert.download._try_lock", side_effect=[False, False, True]) as try_lock,
        (tmp_path / ".lock").open("ab") as handle,
    ):
        dl_mod._lock_handle(handle, poll_seconds=0.25, sleep=sleeps.append)
    assert try_lock.call_count == 3
    assert sleeps == [0.25, 0.25]


def test_install_lock_poll_interval_from_config(tmp_path):
    with patch("dcert.download._lock_handle") as lock_handle, install_lock(tmp_path / ".lock"):
        pass
    assert lock_handle.call_args.kwargs == {
        "poll_seconds": load_config().download.lock_poll_seconds
    }


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


def test_extract_binaries_zip_skips_directory_entries(tmp_path):
    archive = tmp_path / "dcert-x86_64-pc-windows-msvc.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("dcert-mcp/", b"")
        zf.writestr("dcert/", b"")
    install = tmp_path / "install"
    install.mkdir()
    with pytest.raises(RuntimeError, match="dcert-mcp binary not found"):
        extract_binaries(archive, install)
    assert list(install.iterdir()) == []


def test_iter_archive_members_dispatches_on_extension(tmp_path):
    tar = tmp_path / "a.tar.gz"
    _make_tar_gz(tar, ["dcert-mcp"], data=b"tar")
    zipped = tmp_path / "a.zip"
    with zipfile.ZipFile(zipped, "w") as zf:
        zf.writestr("nested/dcert-mcp", b"zip")
    assert [(n, h.read()) for n, h in iter_archive_members(tar, {"dcert-mcp"})] == [
        ("dcert-mcp", b"tar")
    ]
    assert [(n, h.read()) for n, h in iter_archive_members(zipped, {"dcert-mcp"})] == [
        ("dcert-mcp", b"zip")
    ]


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


def test_ensure_binary_ignores_console_script_wrapper(install_dir, linux_platform):
    """pip's wrapper must never count as the installed binary (it would exec itself)."""
    target = install_dir / "dcert-mcp"
    target.write_text("#!/usr/bin/env python3\nfrom dcert.cli import dcert_mcp_main\n")
    target.chmod(0o755)
    archive_bytes = _make_tar_gz(install_dir / "unused.tar.gz", ["dcert", "dcert-mcp"])
    (install_dir / "unused.tar.gz").unlink()
    checksums = _checksums(hashlib.sha256(archive_bytes).hexdigest())
    with (
        patch("dcert.download.load_checksums", return_value=checksums),
        patch("dcert.download.build_opener", return_value=_fake_opener(archive_bytes)),
    ):
        assert ensure_binary("1.0.0") == str(target)
    assert target.read_bytes().startswith(b"#!/bin/sh")


def test_ensure_binary_ignores_running_launcher(install_dir):
    target = install_dir / "dcert-mcp"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    target.chmod(0o755)
    with patch("dcert.download.sys.argv", [str(target)]):
        assert dl_mod._is_installed(target) is False
    assert dl_mod._is_installed(target) is True


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


def test_ensure_binary_downloads_and_verifies(install_dir, linux_platform, capsys, caplog):
    archive_bytes = _make_tar_gz(install_dir / "unused.tar.gz", ["dcert", "dcert-mcp"])
    (install_dir / "unused.tar.gz").unlink()
    checksums = _checksums(hashlib.sha256(archive_bytes).hexdigest())
    capture = {}
    messages = []
    with (
        caplog.at_level("INFO", logger="dcert.download"),
        patch("dcert.download.load_checksums", return_value=checksums),
        patch("dcert.download.build_opener", return_value=_fake_opener(archive_bytes, capture)),
    ):
        result = ensure_binary("3.0.12", notify=messages.append)
    assert result == str(install_dir / "dcert-mcp")
    assert os.access(install_dir / "dcert-mcp", os.X_OK)
    assert os.access(install_dir / "dcert", os.X_OK)
    assert capture["url"] == (
        "https://github.com/SCGIS-Wales/dcert/releases/download/v3.0.12/" + ARCHIVE
    )
    assert _leftovers(install_dir) == []
    # The library never prints; progress goes to the log and the notify hook.
    assert capsys.readouterr() == ("", "")
    assert [m.split(" ")[0] for m in messages] == ["Downloading", "Installed"]
    assert "Installed dcert binaries" in caplog.text


def test_ensure_binary_checksum_mismatch_raises(install_dir, linux_platform):
    with (
        patch("dcert.download.load_checksums", return_value=_checksums("0" * 64)),
        patch("dcert.download.build_opener", return_value=_fake_opener(b"tampered content")),
        pytest.raises(IntegrityError, match="Checksum mismatch"),
    ):
        ensure_binary("1.0.0")
    assert _leftovers(install_dir) == []
    assert not (install_dir / "dcert-mcp").exists()


def test_ensure_binary_size_cap(install_dir, linux_platform):
    oversized = _fake_opener(b"x", headers={"Content-Length": str(10**12)})
    with (
        patch("dcert.download.load_checksums", return_value=_checksums("0" * 64)),
        patch("dcert.download.build_opener", return_value=oversized),
        pytest.raises(IntegrityError, match="exceeds"),
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
        patch("dcert.download.is_current", side_effect=[False, True]),
    ):
        assert ensure_binary("1.0.0") == str(target)
    opener.assert_not_called()


# ---------------------------------------------------------------------------
# Binary freshness (install record)
# ---------------------------------------------------------------------------


def _install(install_dir, version="1.0.0", payload=None):
    """Run ensure_binary against a fake release; return (checksums, opener mock)."""
    archive_bytes = _make_tar_gz(install_dir / "a.tar.gz", ["dcert", "dcert-mcp"], payload)
    (install_dir / "a.tar.gz").unlink()
    checksums = _checksums(hashlib.sha256(archive_bytes).hexdigest())
    with (
        patch("dcert.download.load_checksums", return_value=checksums),
        patch("dcert.download.build_opener", return_value=_fake_opener(archive_bytes)) as opener,
    ):
        ensure_binary(version)
    return checksums, opener


def test_install_record_describes_the_install(install_dir, linux_platform):
    checksums, _ = _install(install_dir, "2.0.0")
    record = dl_mod.read_install_record(install_dir)
    assert record["version"] == "2.0.0"
    assert record["archive"] == ARCHIVE
    assert record["archive_sha256"] == checksums["archives"][ARCHIVE]
    assert record["binaries"]["dcert-mcp"] == dl_mod.file_sha256(install_dir / "dcert-mcp")
    assert _leftovers(install_dir) == []


def test_a_current_install_is_not_downloaded_again(install_dir, linux_platform):
    checksums, _ = _install(install_dir, "2.0.0")
    with (
        patch("dcert.download.load_checksums", return_value=checksums),
        patch("dcert.download.build_opener") as opener,
    ):
        assert ensure_binary("2.0.0") == str(install_dir / "dcert-mcp")
    opener.assert_not_called()


def test_a_new_package_version_downloads_again(install_dir, linux_platform):
    _install(install_dir, "2.0.0")
    _, opener = _install(install_dir, "2.0.1")
    opener.assert_called_once()
    assert dl_mod.read_install_record(install_dir)["version"] == "2.0.1"


def test_a_modified_binary_downloads_again(install_dir, linux_platform):
    checksums, _ = _install(install_dir, "2.0.0")
    (install_dir / "dcert-mcp").write_text("#!/bin/sh\necho tampered")
    assert not dl_mod.is_current(
        install_dir / "dcert-mcp", install_dir, "2.0.0", checksums["archives"][ARCHIVE]
    )


def test_a_changed_embedded_checksum_downloads_again(install_dir, linux_platform):
    checksums, _ = _install(install_dir, "2.0.0")
    target = install_dir / "dcert-mcp"
    assert dl_mod.is_current(target, install_dir, "2.0.0", checksums["archives"][ARCHIVE])
    assert not dl_mod.is_current(target, install_dir, "2.0.0", "f" * 64)


def test_an_unreadable_install_record_is_not_current(install_dir):
    dl_mod.install_record_path(install_dir).write_text("not json")
    assert dl_mod.read_install_record(install_dir) is None
    target = install_dir / "dcert-mcp"
    target.write_text("#!/bin/sh\necho x")
    target.chmod(0o755)
    assert not dl_mod.is_current(target, install_dir, "1.0.0", "0" * 64)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_install_dir_is_created_private(tmp_path, clean_env, monkeypatch):
    created = tmp_path / "fresh" / "bin"
    monkeypatch.setenv(load_config().install.env_override, str(created))
    assert get_install_dir() == created
    assert created.stat().st_mode & 0o777 == 0o700
