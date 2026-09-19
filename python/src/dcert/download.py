"""Download the dcert release archive from GitHub and install its binaries.

Supply chain safeguards:

- Checksums are baked into the wheel (``checksums.json``), never fetched.
- Only ``https`` URLs on the configured hosts are opened, and every redirect
  is validated against the same rule before it is followed.
- The archive is capped at the configured size, checked against the
  ``Content-Length`` header and again while streaming.
- The archive is verified against its SHA256 digest before extraction.
- Archive member names are flattened to their basename so an entry can never
  escape the install directory, and each binary is written to a temporary
  file that is moved into place atomically.
- Concurrent installs are serialised with a lock file.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import sys
import sysconfig
import tarfile
import tempfile
import urllib.request
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import Message
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any, Protocol
from urllib.parse import urlsplit

from dcert.binary import binary_filename, ensure_executable
from dcert.config import PlatformTarget, archive_name_for, find_platform, load_config

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

logger = logging.getLogger(__name__)

CHECKSUMS_PATH = Path(__file__).with_name("checksums.json")


def load_checksums() -> dict[str, Any]:
    """Return the checksums embedded in the package, or an empty mapping."""
    path = Path(__file__).with_name("checksums.json")
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        data = json.load(handle)
    return dict(data) if isinstance(data, dict) else {}


def get_target() -> PlatformTarget | None:
    """Return the platform row for the running machine, if supported."""
    return find_platform(platform.system(), platform.machine())


def get_target_triple() -> str | None:
    """Return the Rust target triple for the running machine, if supported."""
    target = get_target()
    return target.triple if target else None


def get_archive_name() -> str | None:
    """Return the release archive name for the running machine, if supported."""
    target = get_target()
    return archive_name_for(target) if target else None


def get_install_dir() -> Path:
    """Return a writable directory that is normally on ``PATH``.

    Prefers the interpreter's scripts directory (where pip installs console
    scripts) and falls back to ``~/.local/bin``.
    """
    scripts_dir = Path(sysconfig.get_path("scripts"))
    if os.access(scripts_dir, os.W_OK):
        return scripts_dir
    local_bin = Path.home() / ".local" / "bin"
    local_bin.mkdir(parents=True, exist_ok=True)
    return local_bin


def verify_checksum(file_path: Path, expected_sha256: str) -> bool:
    """Return ``True`` when the SHA256 digest of *file_path* matches."""
    with file_path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    return digest == expected_sha256.lower()


def is_allowed_url(url: str, allowed_hosts: tuple[str, ...]) -> bool:
    """Return ``True`` when *url* is ``https`` and on an allowed host."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host:
        return False
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts)


class _ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses redirects off the allowed https hosts."""

    def __init__(self, allowed_hosts: tuple[str, ...]) -> None:
        super().__init__()
        self._allowed_hosts = allowed_hosts

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not is_allowed_url(newurl, self._allowed_hosts):
            raise RuntimeError(f"Refusing redirect to {newurl}: only https on allowed hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(allowed_hosts: tuple[str, ...]) -> urllib.request.OpenerDirector:
    """Return a urllib opener whose redirects are validated."""
    return urllib.request.build_opener(_ValidatingRedirectHandler(allowed_hosts))


class _Response(Protocol):
    """The subset of ``http.client.HTTPResponse`` used while streaming."""

    @property
    def headers(self) -> Message: ...

    def read(self, amt: int | None = None, /) -> bytes: ...


def _content_length(headers: Message) -> int | None:
    """Return the declared ``Content-Length`` or ``None`` when absent or invalid."""
    value = headers.get("Content-Length")
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def stream_to_file(response: _Response, out: IO[bytes], *, max_bytes: int, chunk_size: int) -> int:
    """Copy *response* into *out*, aborting once *max_bytes* is exceeded."""
    declared = _content_length(response.headers)
    if declared is not None and declared > max_bytes:
        raise RuntimeError(f"Download of {declared} bytes exceeds the {max_bytes} byte limit")
    total = 0
    while chunk := response.read(chunk_size):
        total += len(chunk)
        if total > max_bytes:
            raise RuntimeError(f"Download exceeded the {max_bytes} byte limit")
        out.write(chunk)
    return total


def download_to_file(
    url: str,
    out: IO[bytes],
    *,
    timeout: float,
    max_bytes: int,
    chunk_size: int,
    allowed_hosts: tuple[str, ...],
) -> int:
    """Download *url* into *out* with scheme, host and size validation.

    Returns:
        The number of bytes written.

    Raises:
        RuntimeError: If the URL or a redirect is not allowed, or the
            download exceeds *max_bytes*.
    """
    if not is_allowed_url(url, allowed_hosts):
        raise RuntimeError(f"Refusing to download {url}: only https on allowed hosts")
    opener = build_opener(allowed_hosts)
    with opener.open(url, timeout=timeout) as response:
        return stream_to_file(response, out, max_bytes=max_bytes, chunk_size=chunk_size)


def _lock_handle(handle: IO[bytes]) -> None:
    """Take an exclusive lock on *handle*, blocking until it is available."""
    if sys.platform == "win32":
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _unlock_handle(handle: IO[bytes]) -> None:
    """Release the lock taken by :func:`_lock_handle`."""
    if sys.platform == "win32":
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def install_lock(lock_path: Path) -> Iterator[None]:
    """Serialise installs across processes with an exclusive lock file."""
    with lock_path.open("ab") as handle:
        _lock_handle(handle)
        try:
            yield
        finally:
            _unlock_handle(handle)


def _install_member(name: str, source: IO[bytes], install_dir: Path) -> Path:
    """Write one archive member to *install_dir* atomically and mark it executable."""
    target = install_dir / name
    fd, tmp_name = tempfile.mkstemp(dir=install_dir, prefix=f".{name}.")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(source, out)
        ensure_executable(tmp_path)
        os.replace(tmp_path, target)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return target


def _iter_zip_members(archive_path: Path, wanted: set[str]) -> Iterator[tuple[str, IO[bytes]]]:
    """Yield ``(basename, file object)`` for each wanted member of a zip archive."""
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            name = Path(member.filename).name
            if name in wanted:
                with archive.open(member) as handle:
                    yield name, handle


def _iter_tar_members(archive_path: Path, wanted: set[str]) -> Iterator[tuple[str, IO[bytes]]]:
    """Yield ``(basename, file object)`` for each wanted member of a tar.gz archive."""
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            name = Path(member.name).name
            if name not in wanted or not member.isfile():
                continue
            handle = archive.extractfile(member)
            if handle is not None:
                with handle:
                    yield name, handle


def extract_binaries(archive_path: Path, install_dir: Path) -> Path:
    """Install ``dcert`` and ``dcert-mcp`` from a verified archive.

    Member names are flattened to their basename, so a crafted path such as
    ``../../bin/dcert`` cannot escape *install_dir*.

    Returns:
        Path to the installed ``dcert-mcp`` binary.

    Raises:
        RuntimeError: If ``dcert-mcp`` is not present in the archive.
    """
    mcp_name = binary_filename("dcert-mcp")
    wanted = {binary_filename("dcert"), mcp_name}
    members = (
        _iter_zip_members(archive_path, wanted)
        if archive_path.suffix == ".zip"
        else _iter_tar_members(archive_path, wanted)
    )
    installed = {name: _install_member(name, handle, install_dir) for name, handle in members}
    if mcp_name not in installed:
        raise RuntimeError("dcert-mcp binary not found in archive")
    return installed[mcp_name]


def _is_installed(path: Path) -> bool:
    """Return ``True`` when *path* is an executable file."""
    return path.is_file() and os.access(path, os.X_OK)


def _download_and_install(url: str, archive_name: str, expected: str, install_dir: Path) -> Path:
    """Download *url* into *install_dir*, verify it and extract the binaries."""
    cfg = load_config()
    fd, tmp_name = tempfile.mkstemp(dir=install_dir, prefix=".dcert-")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out:
            download_to_file(
                url,
                out,
                timeout=cfg.download.timeout_seconds,
                max_bytes=cfg.download.max_bytes,
                chunk_size=cfg.download.chunk_size,
                allowed_hosts=cfg.release.allowed_hosts,
            )
        if not verify_checksum(tmp_path, expected):
            raise RuntimeError(
                f"Checksum mismatch for {archive_name}. The downloaded archive does not "
                "match the expected hash. This could indicate a tampered download."
            )
        return extract_binaries(tmp_path, install_dir)
    finally:
        tmp_path.unlink(missing_ok=True)


def ensure_binary(version: str) -> str | None:
    """Ensure the ``dcert-mcp`` binary is installed, downloading it if needed.

    Args:
        version: Package version used to build the release URL.

    Returns:
        Absolute path to ``dcert-mcp``, or ``None`` when no download is
        possible for this platform (unsupported, or no embedded checksum).

    Raises:
        RuntimeError: If the archive fails size, redirect or checksum checks.
        OSError: If the download or the file system operations fail.
    """
    cfg = load_config()
    install_dir = get_install_dir()
    target = install_dir / binary_filename("dcert-mcp")
    if _is_installed(target):
        return str(target)

    archive_name = get_archive_name()
    if archive_name is None:
        logger.debug("Unsupported platform %s/%s", platform.system(), platform.machine())
        return None
    expected = load_checksums().get("archives", {}).get(archive_name)
    if not expected:
        logger.debug("No checksum for %s, skipping automatic download", archive_name)
        return None

    url = cfg.release.url_template.format(version=version, archive_name=archive_name)
    with install_lock(install_dir / cfg.download.lock_file_name):
        if _is_installed(target):
            return str(target)
        logger.info("Downloading dcert binaries from %s", url)
        print(f"Downloading dcert binaries from {url}", file=sys.stderr)
        mcp_path = _download_and_install(url, archive_name, expected, install_dir)
        print(f"Installed dcert binaries to {install_dir}", file=sys.stderr)
        logger.info("Installed dcert binaries to %s", install_dir)
        return str(mcp_path)
