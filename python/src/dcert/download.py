"""Auto-download dcert binaries from GitHub Releases.

Downloads the platform-appropriate tar.gz archive, verifies its SHA256
checksum against values embedded in the package (checksums.json), extracts
the ``dcert`` and ``dcert-mcp`` binaries, and installs them to a
PATH-accessible directory.

Supply chain security:
  - Checksums are baked into the wheel at build time, not fetched at runtime.
  - Downloads use HTTPS with certificate verification.
  - Archive is written to a temp file and only extracted after checksum passes.
  - No shell commands or install-time hooks are used.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import stat
import sys
import sysconfig
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

GITHUB_RELEASE_URL = (
    "https://github.com/SCGIS-Wales/dcert/releases/download/v{version}/{archive_name}"
)

# Timeout for the HTTP connection and read (seconds).
DOWNLOAD_TIMEOUT = 60

# Maps (system, machine) to Rust target triple
PLATFORM_MAP: dict[tuple[str, str], str] = {
    ("darwin", "arm64"): "aarch64-apple-darwin",
    ("darwin", "x86_64"): "x86_64-apple-darwin",
    ("linux", "x86_64"): "x86_64-unknown-linux-gnu",
    ("windows", "amd64"): "x86_64-pc-windows-msvc",
}


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _bin_filename(stem: str) -> str:
    """Return the on-disk binary filename for *stem* (adds .exe on Windows)."""
    return f"{stem}.exe" if _is_windows() else stem


def _load_checksums() -> dict:
    """Load embedded checksums from package data.

    Returns:
        Parsed checksums dict, or empty dict if file is missing.
    """
    checksums_path = Path(__file__).parent / "checksums.json"
    if not checksums_path.exists():
        return {}
    with open(checksums_path) as f:
        return json.load(f)


def _get_target_triple() -> str | None:
    """Get the Rust target triple for the current platform.

    Returns:
        Target triple like ``aarch64-apple-darwin``, or ``None`` if
        the platform is not supported.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()
    return PLATFORM_MAP.get((system, machine))


def _get_archive_name() -> str | None:
    """Get the platform-specific archive filename.

    Returns:
        Archive name like ``dcert-aarch64-apple-darwin.tar.gz``,
        or ``None`` if the platform is not supported.
    """
    triple = _get_target_triple()
    if triple is None:
        return None
    # Windows binaries are shipped as .zip (PowerShell-friendly); other
    # platforms use .tar.gz.
    ext = "zip" if _is_windows() else "tar.gz"
    return f"dcert-{triple}.{ext}"


def _get_install_dir() -> Path:
    """Get the best directory for installing the binaries.

    Prefers the Python scripts directory (where pip puts console_scripts,
    which is on PATH). Falls back to ``~/.local/bin``.

    Returns:
        Writable directory path.
    """
    scripts_dir = Path(sysconfig.get_path("scripts"))
    if os.access(str(scripts_dir), os.W_OK):
        return scripts_dir
    # Fallback: user-local bin
    local_bin = Path.home() / ".local" / "bin"
    local_bin.mkdir(parents=True, exist_ok=True)
    return local_bin


def _verify_checksum(file_path: Path, expected_sha256: str) -> bool:
    """Verify SHA256 checksum of a file.

    Args:
        file_path: Path to the file to verify.
        expected_sha256: Expected hex-encoded SHA256 digest.

    Returns:
        True if checksum matches, False otherwise.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest() == expected_sha256


def _extract_binaries(archive_path: Path, install_dir: Path) -> Path:
    """Extract dcert and dcert-mcp binaries from a downloaded archive.

    Handles both .tar.gz (Linux/macOS) and .zip (Windows) archives. On
    Windows the binaries are named ``dcert.exe`` / ``dcert-mcp.exe``.

    Args:
        archive_path: Path to the downloaded .tar.gz or .zip file.
        install_dir: Directory to install binaries into.

    Returns:
        Path to the installed dcert-mcp binary.

    Raises:
        RuntimeError: If the dcert-mcp binary is not found in the archive.
    """
    is_win = _is_windows()
    mcp_name = _bin_filename("dcert-mcp")
    wanted = {_bin_filename("dcert"), mcp_name}
    found_mcp = False

    def _emit(name: str, file_obj) -> None:
        nonlocal found_mcp
        # Write contents manually rather than using extract() to avoid path
        # traversal — member names could contain "../" even after Path.name.
        target = install_dir / name
        with open(target, "wb") as out:
            shutil.copyfileobj(file_obj, out)
        if not is_win:
            target.chmod(target.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        if name == mcp_name:
            found_mcp = True

    if archive_path.suffix == ".zip" or is_win:
        with zipfile.ZipFile(archive_path) as zf:
            for member in zf.infolist():
                name = Path(member.filename).name
                if name in wanted:
                    with zf.open(member) as file_obj:
                        _emit(name, file_obj)
    else:
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                name = Path(member.name).name
                if name in wanted:
                    file_obj = tar.extractfile(member)
                    if file_obj is None:
                        continue
                    _emit(name, file_obj)

    if not found_mcp:
        raise RuntimeError("dcert-mcp binary not found in archive")

    return install_dir / mcp_name


def ensure_binary(version: str) -> str | None:
    """Ensure the dcert-mcp binary is available, downloading if needed.

    If the binary already exists in the install directory and is executable,
    returns its path immediately. Otherwise downloads the platform archive
    from GitHub Releases, verifies the SHA256 checksum, extracts the
    binaries, and installs them.

    Args:
        version: Package version (e.g. ``"3.0.12"``). Used to construct
            the download URL and match against checksums.

    Returns:
        Absolute path to the dcert-mcp binary, or ``None`` if download
        is not possible (e.g. no checksums available for this platform).

    Raises:
        RuntimeError: If the downloaded archive fails checksum verification.
        urllib.error.URLError: If the download fails.
    """
    install_dir = _get_install_dir()
    target = install_dir / _bin_filename("dcert-mcp")

    # Already installed?
    if target.exists() and os.access(str(target), os.X_OK):
        return str(target)

    # Load embedded checksums
    archive_name = _get_archive_name()
    if archive_name is None:
        logger.debug(
            "Unsupported platform %s/%s — skipping auto-download",
            platform.system(),
            platform.machine(),
        )
        return None

    checksums = _load_checksums()
    expected = checksums.get("archives", {}).get(archive_name)
    if not expected:
        logger.debug("No checksum for %s — skipping auto-download", archive_name)
        return None

    url = GITHUB_RELEASE_URL.format(version=version, archive_name=archive_name)
    logger.info("Downloading dcert binaries from %s", url)
    print(
        f"Downloading dcert binaries for {platform.system()}/{platform.machine()}...",
        file=sys.stderr,
    )

    # Download to temp file, verify checksum, then extract
    fd, tmp_path = tempfile.mkstemp(dir=str(install_dir), prefix=".dcert-")
    try:
        os.close(fd)
        with (
            urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as resp,
            open(tmp_path, "wb") as out,
        ):
            shutil.copyfileobj(resp, out)

        if not _verify_checksum(Path(tmp_path), expected):
            raise RuntimeError(
                f"Checksum mismatch for {archive_name}. "
                "The downloaded archive does not match the expected hash. "
                "This could indicate a tampered download."
            )

        # Extract binaries from the verified archive
        mcp_path = _extract_binaries(Path(tmp_path), install_dir)

        print(f"Installed dcert binaries to {install_dir}", file=sys.stderr)
        logger.info("Installed dcert binaries to %s", install_dir)
        return str(mcp_path)
    except Exception:
        # Clean up temp file on any failure
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
