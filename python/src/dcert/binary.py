"""Locate the Rust ``dcert`` and ``dcert-mcp`` binaries.

The search order for :func:`find_binary` is:

1. An explicit path from the environment (``DCERT_MCP_BINARY`` for
   ``dcert-mcp``, ``DCERT_PATH`` for ``dcert``; see ``config.yaml``).
2. A binary bundled in the package ``bin/`` directory (``.exe`` on Windows).
3. A compiled binary on ``PATH``, skipping pip console-script wrappers so the
   universal wheel can never exec itself in a loop.
4. An automatic download from GitHub Releases with checksum verification.
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
from pathlib import Path

from dcert.config import load_config

logger = logging.getLogger(__name__)

_EXECUTABLE_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def is_python_script(path: str) -> bool:
    """Return ``True`` when *path* is a Python console-script wrapper.

    Reads the first 128 bytes; a file starting with ``#!`` whose first line
    mentions ``python`` is a pip generated wrapper, not a compiled binary.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(128)
    except OSError:
        return False
    first_line = head.split(b"\n", 1)[0].lower()
    return head[:2] == b"#!" and b"python" in first_line


def ensure_executable(path: Path) -> bool:
    """Make *path* executable if it is not already.

    pip does not always preserve file modes for package data, so a bundled
    binary may land without its execute bits.

    Returns:
        ``True`` when the file is executable afterwards, ``False`` otherwise.
    """
    if os.access(path, os.X_OK):
        return True
    try:
        path.chmod(path.stat().st_mode | _EXECUTABLE_BITS)
    except OSError:
        logger.debug("Cannot make %s executable", path, exc_info=True)
        return False
    return os.access(path, os.X_OK)


def binary_filename(name: str) -> str:
    """Return the on-disk filename for *name* on this platform."""
    return f"{name}.exe" if sys.platform == "win32" and not name.endswith(".exe") else name


def find_bundled_binary(name: str) -> str | None:
    """Return the path to ``bin/<name>`` inside the package, if present."""
    bundled = Path(__file__).parent / "bin" / binary_filename(name)
    if not bundled.is_file() or not ensure_executable(bundled):
        return None
    return str(bundled)


def _explicit_binary(name: str) -> str | None:
    """Return the binary named by its environment variable, if any is set."""
    variable = load_config().binaries.get(name)
    value = os.environ.get(variable, "") if variable else ""
    if not value:
        return None
    candidate = Path(value)
    if candidate.is_file() and os.access(candidate, os.X_OK):
        logger.debug("Using %s from %s: %s", name, variable, candidate)
        return str(candidate)
    raise FileNotFoundError(f"{variable}={value} does not exist or is not executable")


def _path_binary(name: str) -> str | None:
    """Return a compiled *name* on ``PATH``, skipping Python wrappers."""
    found = shutil.which(name)
    if found and not is_python_script(found):
        return found
    return None


def _downloaded_binary(name: str) -> str | None:
    """Download the release archive and return the installed *name*.

    Raises:
        RuntimeError: When the download fails integrity verification; this is
            a tamper indicator and is never masked.
    """
    from dcert import __version__
    from dcert.download import ensure_binary, get_install_dir

    try:
        installed = ensure_binary(__version__)
    except RuntimeError as exc:
        raise RuntimeError(f"{name} download failed integrity verification: {exc}") from exc
    except OSError as exc:
        logger.warning("Automatic download of %s failed: %s", name, exc)
        return None
    if installed is None:
        return None
    candidate = get_install_dir() / binary_filename(name)
    if candidate.is_file() and ensure_executable(candidate):
        return str(candidate)
    return None


def find_binary(name: str) -> str:
    """Return the absolute path to the Rust binary *name*.

    Raises:
        FileNotFoundError: If no usable binary can be located.
        RuntimeError: If a downloaded archive fails checksum verification.
    """
    for locate in (_explicit_binary, find_bundled_binary, _path_binary, _downloaded_binary):
        found = locate(name)
        if found:
            logger.debug("Resolved %s to %s", name, found)
            return found
    variable = load_config().binaries.get(name, "DCERT_MCP_BINARY")
    raise FileNotFoundError(
        f"{name} binary not found. Either:\n"
        f"  1. Set {variable}=/path/to/{name}\n"
        f"  2. Install dcert and ensure {name} is on your PATH\n"
        "  3. Run: dcert-python --setup"
    )
