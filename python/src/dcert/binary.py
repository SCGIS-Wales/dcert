"""Locate the Rust ``dcert`` and ``dcert-mcp`` binaries.

The search order for :func:`find_binary` is:

1. An explicit path from the environment (``DCERT_MCP_BINARY`` for
   ``dcert-mcp``, ``DCERT_PATH`` for ``dcert``; see ``config.yaml``).
2. A binary bundled in the package ``bin/`` directory (``.exe`` on Windows).
3. A compiled binary on ``PATH``, skipping console script wrappers so the
   universal wheel can never exec itself in a loop.
4. An automatic download from GitHub Releases with checksum verification,
   installed into a directory owned by dcert rather than by pip.
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

from dcert.config import load_config

logger = logging.getLogger(__name__)

_EXECUTABLE_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH

#: Receives progress messages meant for a person, such as "Downloading ...".
Notify = Callable[[str], None]


def is_python_script(path: str) -> bool:
    """Return ``True`` when *path* is a Python console-script wrapper.

    Reads the configured number of leading bytes; a file starting with
    ``#!`` whose first line mentions ``python`` is a pip generated wrapper,
    not a compiled binary.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(load_config().binaries.wrapper_probe_bytes)
    except OSError:
        return False
    first_line = head.split(b"\n", 1)[0].lower()
    return head[:2] == b"#!" and b"python" in first_line


def is_running_script(path: str) -> bool:
    """Return ``True`` when *path* is the script the interpreter is running.

    On Windows pip installs a native ``.exe`` launcher that runs Python on
    itself, so ``sys.argv[0]`` is that launcher; comparing by file identity
    catches it where :func:`is_python_script` cannot.
    """
    argv0 = sys.argv[0] if sys.argv else ""
    if not argv0:
        return False
    try:
        return os.path.samefile(path, argv0)
    except (OSError, ValueError):
        return False


def is_wrapper(path: str) -> bool:
    """Return ``True`` when *path* is a console script wrapper rather than a binary."""
    return is_python_script(path) or is_running_script(path)


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
    """Return the binary named by its environment variable, if any is set.

    The value is made absolute so it can never be resolved through ``PATH``.
    """
    variable = load_config().binaries.env.get(name)
    value = os.environ.get(variable, "") if variable else ""
    if not value:
        return None
    candidate = Path(value).expanduser().resolve()
    if candidate.is_file() and os.access(candidate, os.X_OK):
        logger.debug("Using %s from %s: %s", name, variable, candidate)
        return str(candidate)
    raise FileNotFoundError(f"{variable}={value} does not exist or is not executable")


def _path_binary(name: str) -> str | None:
    """Return a compiled *name* on ``PATH``, skipping console script wrappers."""
    found = shutil.which(name)
    if found and not is_wrapper(found):
        return found
    return None


def _downloaded_binary(name: str, notify: Notify | None = None) -> str | None:
    """Download the release archive and return the installed *name*.

    Raises:
        IntegrityError: When the download fails a supply chain check; this
            is a tamper indicator and is never masked.
    """
    from dcert import __version__
    from dcert.download import IntegrityError, ensure_binary, get_install_dir

    try:
        installed = ensure_binary(__version__, notify=notify)
    except IntegrityError as exc:
        raise IntegrityError(f"{name} download failed integrity verification: {exc}") from exc
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        logger.warning("Automatic download of %s failed: %s", name, exc)
        return None
    if installed is None:
        return None
    candidate = get_install_dir() / binary_filename(name)
    if candidate.is_file() and ensure_executable(candidate):
        return str(candidate)
    return None


def find_binary(name: str, notify: Notify | None = None) -> str:
    """Return the absolute path to the Rust binary *name*.

    Args:
        name: ``dcert`` or ``dcert-mcp``.
        notify: Receives progress messages when a download is needed.

    Raises:
        FileNotFoundError: If no usable binary can be located.
        RuntimeError: If a downloaded archive fails verification or is malformed.
    """
    for locate in (_explicit_binary, find_bundled_binary, _path_binary):
        found = locate(name)
        if found:
            logger.debug("Resolved %s to %s", name, found)
            return found
    downloaded = _downloaded_binary(name, notify)
    if downloaded:
        logger.debug("Resolved %s to %s", name, downloaded)
        return downloaded
    binaries = load_config().binaries
    variable = binaries.env.get(name, binaries.fallback_env)
    raise FileNotFoundError(
        f"{name} binary not found. Either:\n"
        f"  1. Set {variable}=/path/to/{name}\n"
        f"  2. Install dcert and ensure {name} is on your PATH\n"
        "  3. Run: dcert-python --setup"
    )
