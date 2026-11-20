"""Locate the Rust ``dcert-mcp`` binary.

The search order for :func:`find_binary` is:

1. An explicit path from the environment (``DCERT_MCP_BINARY``; see
   ``config.yaml``).
2. A compiled binary on ``PATH``. The ``dcert-mcp`` wheel installs it there, as
   a script that is the Rust executable itself, so no Python wrapper is in the
   way. Pip generated console script wrappers are skipped so the proxy can
   never exec itself in a loop.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

from dcert_mcp.config import load_config

logger = logging.getLogger(__name__)


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


def find_binary(name: str) -> str:
    """Return the absolute path to the Rust binary *name*.

    Args:
        name: ``dcert`` or ``dcert-mcp``.

    Raises:
        FileNotFoundError: If no usable binary can be located.
    """
    for locate in (_explicit_binary, _path_binary):
        found = locate(name)
        if found:
            logger.debug("Resolved %s to %s", name, found)
            return found
    binaries = load_config().binaries
    variable = binaries.env.get(name, binaries.fallback_env)
    raise FileNotFoundError(
        f"{name} binary not found. Either:\n"
        f"  1. Set {variable}=/path/to/{name}\n"
        f"  2. Reinstall the package: pip install --force-reinstall dcert-mcp"
    )
