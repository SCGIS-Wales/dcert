"""FastMCP proxy server wrapping the dcert-mcp Rust binary.

The proxy pattern ensures forward-compatibility: when new tools are added
to the Rust binary, they are automatically discovered and exposed by the
proxy without any Python code changes. The MCP protocol handles tool
discovery at runtime via the ``tools/list`` method.
"""

import logging
import os
import platform
import shutil
from pathlib import Path

from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy

logger = logging.getLogger(__name__)

# Environment variables forwarded to the Rust subprocess.
PASSTHROUGH_ENV_VARS: list[str] = [
    # Core system
    "HOME",
    "USER",
    "PATH",
    # Forward proxy
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    # TLS / CA
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    # dcert-mcp specific
    "DCERT_PATH",
    "DCERT_MCP_TIMEOUT",
    "DCERT_MCP_CONNECTION_TIMEOUT",
    "DCERT_MCP_READ_TIMEOUT",
]


def _find_binary() -> str:
    """Locate the dcert-mcp binary.

    Search order:
      1. ``DCERT_MCP_BINARY`` environment variable
      2. Bundled binary in the package ``bin/`` directory
      3. ``dcert-mcp`` on ``PATH``
      4. Auto-download from GitHub Releases (with checksum verification)

    Returns:
        Absolute path to the dcert-mcp executable.

    Raises:
        FileNotFoundError: If the binary cannot be located.
    """
    # 1. Explicit env var
    env_path = os.environ.get("DCERT_MCP_BINARY")
    if env_path:
        p = Path(env_path)
        if p.is_file() and os.access(str(p), os.X_OK):
            logger.debug("Using binary from DCERT_MCP_BINARY: %s", p)
            return str(p)
        raise FileNotFoundError(f"DCERT_MCP_BINARY={env_path} does not exist or is not executable")

    # 2. Bundled binary in package data
    pkg_dir = Path(__file__).parent
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch_map = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64", "amd64": "amd64"}
    arch = arch_map.get(machine, machine)
    binary_name = f"dcert-mcp-{system}-{arch}"
    bundled = pkg_dir / "bin" / binary_name
    if bundled.is_file() and os.access(str(bundled), os.X_OK):
        logger.debug("Using bundled binary: %s", bundled)
        return str(bundled)

    # Also check for plain "dcert-mcp" in bin/
    plain = pkg_dir / "bin" / "dcert-mcp"
    if plain.is_file() and os.access(str(plain), os.X_OK):
        logger.debug("Using bundled binary: %s", plain)
        return str(plain)

    # 3. PATH lookup (before download — platform wheels put the binary on PATH)
    found = shutil.which("dcert-mcp")
    if found:
        logger.debug("Using dcert-mcp from PATH: %s", found)
        return found

    # 4. Auto-download from GitHub Releases (fallback for universal wheel)
    from dcert import __version__
    from dcert.download import ensure_binary

    try:
        downloaded = ensure_binary(__version__)
        if downloaded:
            logger.debug("Using auto-downloaded binary: %s", downloaded)
            return downloaded
    except Exception:
        logger.debug("Auto-download failed, binary not available", exc_info=True)

    raise FileNotFoundError(
        "dcert-mcp binary not found. Either:\n"
        "  1. Set DCERT_MCP_BINARY=/path/to/dcert-mcp\n"
        "  2. Install dcert and ensure dcert-mcp is on your PATH\n"
        "  3. Run: dcert-python --setup"
    )


def _build_subprocess_env(
    extra_env: dict[str, str] | None = None,
    passthrough: list[str] | None = None,
) -> dict[str, str]:
    """Build the environment dict for the Rust subprocess.

    Collects variables from ``PASSTHROUGH_ENV_VARS`` (or a custom list)
    and merges in any extra overrides.

    Args:
        extra_env: Additional variables that take precedence.
        passthrough: Override the default passthrough list.

    Returns:
        Environment dict for subprocess execution.
    """
    vars_to_pass = passthrough or PASSTHROUGH_ENV_VARS
    env: dict[str, str] = {}
    for var in vars_to_pass:
        val = os.environ.get(var)
        if val is not None:
            env[var] = val
    if extra_env:
        env.update(extra_env)
    return env


def create_server(
    binary_path: str | None = None,
    name: str = "dcert-mcp",
    env: dict[str, str] | None = None,
):
    """Create a FastMCP proxy server wrapping the dcert-mcp Rust binary.

    The proxy transparently forwards all MCP requests to the Rust binary,
    which means any new tools added to the binary are automatically
    available without changing this Python code.

    Args:
        binary_path: Explicit path to the dcert-mcp binary. Auto-detected if ``None``.
        name: Server name advertised via MCP.
        env: Additional environment variables to pass to the subprocess.

    Returns:
        A FastMCP server instance ready to run.

    Example::

        server = create_server()
        server.run()                                       # stdio
        server.run(transport="http", host="0.0.0.0", port=8080)  # HTTP
    """
    binary = binary_path or _find_binary()
    subprocess_env = _build_subprocess_env(extra_env=env)
    transport = StdioTransport(
        command=binary,
        args=[],
        env=subprocess_env or None,
    )
    return create_proxy(transport, name=name)
