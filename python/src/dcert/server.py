"""FastMCP proxy server wrapping the ``dcert-mcp`` Rust binary.

The proxy forwards every MCP request to the Rust binary, so tools added
there are discovered at runtime without Python changes.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Mapping

from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy
from fastmcp.server.providers.proxy import FastMCPProxy

from dcert.binary import find_binary
from dcert.config import load_config
from dcert.middleware import build_middleware
from dcert.resilience import ResilienceConfig, resilience_config_from_env

logger = logging.getLogger(__name__)

#: Environment variables forwarded to the Rust subprocess (from config.yaml).
PASSTHROUGH_ENV_VARS: tuple[str, ...] = load_config().passthrough_env


def build_subprocess_env(
    extra_env: Mapping[str, str] | None = None,
    passthrough: Iterable[str] | None = None,
) -> dict[str, str]:
    """Return the environment for the Rust subprocess.

    Only the variables in *passthrough* (default: the configured allow list)
    are copied from the current process; *extra_env* entries take precedence.
    """
    names = tuple(passthrough) if passthrough is not None else PASSTHROUGH_ENV_VARS
    env = {name: os.environ[name] for name in names if name in os.environ}
    if extra_env:
        env.update(extra_env)
    return env


def create_transport(binary_path: str | None, env: Mapping[str, str] | None) -> StdioTransport:
    """Return a stdio transport for the resolved ``dcert-mcp`` binary."""
    binary = binary_path or find_binary("dcert-mcp")
    return StdioTransport(command=binary, args=[], env=build_subprocess_env(env) or None)


def create_server(
    binary_path: str | None = None,
    name: str | None = None,
    env: Mapping[str, str] | None = None,
    resilience: ResilienceConfig | None = None,
) -> FastMCPProxy:
    """Create the FastMCP proxy server with the resilience middleware attached.

    Args:
        binary_path: Explicit path to ``dcert-mcp``; auto detected when ``None``.
        name: Server name advertised over MCP; defaults to the configured name.
        env: Extra environment variables for the subprocess.
        resilience: Resilience settings; read from the environment when ``None``.

    Raises:
        FileNotFoundError: If the binary cannot be located.
    """
    transport = create_transport(binary_path, env)
    server = create_proxy(transport, name=name or load_config().server.name)
    for middleware in build_middleware(resilience or resilience_config_from_env()):
        server.add_middleware(middleware)
    return server
