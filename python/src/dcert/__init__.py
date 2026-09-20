"""dcert: a Python MCP wrapper for the dcert TLS certificate server.

The package runs a FastMCP proxy around the ``dcert-mcp`` Rust binary and
exposes every TLS certificate tool over the Model Context Protocol. Tools
added to the Rust binary are discovered at runtime, so no Python changes
are needed when the server grows.

Usage as a server::

    from dcert import create_server
    create_server().run()

Usage as a client::

    from dcert import create_client
    async with create_client() as client:
        result = await client.call_tool("analyze_certificate", {"target": "example.com"})

Usage with the typed async wrappers::

    from dcert import analyze_certificate, create_session
    async with create_session() as session:
        result = await analyze_certificate(target="example.com", session=session)
"""

__version__ = "3.0.47"

from dcert.client import create_client
from dcert.config import Config, load_config
from dcert.resilience import (
    CircuitBreaker,
    CircuitBreakerOpen,
    OTelConfig,
    RateLimiter,
    ResilienceConfig,
    backoff_delays,
    create_circuit_breaker,
    create_rate_limiter,
    otel_config_from_env,
    resilience_config_from_env,
    setup_otel,
    truncate_response,
)
from dcert.server import create_server
from dcert.tools import (
    DcertConnectionError,
    DcertError,
    DcertTimeoutError,
    DcertToolError,
    Session,
    analyze_certificate,
    check_expiry,
    check_revocation,
    close_default_session,
    compare_certificates,
    convert_pem_to_pfx,
    convert_pfx_to_pem,
    create_keystore,
    create_session,
    create_truststore,
    export_pem,
    tls_connection_info,
    verify_key_match,
)

__all__ = [
    # Core API
    "create_server",
    "create_client",
    "__version__",
    # Configuration
    "Config",
    "load_config",
    # Sessions
    "Session",
    "create_session",
    "close_default_session",
    # Exceptions
    "DcertError",
    "DcertTimeoutError",
    "DcertConnectionError",
    "DcertToolError",
    # Resilience
    "ResilienceConfig",
    "resilience_config_from_env",
    "OTelConfig",
    "otel_config_from_env",
    "CircuitBreaker",
    "CircuitBreakerOpen",
    "create_circuit_breaker",
    "RateLimiter",
    "create_rate_limiter",
    "backoff_delays",
    "setup_otel",
    "truncate_response",
    # Tool wrappers
    "analyze_certificate",
    "check_expiry",
    "check_revocation",
    "compare_certificates",
    "tls_connection_info",
    "export_pem",
    "verify_key_match",
    "convert_pfx_to_pem",
    "convert_pem_to_pfx",
    "create_keystore",
    "create_truststore",
]
