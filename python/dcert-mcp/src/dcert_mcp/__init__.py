"""dcert_mcp: Python proxy and typed client for the dcert-mcp TLS certificate server.

The package runs a FastMCP proxy around the ``dcert-mcp`` Rust binary and
exposes every TLS certificate tool over the Model Context Protocol. Tools
added to the Rust binary are discovered at runtime, so no Python changes
are needed when the server grows.

Usage as a server::

    from dcert_mcp import create_server
    create_server().run()

Usage as a client::

    from dcert_mcp import create_client
    async with create_client() as client:
        result = await client.call_tool("analyze_certificate", {"target": "example.com"})

Usage with the typed async wrappers::

    from dcert_mcp import analyze_certificate, create_session
    async with create_session() as session:
        result = await analyze_certificate(target="example.com", session=session)

The helpers need the ``proxy`` extra: ``pip install "dcert-mcp[proxy]"``.
"""

from __future__ import annotations

import importlib

__version__ = "4.0.11"

#: Names whose absence means the ``proxy`` extra is not installed.
PROXY_EXTRA_MODULES = frozenset({"fastmcp", "click", "yaml", "starlette", "mcp", "anyio"})
PROXY_EXTRA_HINT = 'pip install "dcert-mcp[proxy]"'

_EXPORTS = {
    "CircuitBreaker": "resilience",
    "CircuitBreakerOpen": "resilience",
    "Config": "config",
    "load_config": "config",
    "DcertConnectionError": "tools",
    "DcertError": "tools",
    "DcertTimeoutError": "tools",
    "DcertToolError": "tools",
    "Guard": "resilience",
    "OTelConfig": "resilience",
    "RateLimiter": "resilience",
    "ResilienceConfig": "resilience",
    "Session": "tools",
    "analyze_certificate": "tools",
    "backoff_delays": "resilience",
    "build_guard": "resilience",
    "check_expiry": "tools",
    "check_revocation": "tools",
    "close_default_session": "tools",
    "compare_certificates": "tools",
    "convert_pem_to_pfx": "tools",
    "convert_pfx_to_pem": "tools",
    "create_circuit_breaker": "resilience",
    "create_client": "client",
    "create_keystore": "tools",
    "create_rate_limiter": "resilience",
    "create_server": "server",
    "create_session": "tools",
    "create_truststore": "tools",
    "explain_cipher_suite": "tools",
    "export_pem": "tools",
    "list_cipher_suites": "tools",
    "list_tls_policies": "tools",
    "otel_config_from_env": "resilience",
    "resilience_config_from_env": "resilience",
    "setup_otel": "resilience",
    "show_tls_policy": "tools",
    "tls_connection_info": "tools",
    "tls_policy_test": "tools",
    "tls_scan": "tools",
    "truncate_response": "resilience",
    "verify_key_match": "tools",
    "create_csr": "generated_tools",
    "diagnose_endpoint": "generated_tools",
    "explain_edge_term": "generated_tools",
    "validate_certificate": "generated_tools",
    "validate_csr": "generated_tools",
    "vault_issue": "generated_tools",
    "vault_list": "generated_tools",
    "vault_renew": "generated_tools",
    "vault_revoke": "generated_tools",
    "vault_sign": "generated_tools",
    "vault_store": "generated_tools",
    "vault_validate": "generated_tools",
    "verify_key_auto_discover": "generated_tools",
    "GENERATED_TOOL_FUNCTIONS": "generated_tools",
}

__all__ = [
    "create_server",
    "create_client",
    "__version__",
    "Config",
    "load_config",
    "Session",
    "create_session",
    "close_default_session",
    "DcertError",
    "DcertTimeoutError",
    "DcertConnectionError",
    "DcertToolError",
    "ResilienceConfig",
    "resilience_config_from_env",
    "OTelConfig",
    "otel_config_from_env",
    "CircuitBreaker",
    "CircuitBreakerOpen",
    "create_circuit_breaker",
    "Guard",
    "build_guard",
    "RateLimiter",
    "create_rate_limiter",
    "backoff_delays",
    "setup_otel",
    "truncate_response",
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
    "list_cipher_suites",
    "explain_cipher_suite",
    "tls_scan",
    "list_tls_policies",
    "show_tls_policy",
    "tls_policy_test",
    "create_csr",
    "diagnose_endpoint",
    "explain_edge_term",
    "validate_certificate",
    "validate_csr",
    "vault_issue",
    "vault_list",
    "vault_renew",
    "vault_revoke",
    "vault_sign",
    "vault_store",
    "vault_validate",
    "verify_key_auto_discover",
    "GENERATED_TOOL_FUNCTIONS",
]


def missing_extra_message(module: str) -> str:
    """Return the one line shown when the ``proxy`` extra is not installed."""
    return f"dcert_mcp needs the optional package '{module}'. Install it with: {PROXY_EXTRA_HINT}"


def __getattr__(name: str) -> object:
    """Import the module that defines *name* on first use.

    ``import dcert_mcp`` stays cheap and works without the ``proxy`` extra;
    only touching a helper that needs FastMCP imports it.

    Raises:
        ImportError: With one line naming the extra when a proxy dependency is missing.
        AttributeError: When *name* is not part of the public API.
    """
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module 'dcert_mcp' has no attribute {name!r}")
    try:
        module = importlib.import_module(f"dcert_mcp.{module_name}")
    except ModuleNotFoundError as exc:
        root = (exc.name or "").split(".")[0]
        if root in PROXY_EXTRA_MODULES:
            raise ImportError(missing_extra_message(root)) from exc
        raise
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted([*globals(), *_EXPORTS])
