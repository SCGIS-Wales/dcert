"""Resilient async tool wrappers for all dcert MCP tools.

Provides typed Python functions for every dcert-mcp tool with production-grade
resilience: automatic reconnection, configurable timeouts, structured error
handling, circuit breaker, bulkhead, and graceful shutdown.

Usage::

    from dcert.tools import DcertClient

    async with DcertClient() as dcert:
        result = await dcert.analyze_certificate(target="example.com")
        expiry = await dcert.check_expiry(target="example.com", days=30)

Module-level convenience functions are also available::

    from dcert.tools import analyze_certificate, check_expiry

    result = await analyze_certificate(target="example.com")
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from dcert.resilience import (
    CircuitBreaker,
    CircuitBreakerOpen,
    RateLimiter,
    ResilienceConfig,
    _wait_for_compat,
    truncate_response,
)
from dcert.server import _build_subprocess_env, _find_binary

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class DcertError(Exception):
    """Base exception for all dcert tool errors."""


class DcertTimeoutError(DcertError):
    """A tool call exceeded its timeout."""


class DcertConnectionError(DcertError):
    """The subprocess died or failed to connect."""


class DcertToolError(DcertError):
    """The MCP tool returned an error result."""

    def __init__(self, message: str, tool: str, error_content: Any = None) -> None:
        super().__init__(message)
        self.tool = tool
        self.error_content = error_content


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_text(result: Any) -> Any:
    """Extract meaningful content from an MCP tool result.

    FastMCP ``call_tool()`` returns a ``CallToolResult`` object with a
    ``.content`` list, or sometimes a raw list.  This helper unwraps the
    content into a plain string when possible.
    """
    # Handle CallToolResult objects (FastMCP 3.x)
    content = getattr(result, "content", None)
    if content is None:
        content = result if isinstance(result, list) else None

    if content is not None and isinstance(content, list):
        if len(content) == 1 and hasattr(content[0], "text"):
            return content[0].text
        # Multiple text blocks — join them
        texts = [item.text for item in content if hasattr(item, "text")]
        if texts:
            return "\n".join(texts)

    return result


def _validate_required(params: dict[str, Any], names: list[str], tool: str) -> None:
    """Raise ``ValueError`` if any required parameter is missing."""
    for name in names:
        if params.get(name) is None:
            raise ValueError(f"{tool}() requires '{name}' parameter")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class DcertClient:
    """Async context manager wrapping the dcert-mcp subprocess.

    Applies five resilience layers (outermost to innermost):

    1. **Bulkhead** -- ``asyncio.Semaphore`` limiting concurrent calls.
    2. **Reconnection loop** -- auto-reconnects on subprocess crash.
    3. **Circuit breaker** -- trips after repeated connection failures.
    4. **Retry with backoff** -- retries transient connection errors.
    5. **Timeout** -- per-call deadline with Python 3.10 compat shim.

    Args:
        binary_path: Explicit path to the dcert-mcp binary.
        env: Additional environment variables for the subprocess.
        timeout: Default timeout (seconds) for tool calls.
        max_reconnects: Maximum automatic reconnection attempts.
        resilience: Resilience configuration (defaults from env vars).
    """

    def __init__(
        self,
        binary_path: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 300.0,
        max_reconnects: int = 3,
        resilience: ResilienceConfig | None = None,
    ) -> None:
        self._binary_path = binary_path
        self._env = env
        self._resilience = resilience or ResilienceConfig()
        self._timeout = timeout
        self._max_reconnects = max_reconnects
        self._client: Client | None = None
        self._connected = False

        # Resilience primitives
        self._semaphore = asyncio.Semaphore(self._resilience.bulkhead_max)
        self._circuit_breaker: CircuitBreaker | None = (
            CircuitBreaker(
                threshold=self._resilience.circuit_breaker_threshold,
                reset_timeout=self._resilience.circuit_breaker_reset_timeout,
            )
            if self._resilience.circuit_breaker_enabled
            else None
        )
        self._rate_limiter: RateLimiter | None = (
            RateLimiter(
                rps=self._resilience.rate_limit_rps,
                burst=self._resilience.rate_limit_burst,
            )
            if self._resilience.rate_limit_enabled
            else None
        )

    # -- lifecycle ----------------------------------------------------------

    async def __aenter__(self) -> DcertClient:
        await self._connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._disconnect()

    async def _connect(self) -> None:
        binary = self._binary_path or _find_binary()
        subprocess_env = _build_subprocess_env(extra_env=self._env)
        transport = StdioTransport(
            command=binary,
            args=[],
            env=subprocess_env or None,
        )
        self._client = Client(transport)
        await self._client.__aenter__()
        self._connected = True
        logger.debug("Connected to dcert-mcp subprocess: %s", binary)

    async def _disconnect(self) -> None:
        if self._client is not None:
            try:
                await self._client.__aexit__(None, None, None)
            except Exception:
                logger.debug("Error during disconnect", exc_info=True)
            finally:
                self._client = None
                self._connected = False

    async def _reconnect(self) -> None:
        logger.warning("Reconnecting to dcert-mcp subprocess...")
        await self._disconnect()
        await self._connect()

    # -- tool dispatch ------------------------------------------------------

    async def _call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        timeout: float | None = None,
    ) -> Any:
        """Call an MCP tool with full resilience stack."""
        effective_timeout = timeout if timeout is not None else self._timeout

        # Layer 1: Bulkhead (concurrency limiter)
        async with self._semaphore:
            # Layer 2: Rate limiting
            if self._rate_limiter is not None:
                await self._rate_limiter.acquire()

            # Layer 3: Circuit breaker
            if self._circuit_breaker is not None and not await self._circuit_breaker.allow():
                raise DcertConnectionError(
                    f"Circuit breaker is open — {tool_name} call rejected. "
                    "The subprocess has failed repeatedly. "
                    "It will recover automatically after the reset timeout."
                )

            return await self._call_with_retry(tool_name, arguments, effective_timeout)

    async def _call_with_retry(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        timeout: float,
    ) -> Any:
        """Inner call loop with reconnection and retry."""
        last_error: Exception | None = None

        for attempt in range(1 + self._max_reconnects):
            if not self._connected or self._client is None:
                if attempt == 0:
                    raise DcertConnectionError("Client is not connected")
                try:
                    await self._reconnect()
                except Exception as exc:
                    last_error = DcertConnectionError(str(exc))
                    if self._circuit_breaker is not None:
                        await self._circuit_breaker.record_failure()
                    continue

            try:
                logger.debug("Calling tool %s (attempt %d)", tool_name, attempt + 1)
                result = await _wait_for_compat(
                    self._client.call_tool(tool_name, arguments),
                    timeout=timeout,
                )

                # Check for error content in the result
                is_error = getattr(result, "is_error", False)
                if is_error:
                    content = getattr(result, "content", [])
                    texts = [
                        getattr(item, "text", str(item))
                        for item in (content if isinstance(content, list) else [])
                    ]
                    msg = "\n".join(texts) if texts else str(result)
                    raise DcertToolError(msg, tool=tool_name, error_content=result)
                # Also check list-of-content for error types
                content = getattr(result, "content", result)
                if isinstance(content, list):
                    for item in content:
                        if hasattr(item, "type") and item.type == "error":
                            text = getattr(item, "text", str(item))
                            raise DcertToolError(text, tool=tool_name, error_content=result)

                # Record success for circuit breaker
                if self._circuit_breaker is not None:
                    await self._circuit_breaker.record_success()

                # Apply response payload management (truncation)
                text = _extract_text(result)
                if isinstance(text, str) and self._resilience.max_response_bytes > 0:
                    text = truncate_response(text, self._resilience.max_response_bytes)
                return text

            except (TimeoutError, asyncio.TimeoutError):
                raise DcertTimeoutError(f"{tool_name} timed out after {timeout}s") from None
            except asyncio.CancelledError:
                raise DcertTimeoutError(f"{tool_name} timed out after {timeout}s") from None
            except DcertToolError:
                raise
            except DcertTimeoutError:
                raise
            except CircuitBreakerOpen:
                raise DcertConnectionError(f"Circuit breaker open — {tool_name} rejected") from None
            except Exception as exc:
                last_error = DcertConnectionError(str(exc))
                self._connected = False
                if self._circuit_breaker is not None:
                    await self._circuit_breaker.record_failure()
                logger.warning("Tool call %s failed (attempt %d): %s", tool_name, attempt + 1, exc)

        raise last_error or DcertConnectionError("All reconnection attempts exhausted")

    # -- tool wrappers (11 tools) ------------------------------------------

    async def analyze_certificate(
        self,
        *,
        target: str,
        fingerprint: bool = True,
        extensions: bool = True,
        check_revocation: bool = False,
        client_cert: str | None = None,
        client_key: str | None = None,
        pkcs12: str | None = None,
        cert_password: str | None = None,
        ca_cert: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Decode and analyze TLS certificates from an HTTPS endpoint or PEM file.

        Returns certificate details including subject, issuer, SANs, validity
        dates, fingerprints, extensions, and TLS connection information.

        Args:
            target: HTTPS URL, hostname, or local path to a PEM file.
            fingerprint: Include SHA-256 fingerprints.
            extensions: Include certificate extensions.
            check_revocation: Check OCSP revocation status.
            client_cert: Client certificate PEM file path for mTLS.
            client_key: Client private key PEM file path for mTLS.
            pkcs12: PKCS12/PFX file for mTLS.
            cert_password: Password for PKCS12 file.
            ca_cert: Custom CA certificate bundle PEM file.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {"target": target}
        _validate_required(args, ["target"], "analyze_certificate")
        if fingerprint is not True:
            args["fingerprint"] = fingerprint
        if extensions is not True:
            args["extensions"] = extensions
        if check_revocation:
            args["check_revocation"] = check_revocation
        if client_cert is not None:
            args["client_cert"] = client_cert
        if client_key is not None:
            args["client_key"] = client_key
        if pkcs12 is not None:
            args["pkcs12"] = pkcs12
        if cert_password is not None:
            args["cert_password"] = cert_password
        if ca_cert is not None:
            args["ca_cert"] = ca_cert
        return await self._call("analyze_certificate", args, timeout=timeout)

    async def check_expiry(
        self,
        *,
        target: str,
        days: int = 30,
        client_cert: str | None = None,
        client_key: str | None = None,
        pkcs12: str | None = None,
        cert_password: str | None = None,
        ca_cert: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Check if TLS certificates expire within a specified number of days.

        Args:
            target: HTTPS URL, hostname, or local path to a PEM file.
            days: Warning threshold in days (max 3650).
            client_cert: Client certificate PEM file path for mTLS.
            client_key: Client private key PEM file path for mTLS.
            pkcs12: PKCS12/PFX file for mTLS.
            cert_password: Password for PKCS12 file.
            ca_cert: Custom CA certificate bundle PEM file.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {"target": target}
        _validate_required(args, ["target"], "check_expiry")
        if days != 30:
            args["days"] = days
        if client_cert is not None:
            args["client_cert"] = client_cert
        if client_key is not None:
            args["client_key"] = client_key
        if pkcs12 is not None:
            args["pkcs12"] = pkcs12
        if cert_password is not None:
            args["cert_password"] = cert_password
        if ca_cert is not None:
            args["ca_cert"] = ca_cert
        return await self._call("check_expiry", args, timeout=timeout)

    async def check_revocation(
        self,
        *,
        target: str,
        client_cert: str | None = None,
        client_key: str | None = None,
        pkcs12: str | None = None,
        cert_password: str | None = None,
        ca_cert: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Check the OCSP revocation status of TLS certificates.

        Args:
            target: HTTPS URL, hostname, or local path to a PEM file.
            client_cert: Client certificate PEM file path for mTLS.
            client_key: Client private key PEM file path for mTLS.
            pkcs12: PKCS12/PFX file for mTLS.
            cert_password: Password for PKCS12 file.
            ca_cert: Custom CA certificate bundle PEM file.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {"target": target}
        _validate_required(args, ["target"], "check_revocation")
        if client_cert is not None:
            args["client_cert"] = client_cert
        if client_key is not None:
            args["client_key"] = client_key
        if pkcs12 is not None:
            args["pkcs12"] = pkcs12
        if cert_password is not None:
            args["cert_password"] = cert_password
        if ca_cert is not None:
            args["ca_cert"] = ca_cert
        return await self._call("check_revocation", args, timeout=timeout)

    async def compare_certificates(
        self,
        *,
        target_a: str,
        target_b: str,
        timeout: float | None = None,
    ) -> Any:
        """Compare TLS certificates between two targets and show differences.

        Args:
            target_a: First HTTPS URL, hostname, or PEM file path.
            target_b: Second HTTPS URL, hostname, or PEM file path.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {"target_a": target_a, "target_b": target_b}
        _validate_required(args, ["target_a", "target_b"], "compare_certificates")
        return await self._call("compare_certificates", args, timeout=timeout)

    async def tls_connection_info(
        self,
        *,
        target: str,
        min_tls: str | None = None,
        max_tls: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        pkcs12: str | None = None,
        cert_password: str | None = None,
        ca_cert: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Get TLS connection details for an HTTPS endpoint.

        Returns protocol version, cipher suite, ALPN negotiation,
        DNS/TCP/TLS latency, and OSI-layer diagnostics.

        Args:
            target: HTTPS URL or hostname to inspect.
            min_tls: Minimum TLS version: ``"1.2"`` or ``"1.3"``.
            max_tls: Maximum TLS version: ``"1.2"`` or ``"1.3"``.
            client_cert: Client certificate PEM file path for mTLS.
            client_key: Client private key PEM file path for mTLS.
            pkcs12: PKCS12/PFX file for mTLS.
            cert_password: Password for PKCS12 file.
            ca_cert: Custom CA certificate bundle PEM file.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {"target": target}
        _validate_required(args, ["target"], "tls_connection_info")
        if min_tls is not None:
            args["min_tls"] = min_tls
        if max_tls is not None:
            args["max_tls"] = max_tls
        if client_cert is not None:
            args["client_cert"] = client_cert
        if client_key is not None:
            args["client_key"] = client_key
        if pkcs12 is not None:
            args["pkcs12"] = pkcs12
        if cert_password is not None:
            args["cert_password"] = cert_password
        if ca_cert is not None:
            args["ca_cert"] = ca_cert
        return await self._call("tls_connection_info", args, timeout=timeout)

    async def export_pem(
        self,
        *,
        target: str,
        output_path: str | None = None,
        exclude_expired: bool = False,
        client_cert: str | None = None,
        client_key: str | None = None,
        pkcs12: str | None = None,
        cert_password: str | None = None,
        ca_cert: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Export the TLS certificate chain as PEM text.

        Args:
            target: HTTPS URL or hostname.
            output_path: Output file path to write the PEM chain.
            exclude_expired: Exclude expired certificates from the chain.
            client_cert: Client certificate PEM file path for mTLS.
            client_key: Client private key PEM file path for mTLS.
            pkcs12: PKCS12/PFX file for mTLS.
            cert_password: Password for PKCS12 file.
            ca_cert: Custom CA certificate bundle PEM file.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {"target": target}
        _validate_required(args, ["target"], "export_pem")
        if output_path is not None:
            args["output_path"] = output_path
        if exclude_expired:
            args["exclude_expired"] = exclude_expired
        if client_cert is not None:
            args["client_cert"] = client_cert
        if client_key is not None:
            args["client_key"] = client_key
        if pkcs12 is not None:
            args["pkcs12"] = pkcs12
        if cert_password is not None:
            args["cert_password"] = cert_password
        if ca_cert is not None:
            args["ca_cert"] = ca_cert
        return await self._call("export_pem", args, timeout=timeout)

    async def verify_key_match(
        self,
        *,
        target: str,
        key_path: str,
        timeout: float | None = None,
    ) -> Any:
        """Verify that a private key matches a certificate.

        Args:
            target: PEM certificate file or HTTPS URL.
            key_path: Private key PEM file path.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {"target": target, "key_path": key_path}
        _validate_required(args, ["target", "key_path"], "verify_key_match")
        return await self._call("verify_key_match", args, timeout=timeout)

    async def convert_pfx_to_pem(
        self,
        *,
        pkcs12_path: str,
        password: str,
        output_dir: str = ".",
        timeout: float | None = None,
    ) -> Any:
        """Convert a PKCS12/PFX file to separate PEM files.

        Args:
            pkcs12_path: Input PKCS12/PFX file path.
            password: Password for the PKCS12 file.
            output_dir: Output directory for PEM files.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {
            "pkcs12_path": pkcs12_path,
            "password": password,
        }
        _validate_required(args, ["pkcs12_path", "password"], "convert_pfx_to_pem")
        if output_dir != ".":
            args["output_dir"] = output_dir
        return await self._call("convert_pfx_to_pem", args, timeout=timeout)

    async def convert_pem_to_pfx(
        self,
        *,
        cert_path: str,
        key_path: str,
        password: str,
        output_path: str,
        ca_path: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Convert PEM certificate and key to a PKCS12/PFX file.

        Args:
            cert_path: PEM certificate file path.
            key_path: PEM private key file path.
            password: Password for the output PKCS12 file.
            output_path: Output PFX file path.
            ca_path: Optional CA certificate PEM file to include.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {
            "cert_path": cert_path,
            "key_path": key_path,
            "password": password,
            "output_path": output_path,
        }
        _validate_required(
            args, ["cert_path", "key_path", "password", "output_path"], "convert_pem_to_pfx"
        )
        if ca_path is not None:
            args["ca_path"] = ca_path
        return await self._call("convert_pem_to_pfx", args, timeout=timeout)

    async def create_keystore(
        self,
        *,
        cert_path: str,
        key_path: str,
        password: str,
        output_path: str,
        alias: str = "server",
        timeout: float | None = None,
    ) -> Any:
        """Create a PKCS12 keystore from PEM certificate and key files.

        Java-compatible since JDK 9 (PKCS12 is the default keystore type).

        Args:
            cert_path: PEM certificate file path.
            key_path: PEM private key file path.
            password: Password for the keystore.
            output_path: Output PKCS12 keystore file path.
            alias: Alias for the key entry.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {
            "cert_path": cert_path,
            "key_path": key_path,
            "password": password,
            "output_path": output_path,
        }
        _validate_required(
            args, ["cert_path", "key_path", "password", "output_path"], "create_keystore"
        )
        if alias != "server":
            args["alias"] = alias
        return await self._call("create_keystore", args, timeout=timeout)

    async def create_truststore(
        self,
        *,
        cert_paths: list[str],
        output_path: str,
        password: str = "changeit",
        timeout: float | None = None,
    ) -> Any:
        """Create a PKCS12 truststore from CA certificate PEM files.

        Java-compatible since JDK 9. Bundles multiple CA certificates
        into a single truststore file.

        Args:
            cert_paths: PEM file paths containing CA certificates to trust.
            output_path: Output PKCS12 truststore file path.
            password: Password for the truststore.
            timeout: Timeout in seconds (overrides default).
        """
        args: dict[str, Any] = {
            "cert_paths": cert_paths,
            "output_path": output_path,
        }
        _validate_required(args, ["cert_paths", "output_path"], "create_truststore")
        if not cert_paths:
            raise ValueError("create_truststore() requires at least one cert_path")
        if password != "changeit":
            args["password"] = password
        return await self._call("create_truststore", args, timeout=timeout)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

_default_client: DcertClient | None = None


async def _get_client() -> DcertClient:
    """Get or create the module-level singleton client."""
    global _default_client  # noqa: PLW0603
    if _default_client is None or not _default_client._connected:
        if _default_client is not None:
            await _default_client._disconnect()
        _default_client = DcertClient()
        await _default_client._connect()
    return _default_client


async def analyze_certificate(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.analyze_certificate`."""
    client = await _get_client()
    return await client.analyze_certificate(**kwargs)


async def check_expiry(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.check_expiry`."""
    client = await _get_client()
    return await client.check_expiry(**kwargs)


async def check_revocation(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.check_revocation`."""
    client = await _get_client()
    return await client.check_revocation(**kwargs)


async def compare_certificates(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.compare_certificates`."""
    client = await _get_client()
    return await client.compare_certificates(**kwargs)


async def tls_connection_info(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.tls_connection_info`."""
    client = await _get_client()
    return await client.tls_connection_info(**kwargs)


async def export_pem(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.export_pem`."""
    client = await _get_client()
    return await client.export_pem(**kwargs)


async def verify_key_match(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.verify_key_match`."""
    client = await _get_client()
    return await client.verify_key_match(**kwargs)


async def convert_pfx_to_pem(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.convert_pfx_to_pem`."""
    client = await _get_client()
    return await client.convert_pfx_to_pem(**kwargs)


async def convert_pem_to_pfx(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.convert_pem_to_pfx`."""
    client = await _get_client()
    return await client.convert_pem_to_pfx(**kwargs)


async def create_keystore(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.create_keystore`."""
    client = await _get_client()
    return await client.create_keystore(**kwargs)


async def create_truststore(**kwargs: Any) -> Any:
    """Module-level convenience wrapper. See :meth:`DcertClient.create_truststore`."""
    client = await _get_client()
    return await client.create_truststore(**kwargs)
