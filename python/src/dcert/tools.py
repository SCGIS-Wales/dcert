"""Resilient async wrappers for every ``dcert-mcp`` tool.

A session is an async context manager yielding an immutable
:class:`Session` record whose ``call`` closure adds a per call timeout,
reconnection with exponential backoff, a bulkhead, an optional rate limiter
and a circuit breaker on top of the FastMCP client::

    from dcert.tools import analyze_certificate, create_session

    async with create_session(timeout=60.0) as session:
        result = await analyze_certificate(target="example.com", session=session)

Every tool function also works without a session, in which case a shared
default session is created on first use and reused afterwards.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol, TypedDict, Unpack

from fastmcp import Client
from fastmcp.client.client import CallToolResult
from fastmcp.client.transports import StdioTransport

from dcert.config import load_config
from dcert.resilience import (
    ResilienceConfig,
    backoff_delays,
    create_circuit_breaker,
    create_rate_limiter,
    is_connection_error,
    resilience_config_from_env,
    run_with_retry,
    truncate_response,
)
from dcert.server import create_transport

logger = logging.getLogger(__name__)

#: What a tool call resolves to: the joined text blocks, or the raw result
#: when the tool returned no text.
ToolResponse = str | CallToolResult

#: Anything that carries MCP content blocks.
ToolContent = CallToolResult | Sequence[object]


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class DcertError(Exception):
    """Base exception for all dcert tool errors."""


class DcertTimeoutError(DcertError):
    """A tool call exceeded its timeout."""


class DcertConnectionError(DcertError):
    """The subprocess died, refused to start, or the circuit breaker is open."""


class DcertToolError(DcertError):
    """The MCP tool returned an error result."""

    def __init__(self, message: str, tool: str, error_content: ToolContent | None = None) -> None:
        super().__init__(message)
        self.tool = tool
        self.error_content = error_content


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


def content_blocks(result: ToolContent) -> list[object]:
    """Return the content blocks of *result* (a result object or a bare list)."""
    content = result if isinstance(result, Sequence) else getattr(result, "content", None)
    return list(content) if isinstance(content, Sequence) else []


def extract_text(result: ToolContent) -> str | None:
    """Return the text blocks of *result* joined with newlines, or ``None``."""
    texts = [str(block.text) for block in content_blocks(result) if hasattr(block, "text")]
    return "\n".join(texts) if texts else None


def error_message(result: ToolContent) -> str | None:
    """Return the error text of *result* when it represents a tool error."""
    blocks = content_blocks(result)
    if getattr(result, "is_error", False):
        texts = [getattr(block, "text", str(block)) for block in blocks]
        return "\n".join(texts) if texts else str(result)
    for block in blocks:
        if getattr(block, "type", None) == "error":
            return str(getattr(block, "text", block))
    return None


def build_arguments(
    tool: str,
    required: Mapping[str, Any],
    optional: Mapping[str, Any] | None = None,
    defaulted: Mapping[str, tuple[Any, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble a tool payload.

    *required* values must not be ``None``; *optional* values are included
    when not ``None``; *defaulted* maps a name to ``(value, default)`` and
    includes the value only when it differs from the default.

    Raises:
        ValueError: If a required value is ``None``.
    """
    for name, value in required.items():
        if value is None:
            raise ValueError(f"{tool}() requires '{name}' parameter")
    arguments = dict(required)
    arguments.update({k: v for k, v in (optional or {}).items() if v is not None})
    arguments.update(
        {k: v for k, (v, default) in (defaulted or {}).items() if v is not None and v != default}
    )
    return arguments


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class ToolCall(Protocol):
    """Signature of :attr:`Session.call`."""

    def __call__(
        self, tool: str, params: Mapping[str, Any], *, timeout: float | None = None
    ) -> Awaitable[ToolResponse]: ...


@dataclass(frozen=True)
class Session:
    """Immutable handle on a connected ``dcert-mcp`` subprocess."""

    binary: str
    call: ToolCall
    connected: Callable[[], bool]


ClientFactory = Callable[[], Client[StdioTransport]]


@asynccontextmanager
async def create_session(
    binary_path: str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    max_reconnects: int | None = None,
    resilience: ResilienceConfig | None = None,
    client_factory: ClientFactory | None = None,
) -> AsyncIterator[Session]:
    """Connect to ``dcert-mcp`` and yield a :class:`Session`.

    Args:
        binary_path: Explicit path to ``dcert-mcp``; auto detected when ``None``.
        env: Extra environment variables for the subprocess.
        timeout: Default per call timeout in seconds (configured default when ``None``).
        max_reconnects: Reconnection attempts per call (configured default when ``None``).
        resilience: Resilience settings; read from the environment when ``None``.
        client_factory: Builds the FastMCP client; mainly for tests.
    """
    config = resilience or resilience_config_from_env()
    default_timeout = config.tool_timeout if timeout is None else timeout
    reconnects = config.reconnect_max if max_reconnects is None else max_reconnects
    transport = create_transport(binary_path, env)
    make_client: ClientFactory = client_factory or (lambda: Client(transport))

    client: Client[StdioTransport] | None = None
    client_stack = AsyncExitStack()
    semaphore = asyncio.Semaphore(config.bulkhead_max)
    breaker = (
        create_circuit_breaker(
            config.circuit_breaker_threshold, config.circuit_breaker_reset_timeout
        )
        if config.circuit_breaker_enabled
        else None
    )
    limiter = (
        create_rate_limiter(config.rate_limit_rps, config.rate_limit_burst)
        if config.rate_limit_enabled
        else None
    )
    delays = list(
        backoff_delays(
            reconnects, config.retry_base_delay, config.retry_max_delay, config.retry_multiplier
        )
    )

    async def connect() -> Client[StdioTransport]:
        nonlocal client
        candidate = make_client()
        await client_stack.enter_async_context(candidate)
        client = candidate
        logger.debug("Connected to dcert-mcp subprocess: %s", transport.command)
        return candidate

    async def disconnect() -> None:
        nonlocal client
        if client is None:
            return
        client = None
        try:
            await client_stack.aclose()
        except Exception:
            logger.debug("Error while disconnecting", exc_info=True)

    async def on_failure(exc: BaseException, attempt: int) -> None:
        logger.warning("Tool call failed on attempt %d: %s", attempt + 1, exc)
        await disconnect()
        if breaker is not None:
            await breaker.record_failure()

    async def call(
        tool: str, params: Mapping[str, Any], *, timeout: float | None = None
    ) -> ToolResponse:
        deadline = default_timeout if timeout is None else timeout

        async def attempt(_attempt: int) -> CallToolResult:
            active = client if client is not None else await connect()
            async with asyncio.timeout(deadline):
                return await active.call_tool(tool, dict(params), raise_on_error=False)

        async with semaphore:
            if limiter is not None:
                await limiter.acquire()
            if breaker is not None and not await breaker.allow():
                raise DcertConnectionError(
                    f"Circuit breaker is open; {tool} call rejected. "
                    "The subprocess has failed repeatedly and will be probed again shortly."
                )
            try:
                result = await run_with_retry(
                    attempt,
                    delays=delays,
                    is_retryable=is_connection_error,
                    on_failure=on_failure,
                )
            except TimeoutError:
                raise DcertTimeoutError(f"{tool} timed out after {deadline}s") from None
            except Exception as exc:
                if is_connection_error(exc):
                    raise DcertConnectionError(str(exc)) from exc
                raise
            if breaker is not None:
                await breaker.record_success()
        message = error_message(result)
        if message is not None:
            raise DcertToolError(message, tool=tool, error_content=result)
        text = extract_text(result)
        if text is None:
            return result
        return truncate_response(text, config.max_response_bytes)

    await connect()
    try:
        yield Session(binary=transport.command, call=call, connected=lambda: client is not None)
    finally:
        await disconnect()


# ---------------------------------------------------------------------------
# Shared default session
# ---------------------------------------------------------------------------

_default_stack: AsyncExitStack | None = None
_default_session: Session | None = None
_default_guard: tuple[asyncio.AbstractEventLoop, asyncio.Lock] | None = None


def _lock_for_current_loop() -> asyncio.Lock:
    """Return the guard for the default session, fresh for each event loop.

    An :class:`asyncio.Lock` binds to the loop that first awaits it, so the
    loop and its lock are kept together as one value. Rebinding them as a pair
    means the two can never disagree about which loop the guard belongs to.
    """
    global _default_guard
    loop = asyncio.get_running_loop()
    guard = _default_guard
    if guard is None or guard[0] is not loop:
        guard = (loop, asyncio.Lock())
        _default_guard = guard
    return guard[1]


async def _close_default_unlocked() -> None:
    global _default_stack, _default_session
    stack, _default_stack, _default_session = _default_stack, None, None
    if stack is not None:
        await stack.aclose()


async def default_session() -> Session:
    """Return the shared session, connecting (or reconnecting) when needed."""
    global _default_stack, _default_session
    async with _lock_for_current_loop():
        if _default_session is None or not _default_session.connected():
            await _close_default_unlocked()
            stack = AsyncExitStack()
            _default_session = await stack.enter_async_context(create_session())
            _default_stack = stack
        return _default_session


async def close_default_session() -> None:
    """Disconnect the shared session, if any."""
    async with _lock_for_current_loop():
        await _close_default_unlocked()


async def call_tool(
    tool: str,
    arguments: Mapping[str, Any],
    *,
    session: Session | None = None,
    timeout: float | None = None,
) -> ToolResponse:
    """Invoke *tool* on *session* (or the shared default session)."""
    active = session if session is not None else await default_session()
    return await active.call(tool, arguments, timeout=timeout)


# ---------------------------------------------------------------------------
# Typed tool wrappers
# ---------------------------------------------------------------------------


class ConnectionOptions(TypedDict, total=False):
    """mTLS and connection overrides shared by the network facing tools.

    Keys:
        client_cert: Client certificate PEM file for mTLS.
        client_key: Client private key PEM file for mTLS.
        pkcs12: PKCS12/PFX file for mTLS.
        cert_password: Password for the PKCS12 file.
        ca_cert: Custom CA bundle PEM file.
        connect_to: Redirect the connection while validating the hostname in
            ``target``: a bare IP address or curl's ``HOST1:PORT1:HOST2:PORT2``.
        resolve: Pin ``HOST:PORT:ADDRESS`` to an IP address like curl's ``--resolve``.
        proxy: Forward proxy URL; ``""`` forces a direct connection.
        noproxy: Comma separated hosts bypassing the proxy; ``"*"`` bypasses it entirely.
    """

    client_cert: str
    client_key: str
    pkcs12: str
    cert_password: str
    ca_cert: str
    connect_to: str | list[str]
    resolve: str | list[str]
    proxy: str
    noproxy: str


async def analyze_certificate(
    *,
    target: str,
    fingerprint: bool = True,
    extensions: bool = True,
    check_revocation: bool = False,
    session: Session | None = None,
    timeout: float | None = None,
    **options: Unpack[ConnectionOptions],
) -> ToolResponse:
    """Decode and analyse the TLS certificates of an endpoint or PEM file.

    Args:
        target: HTTPS URL, hostname, or path to a PEM file.
        fingerprint: Include SHA-256 fingerprints.
        extensions: Include certificate extensions.
        check_revocation: Check OCSP revocation status.
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
        **options: See :class:`ConnectionOptions`.
    """
    arguments = build_arguments(
        "analyze_certificate",
        {"target": target},
        options,
        {
            "fingerprint": (fingerprint, True),
            "extensions": (extensions, True),
            "check_revocation": (check_revocation, False),
        },
    )
    return await call_tool("analyze_certificate", arguments, session=session, timeout=timeout)


async def check_expiry(
    *,
    target: str,
    days: int | None = None,
    session: Session | None = None,
    timeout: float | None = None,
    **options: Unpack[ConnectionOptions],
) -> ToolResponse:
    """Check whether the certificates of *target* expire within *days*.

    Args:
        target: HTTPS URL, hostname, or path to a PEM file.
        days: Warning threshold in days (configured default when ``None``).
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
        **options: See :class:`ConnectionOptions`.
    """
    arguments = build_arguments(
        "check_expiry",
        {"target": target},
        options,
        {"days": (days, load_config().tools.expiry_days)},
    )
    return await call_tool("check_expiry", arguments, session=session, timeout=timeout)


async def check_revocation(
    *,
    target: str,
    session: Session | None = None,
    timeout: float | None = None,
    **options: Unpack[ConnectionOptions],
) -> ToolResponse:
    """Check the OCSP revocation status of the certificates of *target*.

    Args:
        target: HTTPS URL, hostname, or path to a PEM file.
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
        **options: See :class:`ConnectionOptions`.
    """
    arguments = build_arguments("check_revocation", {"target": target}, options)
    return await call_tool("check_revocation", arguments, session=session, timeout=timeout)


async def compare_certificates(
    *,
    target_a: str,
    target_b: str,
    session: Session | None = None,
    timeout: float | None = None,
) -> ToolResponse:
    """Compare the certificates of two targets and report the differences.

    Args:
        target_a: First HTTPS URL, hostname, or PEM file path.
        target_b: Second HTTPS URL, hostname, or PEM file path.
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
    """
    arguments = build_arguments(
        "compare_certificates", {"target_a": target_a, "target_b": target_b}
    )
    return await call_tool("compare_certificates", arguments, session=session, timeout=timeout)


async def tls_connection_info(
    *,
    target: str,
    min_tls: str | None = None,
    max_tls: str | None = None,
    session: Session | None = None,
    timeout: float | None = None,
    **options: Unpack[ConnectionOptions],
) -> ToolResponse:
    """Return TLS connection details (protocol, cipher, ALPN, latency) for *target*.

    Args:
        target: HTTPS URL or hostname.
        min_tls: Minimum TLS version, ``"1.2"`` or ``"1.3"``.
        max_tls: Maximum TLS version, ``"1.2"`` or ``"1.3"``.
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
        **options: See :class:`ConnectionOptions`.
    """
    arguments = build_arguments(
        "tls_connection_info",
        {"target": target},
        {"min_tls": min_tls, "max_tls": max_tls, **options},
    )
    return await call_tool("tls_connection_info", arguments, session=session, timeout=timeout)


async def export_pem(
    *,
    target: str,
    output_path: str | None = None,
    exclude_expired: bool = False,
    session: Session | None = None,
    timeout: float | None = None,
    **options: Unpack[ConnectionOptions],
) -> ToolResponse:
    """Export the certificate chain of *target* as PEM text.

    Args:
        target: HTTPS URL or hostname.
        output_path: File to write the PEM chain to.
        exclude_expired: Leave expired certificates out of the chain.
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
        **options: See :class:`ConnectionOptions`.
    """
    arguments = build_arguments(
        "export_pem",
        {"target": target},
        {"output_path": output_path, **options},
        {"exclude_expired": (exclude_expired, False)},
    )
    return await call_tool("export_pem", arguments, session=session, timeout=timeout)


async def verify_key_match(
    *,
    target: str,
    key_path: str,
    session: Session | None = None,
    timeout: float | None = None,
) -> ToolResponse:
    """Verify that a private key matches a certificate.

    Args:
        target: PEM certificate file or HTTPS URL.
        key_path: Private key PEM file path.
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
    """
    arguments = build_arguments("verify_key_match", {"target": target, "key_path": key_path})
    return await call_tool("verify_key_match", arguments, session=session, timeout=timeout)


async def convert_pfx_to_pem(
    *,
    pkcs12_path: str,
    password: str,
    output_dir: str = ".",
    session: Session | None = None,
    timeout: float | None = None,
) -> ToolResponse:
    """Convert a PKCS12/PFX file to separate PEM files.

    Args:
        pkcs12_path: Input PKCS12/PFX file path.
        password: Password for the PKCS12 file.
        output_dir: Output directory for the PEM files.
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
    """
    arguments = build_arguments(
        "convert_pfx_to_pem",
        {"pkcs12_path": pkcs12_path, "password": password},
        defaulted={"output_dir": (output_dir, ".")},
    )
    return await call_tool("convert_pfx_to_pem", arguments, session=session, timeout=timeout)


async def convert_pem_to_pfx(
    *,
    cert_path: str,
    key_path: str,
    password: str,
    output_path: str,
    ca_path: str | None = None,
    session: Session | None = None,
    timeout: float | None = None,
) -> ToolResponse:
    """Convert a PEM certificate and key to a PKCS12/PFX file.

    Args:
        cert_path: PEM certificate file path.
        key_path: PEM private key file path.
        password: Password for the output PKCS12 file.
        output_path: Output PFX file path.
        ca_path: Optional CA certificate PEM file to include.
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
    """
    arguments = build_arguments(
        "convert_pem_to_pfx",
        {
            "cert_path": cert_path,
            "key_path": key_path,
            "password": password,
            "output_path": output_path,
        },
        {"ca_path": ca_path},
    )
    return await call_tool("convert_pem_to_pfx", arguments, session=session, timeout=timeout)


async def create_keystore(
    *,
    cert_path: str,
    key_path: str,
    password: str,
    output_path: str,
    alias: str | None = None,
    session: Session | None = None,
    timeout: float | None = None,
) -> ToolResponse:
    """Create a PKCS12 keystore (Java compatible since JDK 9) from PEM files.

    Args:
        cert_path: PEM certificate file path.
        key_path: PEM private key file path.
        password: Password for the keystore.
        output_path: Output PKCS12 keystore file path.
        alias: Alias for the key entry (configured default when ``None``).
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
    """
    arguments = build_arguments(
        "create_keystore",
        {
            "cert_path": cert_path,
            "key_path": key_path,
            "password": password,
            "output_path": output_path,
        },
        defaulted={"alias": (alias, load_config().tools.keystore_alias)},
    )
    return await call_tool("create_keystore", arguments, session=session, timeout=timeout)


async def create_truststore(
    *,
    cert_paths: list[str],
    output_path: str,
    password: str | None = None,
    session: Session | None = None,
    timeout: float | None = None,
) -> ToolResponse:
    """Create a PKCS12 truststore (Java compatible since JDK 9) from CA PEM files.

    Args:
        cert_paths: PEM files containing the CA certificates to trust.
        output_path: Output PKCS12 truststore file path.
        password: Truststore password (configured default when ``None``).
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.

    Raises:
        ValueError: If *cert_paths* is empty.
    """
    if not cert_paths:
        raise ValueError("create_truststore() requires at least one cert_path")
    arguments = build_arguments(
        "create_truststore",
        {"cert_paths": cert_paths, "output_path": output_path},
        defaulted={"password": (password, load_config().tools.truststore_password)},
    )
    return await call_tool("create_truststore", arguments, session=session, timeout=timeout)


TOOL_FUNCTIONS: tuple[Callable[..., Awaitable[ToolResponse]], ...] = (
    analyze_certificate,
    check_expiry,
    check_revocation,
    compare_certificates,
    tls_connection_info,
    export_pem,
    verify_key_match,
    convert_pfx_to_pem,
    convert_pem_to_pfx,
    create_keystore,
    create_truststore,
)
