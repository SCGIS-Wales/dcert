"""Resilient async wrappers for every ``dcert-mcp`` tool.

A session is an async context manager yielding an immutable
:class:`Session` record whose ``call`` closure adds a per call timeout,
reconnection with exponential backoff (for tools annotated as safe to
re-run), a bulkhead, an optional rate limiter and a circuit breaker on top
of the FastMCP client::

    from dcert.tools import analyze_certificate, create_session

    async with create_session(timeout=60.0) as session:
        result = await analyze_certificate(target="example.com", session=session)

Every tool function also works without a session, in which case a shared
default session is created on first use and reused afterwards. The shared
session belongs to the event loop that created it; a later ``asyncio.run()``
gets a fresh one.
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
from mcp_types import ToolAnnotations

from dcert.config import load_config
from dcert.resilience import (
    CircuitBreakerOpen,
    ResilienceConfig,
    build_guard,
    is_connection_error,
    is_retry_safe,
    resilience_config_from_env,
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
Sleep = Callable[[float], Awaitable[None]]


@asynccontextmanager
async def create_session(
    binary_path: str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    max_reconnects: int | None = None,
    resilience: ResilienceConfig | None = None,
    client_factory: ClientFactory | None = None,
    sleep: Sleep | None = None,
) -> AsyncIterator[Session]:
    """Connect to ``dcert-mcp`` and yield a :class:`Session`.

    Reconnection after a transport failure is attempted only for tools whose
    annotations mark them read-only or idempotent (read once from the
    backend's tool list), and never when ``DCERT_MCP_NO_RETRY`` is set.

    Args:
        binary_path: Explicit path to ``dcert-mcp``; auto detected when ``None``.
        env: Extra environment variables for the subprocess.
        timeout: Default per call timeout in seconds (configured default when ``None``).
        max_reconnects: Reconnection attempts per call (configured default when ``None``).
        resilience: Resilience settings; read from the environment when ``None``.
        client_factory: Builds the FastMCP client; mainly for tests.
        sleep: Replaces :func:`asyncio.sleep` for backoff; mainly for tests.

    Raises:
        ConnectionError: If the subprocess does not complete the MCP handshake
            within the configured connect timeout.
    """
    config = resilience or resilience_config_from_env()
    default_timeout = config.tool_timeout if timeout is None else timeout
    reconnects = config.reconnect_max if max_reconnects is None else max_reconnects
    transport = create_transport(binary_path, env)
    make_client: ClientFactory = client_factory or (lambda: Client(transport))
    guard = build_guard(config, retries=reconnects, sleep=sleep)

    client: Client[StdioTransport] | None = None
    client_stack = AsyncExitStack()
    client_lock = asyncio.Lock()
    annotations: dict[str, ToolAnnotations | None] | None = None

    async def connect() -> Client[StdioTransport]:
        """Return the connected client, connecting under the lock when needed.

        Concurrent callers that find the transport gone share one new
        subprocess instead of each starting their own.
        """
        nonlocal client
        async with client_lock:
            if client is not None:
                return client
            candidate = make_client()
            try:
                async with asyncio.timeout(config.connect_timeout):
                    await client_stack.enter_async_context(candidate)
            except TimeoutError:
                raise ConnectionError(
                    f"Connecting to dcert-mcp timed out after {config.connect_timeout}s"
                ) from None
            client = candidate
            logger.debug("Connected to dcert-mcp subprocess: %s", transport.command)
            return candidate

    async def disconnect(expected: Client[StdioTransport] | None = None) -> bool:
        """Close the current client and return whether this call closed it.

        With *expected*, only that client is closed: a caller that observed a
        transport failure must not tear down the replacement another caller
        has already connected.
        """
        nonlocal client
        async with client_lock:
            if client is None or (expected is not None and client is not expected):
                return False
            client = None
            try:
                await client_stack.aclose()
            except Exception:
                logger.debug("Error while disconnecting", exc_info=True)
            return True

    async def retry_safe(tool: str) -> bool:
        """Whether *tool* may be re-run, from the backend's annotations (read once)."""
        nonlocal annotations
        if annotations is None:
            active = await connect()
            try:
                async with asyncio.timeout(config.connect_timeout):
                    listed = await active.list_tools()
            except Exception as exc:
                logger.warning("Cannot list tools (%s); %s will not be retried", exc, tool)
                return False
            annotations = {entry.name: entry.annotations for entry in listed}
        return is_retry_safe(annotations.get(tool))

    async def call(
        tool: str, params: Mapping[str, Any], *, timeout: float | None = None
    ) -> ToolResponse:
        deadline = default_timeout if timeout is None else timeout
        used: Client[StdioTransport] | None = None

        async def operation(_attempt: int) -> CallToolResult:
            nonlocal used
            used = None
            used = await connect()
            return await used.call_tool(tool, dict(params), raise_on_error=False)

        async def on_failure(exc: BaseException, attempt: int) -> bool:
            logger.warning("%s failed on attempt %d: %s", tool, attempt + 1, exc)
            if used is None:
                # Connecting failed: nothing to close, and the failure counts.
                return True
            closed = await disconnect(used)
            # A timeout always counts against the breaker; a transport loss
            # counts once, for the call that closed the shared client.
            return closed or isinstance(exc, TimeoutError)

        retry = await retry_safe(tool)
        try:
            result = await guard.run(
                operation, name=tool, timeout=deadline, retry=retry, on_failure=on_failure
            )
        except CircuitBreakerOpen as exc:
            raise DcertConnectionError(str(exc)) from None
        except TimeoutError:
            raise DcertTimeoutError(f"{tool} timed out after {deadline}s") from None
        except Exception as exc:
            if is_connection_error(exc):
                raise DcertConnectionError(str(exc)) from exc
            raise
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


def _make_default_session_provider() -> tuple[
    Callable[[], Awaitable[Session]], Callable[[], Awaitable[None]]
]:
    """Build the ``(get, close)`` accessors of the shared session.

    An :class:`asyncio.Lock` binds to the loop that first awaits it and a
    session's transport belongs to the loop that started the subprocess, so
    the loop, its lock, the session and the exit stack owning it are kept
    together and replaced as one unit whenever a different loop is running.
    A session left over from an earlier ``asyncio.run()`` holds a dead
    transport and its loop is closed, so it cannot be awaited; it is dropped
    with a warning. Calling :func:`close_default_session` before the loop
    ends releases the subprocess cleanly.

    The state lives in this closure rather than in module globals: it is
    written and read in one place, and nothing outside should reach it.
    """
    loop: asyncio.AbstractEventLoop | None = None
    lock: asyncio.Lock | None = None
    stack: AsyncExitStack | None = None
    session: Session | None = None

    def lock_for_current_loop() -> asyncio.Lock:
        nonlocal loop, lock, stack, session
        running = asyncio.get_running_loop()
        if lock is None or loop is not running:
            if session is not None:
                logger.warning(
                    "Dropping the default session of a previous event loop; call "
                    "close_default_session() before the loop ends to release it"
                )
            loop, lock, stack, session = running, asyncio.Lock(), None, None
        return lock

    async def close_unlocked() -> None:
        nonlocal stack, session
        closing, stack, session = stack, None, None
        if closing is not None:
            await closing.aclose()

    async def get() -> Session:
        nonlocal stack, session
        async with lock_for_current_loop():
            if session is None or not session.connected():
                await close_unlocked()
                opened = AsyncExitStack()
                session = await opened.enter_async_context(create_session())
                stack = opened
            return session

    async def close() -> None:
        async with lock_for_current_loop():
            await close_unlocked()

    return get, close


_get_default_session, _close_default_session = _make_default_session_provider()


async def default_session() -> Session:
    """Return the shared session for the running loop, connecting when needed."""
    return await _get_default_session()


async def close_default_session() -> None:
    """Disconnect the shared session of the running loop, if any."""
    await _close_default_session()


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
    output_dir: str | None = None,
    session: Session | None = None,
    timeout: float | None = None,
) -> ToolResponse:
    """Convert a PKCS12/PFX file to separate PEM files.

    Args:
        pkcs12_path: Input PKCS12/PFX file path.
        password: Password for the PKCS12 file.
        output_dir: Output directory for the PEM files (configured default when ``None``).
        session: Session to use; the shared default when ``None``.
        timeout: Per call timeout in seconds.
    """
    arguments = build_arguments(
        "convert_pfx_to_pem",
        {"pkcs12_path": pkcs12_path, "password": password},
        defaulted={"output_dir": (output_dir, load_config().tools.output_dir)},
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
    allow_non_ca: bool = False,
    session: Session | None = None,
    timeout: float | None = None,
) -> ToolResponse:
    """Create a PKCS12 truststore (Java compatible since JDK 9) from CA PEM files.

    Args:
        cert_paths: PEM files containing the CA certificates to trust.
        output_path: Output PKCS12 truststore file path.
        password: Truststore password (configured default when ``None``).
        allow_non_ca: Include leaf (non CA) certificates instead of refusing
            them, as the CLI's ``--allow-non-ca`` does.
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
        defaulted={
            "password": (password, load_config().tools.truststore_password),
            "allow_non_ca": (allow_non_ca, False),
        },
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
