"""Authentication and Host header checks for the HTTP and SSE transports.

``dcert-python --transport http|sse`` exposes every dcert tool over the
network, so it refuses to start without either a static bearer token or an
OIDC configuration, and it only answers requests whose ``Host`` header names
a loopback address, the bind address or an entry from ``--allowed-hosts``
(which defeats DNS rebinding from a browser).
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Awaitable, Callable, Iterable, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Any

from fastmcp.server.auth import AccessToken, AuthProvider, TokenVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier

from dcert.config import AuthConfig

#: Client id reported for requests authenticated with the static token.
STATIC_TOKEN_CLIENT_ID = "dcert-static-token"  # noqa: S105 (an identifier, not a secret)

#: Bind addresses that mean "every interface" and so name no host.
WILDCARD_BINDS = frozenset({"0.0.0.0", "::", ""})  # noqa: S104


@dataclass(frozen=True)
class AuthSettings:
    """Authentication settings resolved from flags and the environment."""

    token: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_uri: str | None = None

    @property
    def oidc_configured(self) -> bool:
        """Whether any OIDC setting is present."""
        return any((self.oidc_issuer, self.oidc_audience, self.oidc_jwks_uri))


def settings_from_env(config: AuthConfig, env: Mapping[str, str] | None = None) -> AuthSettings:
    """Read :class:`AuthSettings` from the variables named in *config*."""
    source = os.environ if env is None else env

    def read(name: str) -> str | None:
        return source.get(name, "").strip() or None

    return AuthSettings(
        token=read(config.token_env),
        oidc_issuer=read(config.oidc_issuer_env),
        oidc_audience=read(config.oidc_audience_env),
        oidc_jwks_uri=read(config.oidc_jwks_env),
    )


class BearerTokenVerifier(TokenVerifier):
    """Accept exactly one static bearer token, compared in constant time."""

    def __init__(self, token: str) -> None:
        super().__init__()
        self._token = token.encode()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an access token when *token* matches, otherwise ``None``."""
        if not hmac.compare_digest(token.encode(), self._token):
            return None
        return AccessToken(token=token, client_id=STATIC_TOKEN_CLIENT_ID, scopes=[])


def build_auth(settings: AuthSettings, config: AuthConfig) -> AuthProvider:
    """Return the auth provider for *settings*.

    OIDC needs the issuer, the audience and the JWKS URL, all over https; a
    static token must be at least ``config.min_token_length`` characters.

    Raises:
        ValueError: If nothing is configured, or the configuration is
            incomplete or unsafe. The message names the variables to set.
    """
    if settings.oidc_configured:
        return _oidc_verifier(settings, config)
    if settings.token is not None:
        if len(settings.token) < config.min_token_length:
            raise ValueError(
                f"the auth token must be at least {config.min_token_length} characters "
                f"(--auth-token or {config.token_env})"
            )
        return BearerTokenVerifier(settings.token)
    raise ValueError(
        "HTTP and SSE transports need authentication: set --auth-token "
        f"(or {config.token_env}) or an OIDC issuer, audience and JWKS URL "
        f"({config.oidc_issuer_env}, {config.oidc_audience_env}, {config.oidc_jwks_env})"
    )


def _oidc_verifier(settings: AuthSettings, config: AuthConfig) -> JWTVerifier:
    """Return a JWT verifier for a complete, https only OIDC configuration."""
    required = {
        config.oidc_issuer_env: settings.oidc_issuer,
        config.oidc_audience_env: settings.oidc_audience,
        config.oidc_jwks_env: settings.oidc_jwks_uri,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(f"incomplete OIDC configuration: set {', '.join(missing)}")
    for name in (config.oidc_issuer_env, config.oidc_jwks_env):
        value = required[name] or ""
        if not value.startswith("https://"):
            raise ValueError(f"{name} must be an https:// URL, got {value!r}")
    return JWTVerifier(
        jwks_uri=settings.oidc_jwks_uri,
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
    )


def parse_host_header(value: str) -> str:
    """Return the host part of a ``Host`` header, lower cased, without port or brackets."""
    host = value.strip().lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def allowed_hosts(loopback: Iterable[str], bind_host: str, extra: Iterable[str]) -> frozenset[str]:
    """Return the ``Host`` header values to accept.

    Loopback names are always accepted. A concrete bind address is accepted
    too; a wildcard bind (``0.0.0.0``) names no host, so remote names must
    come from *extra* (``--allowed-hosts``, comma separated or repeated).
    """
    hosts = {parse_host_header(h) for h in loopback}
    if bind_host.strip() not in WILDCARD_BINDS:
        hosts.add(parse_host_header(bind_host))
    for entry in extra:
        hosts.update(parse_host_header(h) for h in entry.split(",") if h.strip())
    return frozenset(hosts)


Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class HostHeaderGuard:
    """ASGI middleware that answers 400 unless the ``Host`` header is allowed.

    Starlette's own ``TrustedHostMiddleware`` cannot parse bracketed IPv6
    hosts, hence this small replacement.
    """

    def __init__(self, app: ASGIApp, hosts: frozenset[str]) -> None:
        self.app = app
        self.hosts = hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Pass allowed requests through and refuse the rest."""
        if scope.get("type") not in {"http", "websocket"} or host_allowed(scope, self.hosts):
            await self.app(scope, receive, send)
            return
        body = b"Invalid Host header"
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def host_allowed(scope: Scope, hosts: frozenset[str]) -> bool:
    """Return whether the request in *scope* carries an allowed ``Host`` header."""
    headers: Iterable[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == b"host":
            return parse_host_header(value.decode("latin-1")) in hosts
    return False
