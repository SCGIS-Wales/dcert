"""Tests for dcert.auth: transport authentication and Host header checks."""

from __future__ import annotations

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier

from dcert.auth import (
    AuthSettings,
    BearerTokenVerifier,
    HostHeaderGuard,
    allowed_hosts,
    build_auth,
    host_allowed,
    parse_host_header,
    settings_from_env,
)
from dcert.config import load_config
from dcert.server import build_subprocess_env, passthrough_matches

AUTH = load_config().server.auth
TOKEN = "s3cret-" * 6


async def test_bearer_token_verifier_accepts_only_the_configured_token():
    verifier = BearerTokenVerifier(TOKEN)
    accepted = await verifier.verify_token(TOKEN)
    assert accepted is not None
    assert accepted.client_id == "dcert-static-token"
    assert await verifier.verify_token(TOKEN[:-1]) is None
    assert await verifier.verify_token("") is None


def test_build_auth_requires_a_configuration():
    with pytest.raises(ValueError, match=AUTH.token_env):
        build_auth(AuthSettings(), AUTH)


def test_build_auth_refuses_a_short_token():
    with pytest.raises(ValueError, match="at least"):
        build_auth(AuthSettings(token="x" * (AUTH.min_token_length - 1)), AUTH)
    assert isinstance(build_auth(AuthSettings(token=TOKEN), AUTH), BearerTokenVerifier)


def test_build_auth_refuses_incomplete_or_plain_http_oidc():
    with pytest.raises(ValueError, match=AUTH.oidc_jwks_env):
        build_auth(AuthSettings(oidc_issuer="https://idp", oidc_audience="a"), AUTH)
    with pytest.raises(ValueError, match="https"):
        build_auth(
            AuthSettings(
                oidc_issuer="http://idp", oidc_audience="a", oidc_jwks_uri="https://idp/keys"
            ),
            AUTH,
        )


def test_build_auth_prefers_oidc_when_configured():
    settings = AuthSettings(
        token=TOKEN,
        oidc_issuer="https://idp.example.com",
        oidc_audience="dcert",
        oidc_jwks_uri="https://idp.example.com/keys",
    )
    assert isinstance(build_auth(settings, AUTH), JWTVerifier)


def test_settings_from_env_reads_the_configured_variables():
    env = {AUTH.token_env: f" {TOKEN} ", AUTH.oidc_issuer_env: ""}
    assert settings_from_env(AUTH, env) == AuthSettings(token=TOKEN)


@pytest.mark.parametrize(
    ("header", "host"),
    [
        ("localhost:8080", "localhost"),
        ("LOCALHOST", "localhost"),
        ("[::1]:8080", "::1"),
        ("[::1]", "::1"),
        ("127.0.0.1:8080", "127.0.0.1"),
        ("evil.example", "evil.example"),
    ],
)
def test_parse_host_header(header, host):
    assert parse_host_header(header) == host


def test_allowed_hosts_adds_concrete_binds_and_extras_but_not_wildcards():
    loopback = ("127.0.0.1", "localhost", "::1")
    assert allowed_hosts(loopback, "0.0.0.0", ()) == frozenset(loopback)
    hosts = allowed_hosts(loopback, "10.0.0.5", ("a.example, B.example", "c.example"))
    assert {"10.0.0.5", "a.example", "b.example", "c.example"} <= hosts


def _scope(host: bytes | None) -> dict[str, object]:
    headers = [] if host is None else [(b"host", host)]
    return {"type": "http", "headers": headers}


def test_host_allowed_requires_a_listed_host_header():
    hosts = frozenset({"localhost"})
    assert host_allowed(_scope(b"localhost:8080"), hosts)
    assert not host_allowed(_scope(b"attacker.example"), hosts)
    assert not host_allowed(_scope(None), hosts)


async def test_host_header_guard_answers_400_to_a_rebound_host():
    calls: list[str] = []
    sent: list[dict[str, object]] = []

    async def app(scope, receive, send):
        calls.append("app")

    async def receive():
        return {"type": "http.request"}

    async def send(message):
        sent.append(message)

    guard = HostHeaderGuard(app, frozenset({"localhost"}))
    await guard(_scope(b"attacker.example"), receive, send)
    assert calls == []
    assert sent[0]["status"] == 400
    await guard(_scope(b"localhost:8080"), receive, send)
    assert calls == ["app"]
    await guard({"type": "lifespan"}, receive, send)
    assert calls == ["app", "app"]


def test_passthrough_supports_prefix_patterns():
    assert passthrough_matches("DCERT_MCP_FILE_ROOT", ("DCERT_MCP_*",))
    assert not passthrough_matches("DCERT_PROXYX", ("DCERT_PROXY",))
    assert passthrough_matches("DCERT_PROXY", ("DCERT_PROXY",))


def test_subprocess_env_forwards_policy_vault_and_proxy_variables(monkeypatch):
    wanted = {
        "DCERT_MCP_ALLOWED_TARGETS": "api.example.com",
        "DCERT_MCP_VAULT_ADDR_ALLOWLIST": "https://vault:8200",
        "VAULT_ADDR": "https://vault:8200",
        "VAULT_TOKEN": "hvs.x",
        "VAULT_CACERT": "/ca.pem",
        "VAULT_CAPATH": "/ca",
        "VAULT_SKIP_VERIFY": "0",
        "DCERT_KB_FILE": "kb.yaml",
        "DCERT_PROXY": "http://p:3128",
        "DCERT_NOPROXY": "*",
        "ALL_PROXY": "http://p:3128",
        "all_proxy": "http://p:3128",
        "TMPDIR": "/tmp/x",
        "XDG_CACHE_HOME": "/cache",
    }
    for name, value in wanted.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "never")
    env = build_subprocess_env()
    for name, value in wanted.items():
        assert env.get(name) == value, name
    assert "AWS_SECRET_ACCESS_KEY" not in env
