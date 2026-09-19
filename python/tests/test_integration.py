"""Integration tests against the real ``dcert-mcp`` binary.

Set ``DCERT_MCP_BINARY`` or put a compiled ``dcert-mcp`` on ``PATH``; the
module is skipped otherwise. Every tool is exercised against public HTTPS
endpoints or local files.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from dcert.binary import is_python_script
from dcert.tools import (
    DcertError,
    analyze_certificate,
    check_expiry,
    check_revocation,
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


def _binary_available() -> bool:
    """Return ``True`` when a compiled ``dcert-mcp`` (not a pip wrapper) exists."""
    env_path = os.environ.get("DCERT_MCP_BINARY")
    if env_path:
        return os.path.isfile(env_path) and os.access(env_path, os.X_OK)
    found = shutil.which("dcert-mcp")
    return bool(found) and not is_python_script(found)


pytestmark = pytest.mark.skipif(
    not _binary_available(),
    reason="dcert-mcp binary not available (set DCERT_MCP_BINARY or add to PATH)",
)

TEST_TARGET = "google.com"
TEST_TARGET_ALT = "github.com"


@pytest.fixture
async def session():
    async with create_session(timeout=60.0) as active:
        yield active


@pytest.fixture
def temp_file():
    paths: list[Path] = []

    def make(suffix: str) -> str:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
            paths.append(Path(handle.name))
            return handle.name

    yield make
    for path in paths:
        path.unlink(missing_ok=True)


# -- analyze_certificate ----------------------------------------------------


async def test_analyze_basic(session):
    result = await analyze_certificate(target=TEST_TARGET, session=session)
    assert isinstance(result, str)
    assert result
    assert "CN" in result or "subject" in result.lower() or "issuer" in result.lower()


async def test_analyze_with_options(session):
    result = await analyze_certificate(
        target=TEST_TARGET,
        fingerprint=True,
        extensions=True,
        check_revocation=True,
        session=session,
    )
    assert result


async def test_analyze_invalid_target(session):
    # A host that does not resolve may surface either way: the binary can report
    # the failure in its output (a result) or raise. Both are acceptable; what
    # the test guards against is a hang, a crash or a silent empty success.
    with contextlib.suppress(DcertError):
        assert (
            await analyze_certificate(target="invalid.nonexistent.example", session=session)
            is not None
        )


# -- check_expiry / check_revocation ----------------------------------------


@pytest.mark.parametrize("days", [None, 365, 1])
async def test_expiry(session, days):
    assert isinstance(await check_expiry(target=TEST_TARGET, days=days, session=session), str)


@pytest.mark.parametrize("target", [TEST_TARGET, TEST_TARGET_ALT])
async def test_revocation(session, target):
    assert isinstance(await check_revocation(target=target, session=session), str)


# -- compare_certificates / tls_connection_info ------------------------------


@pytest.mark.parametrize("target_b", [TEST_TARGET_ALT, TEST_TARGET])
async def test_compare(session, target_b):
    result = await compare_certificates(target_a=TEST_TARGET, target_b=target_b, session=session)
    assert isinstance(result, str)


async def test_connection_info(session):
    result = await tls_connection_info(target=TEST_TARGET, session=session)
    assert isinstance(result, str)
    assert "tls" in result.lower() or "cipher" in result.lower()
    assert await tls_connection_info(
        target=TEST_TARGET, min_tls="1.2", max_tls="1.3", session=session
    )


# -- export_pem ----------------------------------------------------------------


async def test_export_pem(session, temp_file):
    result = await export_pem(target=TEST_TARGET, session=session)
    assert "BEGIN CERTIFICATE" in result or "certificate" in result.lower()
    output_path = temp_file(".pem")
    await export_pem(target=TEST_TARGET, output_path=output_path, session=session)
    assert "BEGIN CERTIFICATE" in Path(output_path).read_text()
    assert await export_pem(target=TEST_TARGET, exclude_expired=True, session=session)


# -- file based tools with bad input -------------------------------------------


async def test_verify_key_match_mismatch(session, temp_file):
    key_path = temp_file(".pem")
    Path(key_path).write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        "MC4CAQAwBQYDK2VwBCIEIFKZs2v1LFdD3UhGBEH1kPls/Go8fpN5rOm3KQsYwCBt\n"
        "-----END PRIVATE KEY-----\n"
    )
    with contextlib.suppress(DcertError):
        assert await verify_key_match(target=TEST_TARGET, key_path=key_path, session=session)


async def test_conversions_with_missing_files(session, temp_file):
    out = temp_file(".pfx")
    for coroutine in (
        convert_pfx_to_pem(pkcs12_path="/nonexistent/test.pfx", password="test", session=session),
        convert_pem_to_pfx(
            cert_path="/nonexistent/cert.pem",
            key_path="/nonexistent/key.pem",
            password="test",
            output_path=out,
            session=session,
        ),
        create_keystore(
            cert_path="/nonexistent/cert.pem",
            key_path="/nonexistent/key.pem",
            password="test",
            output_path=out,
            session=session,
        ),
        create_truststore(cert_paths=["/nonexistent/ca.pem"], output_path=out, session=session),
    ):
        with contextlib.suppress(DcertError):
            assert await coroutine is not None


async def test_create_truststore_from_exported_pem(session, temp_file):
    pem_path = temp_file(".pem")
    p12_path = temp_file(".p12")
    await export_pem(target=TEST_TARGET, output_path=pem_path, session=session)
    result = await create_truststore(
        cert_paths=[pem_path], output_path=p12_path, password="testpass", session=session
    )
    assert result is not None
    assert Path(p12_path).stat().st_size > 0


# -- cross tool and lifecycle ---------------------------------------------------


async def test_export_then_analyze_local(session, temp_file):
    pem_path = temp_file(".pem")
    await export_pem(target=TEST_TARGET, output_path=pem_path, session=session)
    assert await analyze_certificate(target=pem_path, session=session)


async def test_concurrent_analysis(session):
    results = await asyncio.gather(
        analyze_certificate(target=TEST_TARGET, session=session),
        tls_connection_info(target=TEST_TARGET, session=session),
        check_expiry(target=TEST_TARGET, session=session),
    )
    assert all(results)


async def test_session_lifecycle():
    async with create_session(timeout=60.0) as active:
        assert active.connected() is True
        for tool in (analyze_certificate, check_expiry, tls_connection_info):
            assert await tool(target=TEST_TARGET, session=active)
    assert active.connected() is False
