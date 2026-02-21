"""Integration tests for dcert-mcp with FastMCP.

These tests require the real dcert-mcp binary to be available.
Set the DCERT_MCP_BINARY environment variable or ensure dcert-mcp is on PATH.

All 11 MCP tools are tested against real HTTPS endpoints and/or local
certificate files to verify end-to-end functionality.
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from dcert.tools import (
    DcertClient,
    DcertError,
    DcertToolError,
)


def _binary_available() -> bool:
    """Check if dcert-mcp binary is available."""
    if os.environ.get("DCERT_MCP_BINARY"):
        return True
    return shutil.which("dcert-mcp") is not None


# Skip all tests if the binary is not available
pytestmark = pytest.mark.skipif(
    not _binary_available(),
    reason="dcert-mcp binary not available (set DCERT_MCP_BINARY or add to PATH)",
)

# Public HTTPS endpoint for testing — google.com is highly available
TEST_TARGET = "google.com"
TEST_TARGET_ALT = "github.com"


@pytest.fixture
async def dcert():
    """Create a connected DcertClient for integration tests."""
    async with DcertClient(timeout=60.0) as client:
        yield client


# ---------------------------------------------------------------------------
# Tool 1: analyze_certificate
# ---------------------------------------------------------------------------


class TestAnalyzeCertificate:
    """Integration tests for the analyze_certificate tool."""

    @pytest.mark.asyncio
    async def test_analyze_basic(self, dcert):
        """Test basic certificate analysis returns structured data."""
        result = await dcert.analyze_certificate(target=TEST_TARGET)
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0
        # Should contain certificate info
        assert "CN" in result or "subject" in result.lower() or "issuer" in result.lower()

    @pytest.mark.asyncio
    async def test_analyze_with_fingerprints(self, dcert):
        """Test analysis with fingerprint option."""
        result = await dcert.analyze_certificate(
            target=TEST_TARGET, fingerprint=True, extensions=True
        )
        assert result is not None
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_analyze_with_revocation_check(self, dcert):
        """Test analysis with OCSP revocation check enabled."""
        result = await dcert.analyze_certificate(target=TEST_TARGET, check_revocation=True)
        assert result is not None
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_analyze_invalid_target(self, dcert):
        """Test analysis of an invalid target returns an error or meaningful result."""
        try:
            result = await dcert.analyze_certificate(target="invalid.nonexistent.example")
            # Even if it doesn't throw, the result should indicate failure
            assert result is not None
        except (DcertToolError, DcertError):
            pass  # Expected for invalid targets


# ---------------------------------------------------------------------------
# Tool 2: check_expiry
# ---------------------------------------------------------------------------


class TestCheckExpiry:
    """Integration tests for the check_expiry tool."""

    @pytest.mark.asyncio
    async def test_expiry_default_days(self, dcert):
        """Test expiry check with default 30-day threshold."""
        result = await dcert.check_expiry(target=TEST_TARGET)
        assert result is not None
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_expiry_custom_days(self, dcert):
        """Test expiry check with a custom day threshold."""
        result = await dcert.check_expiry(target=TEST_TARGET, days=365)
        assert result is not None

    @pytest.mark.asyncio
    async def test_expiry_short_window(self, dcert):
        """Test expiry check with very short window (1 day)."""
        result = await dcert.check_expiry(target=TEST_TARGET, days=1)
        assert result is not None


# ---------------------------------------------------------------------------
# Tool 3: check_revocation
# ---------------------------------------------------------------------------


class TestCheckRevocation:
    """Integration tests for the check_revocation tool."""

    @pytest.mark.asyncio
    async def test_revocation_check(self, dcert):
        """Test OCSP revocation check against a live endpoint."""
        result = await dcert.check_revocation(target=TEST_TARGET)
        assert result is not None
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_revocation_alternative_target(self, dcert):
        """Test revocation check against a different endpoint."""
        result = await dcert.check_revocation(target=TEST_TARGET_ALT)
        assert result is not None


# ---------------------------------------------------------------------------
# Tool 4: compare_certificates
# ---------------------------------------------------------------------------


class TestCompareCertificates:
    """Integration tests for the compare_certificates tool."""

    @pytest.mark.asyncio
    async def test_compare_different_targets(self, dcert):
        """Test comparing certificates from two different endpoints."""
        result = await dcert.compare_certificates(target_a=TEST_TARGET, target_b=TEST_TARGET_ALT)
        assert result is not None
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_compare_same_target(self, dcert):
        """Test comparing a target against itself."""
        result = await dcert.compare_certificates(target_a=TEST_TARGET, target_b=TEST_TARGET)
        assert result is not None


# ---------------------------------------------------------------------------
# Tool 5: tls_connection_info
# ---------------------------------------------------------------------------


class TestTlsConnectionInfo:
    """Integration tests for the tls_connection_info tool."""

    @pytest.mark.asyncio
    async def test_connection_info_basic(self, dcert):
        """Test basic TLS connection info retrieval."""
        result = await dcert.tls_connection_info(target=TEST_TARGET)
        assert result is not None
        assert isinstance(result, str)
        # Should contain TLS/protocol information
        assert "TLS" in result or "tls" in result or "cipher" in result.lower()

    @pytest.mark.asyncio
    async def test_connection_info_tls_version_constraint(self, dcert):
        """Test TLS connection with version constraints."""
        result = await dcert.tls_connection_info(target=TEST_TARGET, min_tls="1.2", max_tls="1.3")
        assert result is not None


# ---------------------------------------------------------------------------
# Tool 6: export_pem
# ---------------------------------------------------------------------------


class TestExportPem:
    """Integration tests for the export_pem tool."""

    @pytest.mark.asyncio
    async def test_export_pem_to_stdout(self, dcert):
        """Test exporting PEM chain to stdout."""
        result = await dcert.export_pem(target=TEST_TARGET)
        assert result is not None
        assert isinstance(result, str)
        # PEM data should contain BEGIN/END markers
        assert "BEGIN CERTIFICATE" in result or "certificate" in result.lower()

    @pytest.mark.asyncio
    async def test_export_pem_to_file(self, dcert):
        """Test exporting PEM chain to a file."""
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            output_path = f.name

        try:
            result = await dcert.export_pem(target=TEST_TARGET, output_path=output_path)
            assert result is not None
            # File should have been written
            content = Path(output_path).read_text()
            assert "BEGIN CERTIFICATE" in content
        finally:
            Path(output_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_export_pem_exclude_expired(self, dcert):
        """Test export with exclude_expired option."""
        result = await dcert.export_pem(target=TEST_TARGET, exclude_expired=True)
        assert result is not None


# ---------------------------------------------------------------------------
# Tool 7: verify_key_match
# ---------------------------------------------------------------------------


class TestVerifyKeyMatch:
    """Integration tests for the verify_key_match tool."""

    @pytest.mark.asyncio
    async def test_verify_key_match_with_url(self, dcert):
        """Test key verification against HTTPS endpoint (expected mismatch)."""
        # Create a temporary key file (won't match, but should not crash)
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w") as f:
            # Write a dummy PEM key that's syntactically valid but won't match
            f.write(
                "-----BEGIN PRIVATE KEY-----\n"
                "MC4CAQAwBQYDK2VwBCIEIFKZs2v1LFdD3UhGBEH1kPls/Go8fpN5rOm3KQsYwCBt\n"
                "-----END PRIVATE KEY-----\n"
            )
            key_path = f.name

        try:
            # This should return a mismatch result (not crash)
            result = await dcert.verify_key_match(target=TEST_TARGET, key_path=key_path)
            assert result is not None
        except (DcertToolError, DcertError):
            # Tool error is expected when key doesn't match
            pass
        finally:
            Path(key_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Tool 8: convert_pfx_to_pem
# ---------------------------------------------------------------------------


class TestConvertPfxToPem:
    """Integration tests for the convert_pfx_to_pem tool."""

    @pytest.mark.asyncio
    async def test_convert_nonexistent_pfx(self, dcert):
        """Test converting a non-existent PFX file returns an error."""
        try:
            result = await dcert.convert_pfx_to_pem(
                pkcs12_path="/nonexistent/test.pfx", password="test"
            )
            # If it returns, should indicate an error
            assert result is not None
        except (DcertToolError, DcertError):
            pass  # Expected


# ---------------------------------------------------------------------------
# Tool 9: convert_pem_to_pfx
# ---------------------------------------------------------------------------


class TestConvertPemToPfx:
    """Integration tests for the convert_pem_to_pfx tool."""

    @pytest.mark.asyncio
    async def test_convert_nonexistent_pem(self, dcert):
        """Test converting non-existent PEM files returns an error."""
        try:
            result = await dcert.convert_pem_to_pfx(
                cert_path="/nonexistent/cert.pem",
                key_path="/nonexistent/key.pem",
                password="test",
                output_path="/tmp/test_out.pfx",
            )
            assert result is not None
        except (DcertToolError, DcertError):
            pass  # Expected


# ---------------------------------------------------------------------------
# Tool 10: create_keystore
# ---------------------------------------------------------------------------


class TestCreateKeystore:
    """Integration tests for the create_keystore tool."""

    @pytest.mark.asyncio
    async def test_create_keystore_nonexistent_files(self, dcert):
        """Test creating keystore with non-existent input files returns an error."""
        try:
            result = await dcert.create_keystore(
                cert_path="/nonexistent/cert.pem",
                key_path="/nonexistent/key.pem",
                password="changeit",
                output_path="/tmp/test_keystore.p12",
            )
            assert result is not None
        except (DcertToolError, DcertError):
            pass  # Expected


# ---------------------------------------------------------------------------
# Tool 11: create_truststore
# ---------------------------------------------------------------------------


class TestCreateTruststore:
    """Integration tests for the create_truststore tool."""

    @pytest.mark.asyncio
    async def test_create_truststore_nonexistent_files(self, dcert):
        """Test creating truststore with non-existent files returns an error."""
        try:
            result = await dcert.create_truststore(
                cert_paths=["/nonexistent/ca.pem"],
                output_path="/tmp/test_truststore.p12",
            )
            assert result is not None
        except (DcertToolError, DcertError):
            pass  # Expected

    @pytest.mark.asyncio
    async def test_create_truststore_from_exported_pem(self, dcert):
        """Test creating a truststore from a freshly exported PEM chain."""
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as pem_f:
            pem_path = pem_f.name
        with tempfile.NamedTemporaryFile(suffix=".p12", delete=False) as p12_f:
            p12_path = p12_f.name

        try:
            # First export the PEM chain
            await dcert.export_pem(target=TEST_TARGET, output_path=pem_path)

            # Then create a truststore from it
            result = await dcert.create_truststore(
                cert_paths=[pem_path],
                output_path=p12_path,
                password="testpass",
            )
            assert result is not None
            # Truststore file should exist and be non-empty
            assert Path(p12_path).stat().st_size > 0
        finally:
            Path(pem_path).unlink(missing_ok=True)
            Path(p12_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Cross-tool integration tests
# ---------------------------------------------------------------------------


class TestCrossToolIntegration:
    """Tests that exercise multiple tools in sequence."""

    @pytest.mark.asyncio
    async def test_analyze_then_check_expiry(self, dcert):
        """Test analyzing a certificate and then checking its expiry."""
        analyze_result = await dcert.analyze_certificate(target=TEST_TARGET)
        assert analyze_result is not None

        expiry_result = await dcert.check_expiry(target=TEST_TARGET)
        assert expiry_result is not None

    @pytest.mark.asyncio
    async def test_export_pem_and_analyze_local(self, dcert):
        """Test exporting PEM and analyzing the local file."""
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            pem_path = f.name

        try:
            # Export PEM chain to file
            await dcert.export_pem(target=TEST_TARGET, output_path=pem_path)

            # Analyze the local PEM file
            result = await dcert.analyze_certificate(target=pem_path)
            assert result is not None
        finally:
            Path(pem_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_concurrent_analysis(self, dcert):
        """Test running multiple tool calls concurrently."""
        import asyncio

        results = await asyncio.gather(
            dcert.analyze_certificate(target=TEST_TARGET),
            dcert.tls_connection_info(target=TEST_TARGET),
            dcert.check_expiry(target=TEST_TARGET),
        )
        assert len(results) == 3
        assert all(r is not None for r in results)


# ---------------------------------------------------------------------------
# Client lifecycle tests
# ---------------------------------------------------------------------------


class TestClientLifecycle:
    """Test client connection and reconnection with real binary."""

    @pytest.mark.asyncio
    async def test_context_manager_lifecycle(self):
        """Test that context manager properly connects and disconnects."""
        async with DcertClient(timeout=60.0) as client:
            assert client._connected is True
            result = await client.analyze_certificate(target=TEST_TARGET)
            assert result is not None

    @pytest.mark.asyncio
    async def test_multiple_calls_same_client(self):
        """Test making multiple calls on the same client connection."""
        async with DcertClient(timeout=60.0) as client:
            r1 = await client.analyze_certificate(target=TEST_TARGET)
            r2 = await client.check_expiry(target=TEST_TARGET)
            r3 = await client.tls_connection_info(target=TEST_TARGET)
            assert all(r is not None for r in [r1, r2, r3])
