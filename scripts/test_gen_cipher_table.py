"""Tests for scripts/gen_cipher_table.py."""

from __future__ import annotations

import base64
import gzip
import importlib.util
import io
import sys
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("gen_cipher_table", HERE / "gen_cipher_table.py")
assert _spec is not None
assert _spec.loader is not None
gen = importlib.util.module_from_spec(_spec)
sys.modules["gen_cipher_table"] = gen
_spec.loader.exec_module(gen)

SAMPLE = (HERE / "testdata" / "tls-parameters-4-sample.csv").read_text(encoding="utf-8")
NAMES = {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256"}


def rows() -> dict[str, Any]:
    return {r.iana: r for r in gen.parse_registry(SAMPLE, NAMES)}


def test_only_assigned_named_suites_are_kept_in_code_order() -> None:
    parsed = gen.parse_registry(SAMPLE, NAMES)
    assert [r.code for r in parsed] == sorted(r.code for r in parsed)
    assert all(r.iana.startswith("TLS_") for r in parsed)
    assert len(parsed) == 10


def test_tls12_aead_suite() -> None:
    r = rows()["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
    assert (r.code, r.openssl, r.protocol) == (0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", "tls12")
    assert (r.kx, r.au, r.enc, r.mac) == ("ECDHE", "RSA", "AES_128_GCM", "AEAD")
    assert r.aead
    assert r.pfs
    assert r.fips
    assert not r.export
    assert not r.recommended
    assert rows()["TLS_AES_128_GCM_SHA256"].recommended
    assert gen.classify(0x0001, "TLS_RSA_WITH_NULL_MD5", None, "D").discouraged


def test_ccm_suites_keep_their_mode() -> None:
    ccm = rows()["TLS_ECDHE_ECDSA_WITH_AES_128_CCM"]
    ccm8 = rows()["TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"]
    assert (ccm.enc, ccm.mac, ccm.fips) == ("AES_128_CCM", "AEAD", True)
    assert (ccm8.enc, ccm8.mac, ccm8.fips) == ("AES_128_CCM_8", "AEAD", False)


def test_tls13_suites_take_their_openssl_name_from_the_mapping_only() -> None:
    r = rows()["TLS_AES_128_CCM_SHA256"]
    assert (r.protocol, r.openssl) == ("tls13", None)
    named = gen.parse_registry(SAMPLE, {"TLS_AES_128_CCM_SHA256": "TLS_AES_128_CCM_SHA256"})
    assert {x.iana: x.openssl for x in named}["TLS_AES_128_CCM_SHA256"] == "TLS_AES_128_CCM_SHA256"
    assert (r.kx, r.mac) == ("any", "AEAD")
    assert r.pfs
    assert r.fips


def test_weak_suites_are_flagged() -> None:
    null = rows()["TLS_RSA_WITH_NULL_MD5"]
    anon = rows()["TLS_DH_anon_WITH_AES_128_CBC_SHA"]
    cbc = rows()["TLS_RSA_WITH_AES_128_CBC_SHA"]
    assert null.null
    assert not null.aead
    assert anon.anonymous
    assert not anon.pfs
    assert not cbc.pfs
    assert not cbc.fips
    assert cbc.mac == "SHA"


def test_render_names_the_source_and_is_stable() -> None:
    parsed = gen.parse_registry(SAMPLE, NAMES)
    out = gen.render(parsed, "abc123")
    assert "sha256 abc123" in out
    assert 'iana: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ' in out
    assert 'openssl: Some("ECDHE-RSA-AES128-GCM-SHA256")' in out
    assert gen.render(parsed, "abc123") == out


def test_openssl_listing_parser() -> None:
    listing = (
        "          0xC0,0x2F - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 - "
        "ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH Au=RSA Enc=AESGCM(128) Mac=AEAD\n"
    )
    assert gen.parse_openssl_listing(listing) == NAMES


def test_config_paths_resolve_against_the_repository() -> None:
    config = gen.load_config()
    assert config["iana_url"].startswith("https://www.iana.org/")
    assert config["table"] == gen.PROJECT_ROOT / "src" / "ciphers_table.rs"
    assert config["iana_csv"].is_relative_to(gen.PROJECT_ROOT)


class FakeResponse(io.BytesIO):
    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def serve(monkeypatch: pytest.MonkeyPatch, body: bytes) -> None:
    monkeypatch.setattr(gen.urllib.request, "urlopen", lambda *_a, **_k: FakeResponse(body))


def test_download_refuses_plain_http_and_oversized_bodies(monkeypatch: pytest.MonkeyPatch) -> None:
    serve(monkeypatch, b"x" * 11)
    with pytest.raises(click.ClickException, match="non https"):
        gen.download("http://example.test/a.csv", 10, 1)
    with pytest.raises(click.ClickException, match="larger than 10 bytes"):
        gen.download("https://example.test/a.csv", 10, 1)
    assert gen.download("https://example.test/a.csv", 11, 1) == b"x" * 11


def with_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    vendored = tmp_path / "data" / "tls-parameters-4.csv"
    config = {
        "iana_url": "https://example.test/tls-parameters-4.csv",
        "iana_csv": vendored,
        "max_download_bytes": 1 << 20,
        "download_timeout_seconds": 1,
    }
    monkeypatch.setattr(gen, "load_config", lambda: config)
    return vendored


def test_fetch_check_fails_on_a_difference_and_prints_a_faithful_copy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    vendored = with_config(monkeypatch, tmp_path)
    live = SAMPLE.encode()
    serve(monkeypatch, live)
    result = CliRunner().invoke(gen.main, ["fetch", "--check", "--print-copy"])
    assert result.exit_code == 1
    payload = result.stdout.split("gzip then base64:\n", 1)[1]
    assert gzip.decompress(base64.b64decode(payload)) == live
    assert not vendored.exists()


def test_fetch_refreshes_the_vendored_copy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    vendored = with_config(monkeypatch, tmp_path)
    serve(monkeypatch, SAMPLE.encode())
    assert CliRunner().invoke(gen.main, ["fetch"]).exit_code == 0
    assert vendored.read_text(encoding="utf-8") == SAMPLE
    result = CliRunner().invoke(gen.main, ["fetch", "--check"])
    assert result.exit_code == 0
    assert "matches" in result.stdout
