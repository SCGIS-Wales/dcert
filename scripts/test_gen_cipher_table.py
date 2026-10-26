"""Tests for scripts/gen_cipher_table.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

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


def test_ccm_suites_keep_their_mode() -> None:
    ccm = rows()["TLS_ECDHE_ECDSA_WITH_AES_128_CCM"]
    ccm8 = rows()["TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"]
    assert (ccm.enc, ccm.mac, ccm.fips) == ("AES_128_CCM", "AEAD", True)
    assert (ccm8.enc, ccm8.mac, ccm8.fips) == ("AES_128_CCM_8", "AEAD", False)


def test_tls13_suites_use_their_standard_name_in_openssl() -> None:
    r = rows()["TLS_AES_128_CCM_SHA256"]
    assert (r.protocol, r.openssl) == ("tls13", "TLS_AES_128_CCM_SHA256")
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
