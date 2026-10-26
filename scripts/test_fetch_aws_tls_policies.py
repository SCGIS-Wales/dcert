"""Tests for scripts/fetch_aws_tls_policies.py."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "fetch_aws_tls_policies", HERE / "fetch_aws_tls_policies.py"
)
assert _spec is not None
assert _spec.loader is not None
fetch = importlib.util.module_from_spec(_spec)
sys.modules["fetch_aws_tls_policies"] = fetch
_spec.loader.exec_module(fetch)

PAGE = """
<html><head><script>var x = "<table>";</script></head><body>
<h2>TLS protocols</h2>
<p>The following table lists the protocols each policy supports.</p>
<table>
  <tr><th>Security policies</th><th>TLS 1.3</th><th>TLS 1.2</th></tr>
  <tr><td>ELBSecurityPolicy-TLS13-1-3-PQ-2025-09</td>
      <td><img alt="Yes" src="y.png"></td><td></td></tr>
  <tr><td>ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09</td>
      <td><img alt="Yes"></td><td><img alt="Yes"></td></tr>
</table>
<h3>Ciphers</h3>
<table><tr><td><p>ECDHE-RSA-AES128-GCM-SHA256</p><p>TLS_AES_<b>128</b>_GCM_SHA256</p></td>
<td><code>A</code><code>B</code><br>C</td></tr></table>
<table></table>
</body></html>
"""


def test_tables_keep_headings_context_and_image_alt_text() -> None:
    tables = fetch.extract_tables(PAGE)
    assert len(tables) == 2
    protocols, ciphers = tables
    assert protocols["heading"] == "TLS protocols"
    assert "lists the protocols" in protocols["context"]
    assert protocols["rows"][0] == ["Security policies", "TLS 1.3", "TLS 1.2"]
    assert protocols["rows"][1] == ["ELBSecurityPolicy-TLS13-1-3-PQ-2025-09", "Yes", ""]
    assert protocols["rows"][2][1:] == ["Yes", "Yes"]
    assert ciphers["heading"] == "Ciphers"
    assert ciphers["rows"] == [["ECDHE-RSA-AES128-GCM-SHA256 TLS_AES_128_GCM_SHA256", "A B C"]]


def test_json_sources_are_kept_as_json() -> None:
    reduced = fetch.reduce_source("https://example.test/latest.json", b'{"version": 5.7}')
    assert reduced == {"url": "https://example.test/latest.json", "json": {"version": 5.7}}


def test_download_refuses_plain_http() -> None:
    with pytest.raises(click.ClickException, match="non https"):
        fetch.download("http://example.test/a.html", 10, 1)


def with_sources(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    snapshot = tmp_path / "data" / "snapshot.json"
    config = {
        "snapshot": snapshot,
        "catalogue": tmp_path / "catalogue.yaml",
        "max_download_bytes": 1 << 20,
        "download_timeout_seconds": 1,
        "sources": {
            "aws_alb": "https://example.test/alb.html",
            "mozilla": "https://example.test/m.json",
        },
    }
    bodies = {
        "https://example.test/alb.html": PAGE.encode(),
        "https://example.test/m.json": b'{"v": 1}',
    }
    monkeypatch.setattr(fetch, "load_config", lambda: config)
    monkeypatch.setattr(fetch, "download", lambda url, _limit, _timeout: bodies[url])
    return snapshot


def test_download_writes_then_matches(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    snapshot = with_sources(monkeypatch, tmp_path)
    assert CliRunner().invoke(fetch.main, ["download"]).exit_code == 0
    written = json.loads(snapshot.read_text(encoding="utf-8"))
    assert sorted(written) == ["aws_alb", "mozilla"]
    assert written["aws_alb"]["tables"][0]["heading"] == "TLS protocols"
    result = CliRunner().invoke(fetch.main, ["download", "--check"])
    assert result.exit_code == 0
    assert "matches" in result.stdout


def test_download_check_prints_a_faithful_copy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    snapshot = with_sources(monkeypatch, tmp_path)
    result = CliRunner().invoke(fetch.main, ["download", "--check", "--print-copy"])
    assert result.exit_code == 1
    payload = base64.b64decode(result.stdout.split("base64:\n", 1)[1])
    assert hashlib.sha256(payload).hexdigest() in result.stderr
    assert json.loads(payload)["mozilla"]["json"] == {"v": 1}
    assert not snapshot.exists()


# --------------------------------------------------------------------------
# Catalogue generation
# --------------------------------------------------------------------------

ALB = "https://example.test/alb.html"


def elb_tables(extra_policy_for_aes: bool = False) -> list[dict[str, object]]:
    by_cipher = "P-RES P-13" + (" P-OLD" if extra_policy_for_aes else "")
    return [
        {
            "heading": "Protocols by policy",
            "context": "protocols that each TLS security policy supports.",
            "rows": [
                ["Security policies", "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"],
                ["P-13", "Yes", "No", "No", "No"],
                ["P-RES", "Yes", "Yes", "No", "No"],
                ["P-OLD", "No", "Yes", "Yes", "Yes"],
            ],
        },
        {
            "heading": "Ciphers by policy",
            "context": "",
            "rows": [
                ["Security policy", "Ciphers"],
                ["P-13", "TLS_AES_128_GCM_SHA256"],
                ["P-RES", "TLS_AES_128_GCM_SHA256 ECDHE-RSA-AES128-GCM-SHA256"],
                ["P-OLD", "ECDHE-RSA-AES128-SHA AES128-SHA"],
            ],
        },
        {
            "heading": "Policies by cipher",
            "context": "",
            "rows": [
                ["Cipher name", "Security policies", "Cipher suite"],
                [
                    "OpenSSL – TLS_AES_128_GCM_SHA256 IANA – TLS_AES_128_GCM_SHA256",
                    by_cipher,
                    "1301",
                ],
            ],
        },
    ]


def snapshot(extra_policy_for_aes: bool = False) -> dict[str, object]:
    gateway_header = ["Security policy", "Supported TLS versions", "Supported ciphers"]
    return {
        "aws_alb": {"url": ALB, "tables": elb_tables(extra_policy_for_aes)},
        "aws_nlb": {"url": "https://example.test/nlb.html", "tables": elb_tables()},
        "aws_cloudfront": {
            "url": "https://example.test/cf.html",
            "tables": [
                {
                    "heading": "x",
                    "context": "",
                    "rows": [
                        ["", "Security policy"],
                        ["", "SSLv3", "TLSv1.2_2021"],
                        ["Supported SSL/TLS protocols"],
                        ["TLSv1.3", "♦", "♦"],
                        ["TLSv1.2", "♦", "♦"],
                        ["SSLv3", "♦", ""],
                        ["TLS_AES_128_GCM_SHA256", "♦", "♦"],
                        ["RC4-MD5", "♦", ""],
                        ["ECDHE-RSA-AES128-GCM-SHA256", "♦", "♦"],
                    ],
                },
                {
                    "heading": "Note",
                    "context": "",
                    "rows": [
                        ["OpenSSL and s2n cipher name", "RFC cipher name"],
                        ["RC4-MD5", "TLS_RSA_WITH_RC4_128_MD5"],
                    ],
                },
            ],
        },
        "aws_api_gateway": {
            "url": "https://example.test/apigw.html",
            "tables": [
                {
                    "heading": "Default security policies",
                    "context": "",
                    "rows": [
                        ["Resource", "Default security policy name"],
                        ["Regional APIs", "TLS_1_2"],
                        ["Edge-optimized domain", "TLS_1_2"],
                    ],
                },
                {
                    "heading": "Supported security policies for Regional and private APIs",
                    "context": "",
                    "rows": [
                        gateway_header,
                        [
                            "TLS_1_2",
                            "TLS1.3 TLS1.2",
                            "TLS1.3 TLS_AES_128_GCM_SHA256 TLS1.2 AES128-SHA",
                        ],
                    ],
                },
                {
                    "heading": "Supported security policies for edge-optimized APIs",
                    "context": "",
                    "rows": [
                        gateway_header,
                        [
                            "TLS_1_2 (edge-optimized custom domain names only)",
                            "TLS1.2",
                            "TLS1.2 ECDHE-RSA-AES128-SHA",
                        ],
                        ["SecurityPolicy_X_PQ_2025", "TLS1.3", "TLS1.3 TLS_AES_128_GCM_SHA256"],
                    ],
                },
            ],
        },
        "mozilla": {
            "url": "https://example.test/latest.json",
            "json": {
                "href": "https://example.test/6.0.json",
                "version": 6.0,
                "configurations": {
                    level: {
                        "tls_versions": ["TLSv1.3"]
                        if level == "modern"
                        else ["TLSv1.2", "TLSv1.3"],
                        "ciphersuites": ["TLS_AES_128_GCM_SHA256"],
                        "ciphers": {
                            "iana": []
                            if level == "modern"
                            else ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
                        },
                        "tls_curves": ["X25519MLKEM768", "X25519"],
                    }
                    for level in ("modern", "intermediate")
                },
            },
        },
    }


NAMES = {
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": "ECDHE-RSA-AES128-SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA": "AES128-SHA",
}
CONFIG = {
    "retrieved": "2026-10-26",
    "statements": {
        "aws_alb": {"post_quantum_groups": ["X25519MLKEM768"], "defaults": {"P-RES": ["console"]}}
    },
}


def catalogue(**kwargs: bool) -> dict[tuple[str, str], dict[str, object]]:
    return {
        (p["provider"], p["id"]): p
        for p in fetch.build_catalogue(snapshot(**kwargs), CONFIG, NAMES)
    }


def test_elb_policies_take_protocols_ciphers_and_stated_facts() -> None:
    policies = catalogue()
    res = policies[("aws_alb", "P-RES")]
    assert res["protocols"] == ["1.3", "1.2"]
    assert res["tls13_suites"] == ["TLS_AES_128_GCM_SHA256"]
    assert res["tls12_ciphers"] == ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
    assert res["default_for"] == ["console"]
    assert policies[("aws_alb", "P-OLD")]["tls12_ciphers"] == [
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
    ]
    assert ("aws_nlb", "P-RES") in policies, "ALB and NLB names coexist"
    assert policies[("aws_nlb", "P-RES")]["default_for"] == []


def test_table_disagreements_become_notes() -> None:
    old = catalogue(extra_policy_for_aes=True)[("aws_alb", "P-OLD")]
    assert "adds TLS_AES_128_GCM_SHA256" in old["notes"]
    assert old["tls13_suites"] == []


def test_cloudfront_matrix_and_sslv3() -> None:
    policies = catalogue()
    legacy = policies[("aws_cloudfront", "SSLv3")]
    assert legacy["tls12_ciphers"] == [
        "TLS_RSA_WITH_RC4_128_MD5",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ]
    assert "SSLv3" in legacy["notes"]
    assert policies[("aws_cloudfront", "TLSv1.2_2021")]["tls12_ciphers"] == [
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ]


def test_api_gateway_scopes_and_defaults() -> None:
    policies = catalogue()
    regional = policies[("aws_api_gateway", "TLS_1_2")]
    edge = policies[("aws_api_gateway", "TLS_1_2/edge")]
    assert regional["default_for"] == ["Regional APIs"]
    assert edge["default_for"] == ["Edge-optimized domain"]
    assert edge["protocols"] == ["1.2"]
    assert policies[("aws_api_gateway", "SecurityPolicy_X_PQ_2025")]["post_quantum"] is True


def test_mozilla_levels() -> None:
    modern = catalogue()[("mozilla", "mozilla-modern")]
    assert modern["protocols"] == ["1.3"]
    assert modern["groups"] == ["X25519MLKEM768", "X25519"]
    assert modern["post_quantum"] is True
    assert modern["unspecified_classical"] is False
    assert modern["source_url"] == "https://example.test/6.0.json"


def test_unknown_cipher_names_fail_loudly() -> None:
    with pytest.raises(click.ClickException, match="no IANA name"):
        fetch.build_catalogue(snapshot(), CONFIG, {})


def test_render_is_stable_and_compact() -> None:
    policies = fetch.build_catalogue(snapshot(), CONFIG, NAMES)
    text = fetch.render_catalogue(policies, "abc")
    assert text.startswith("# @generated")
    assert "snapshot sha256 abc" in text
    assert "fips: false" not in text
    assert fetch.render_catalogue(policies, "abc") == text


def test_the_vendored_catalogue_is_current() -> None:
    result = CliRunner().invoke(fetch.main, ["generate", "--check"])
    assert result.exit_code == 0, result.output


def test_set_retrieved_keeps_comments(tmp_path: Path) -> None:
    config = tmp_path / "c.yaml"
    config.write_text('# keep me\nretrieved: "2020-01-01"\nother: 1\n', encoding="utf-8")
    fetch.set_retrieved(config, fetch.dt.date(2026, 10, 26))
    assert config.read_text(encoding="utf-8") == '# keep me\nretrieved: "2026-10-26"\nother: 1\n'
    config.write_text("other: 1\n", encoding="utf-8")
    with pytest.raises(click.ClickException, match="retrieved"):
        fetch.set_retrieved(config, fetch.dt.date(2026, 10, 26))
