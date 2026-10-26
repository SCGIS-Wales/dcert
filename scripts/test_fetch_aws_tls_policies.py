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
<table><tr><td>ECDHE-RSA-AES128-GCM-SHA256<br>TLS_AES_128_GCM_SHA256</td></tr></table>
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
    assert ciphers["rows"] == [["ECDHE-RSA-AES128-GCM-SHA256 TLS_AES_128_GCM_SHA256"]]


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
