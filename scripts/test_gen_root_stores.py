"""Tests for scripts/gen_root_stores.py (no network)."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import sys
from pathlib import Path

import click
import pytest

_PATH = Path(__file__).with_name("gen_root_stores.py")
_SPEC = importlib.util.spec_from_file_location("gen_root_stores", _PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
grs = importlib.util.module_from_spec(_SPEC)
sys.modules["gen_root_stores"] = grs
_SPEC.loader.exec_module(grs)

COLUMNS = [
    "CA Owner",
    "Certificate Name",
    "SHA-256 Fingerprint",
    "SPKI SHA256",
    "X.509 Certificate (PEM)",
    "Distrust for TLS After Date",
    "sct_not_after_sec",
    "permitted_dns_names",
    "Apple Applied Constraints",
    "Microsoft Disabled Date",
]


def row(name: str, der: bytes, **extra: str) -> dict[str, str]:
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(der).decode()
        + "\n-----END CERTIFICATE-----"
    )
    base = {c: "" for c in COLUMNS}
    base.update(
        {
            "CA Owner": "Owner",
            "Certificate Name": name,
            "SHA-256 Fingerprint": hashlib.sha256(der).hexdigest().upper(),
            "SPKI SHA256": hashlib.sha256(b"key" + der).hexdigest().upper(),
            "X.509 Certificate (PEM)": pem,
        }
    )
    base.update(extra)
    return base


def report(rows: list[dict[str, str]]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def test_build_merges_stores_and_limits() -> None:
    shared, chrome_only = b"\x30\x01", b"\x30\x02"
    reports = {
        "mozilla": report([row("Shared", shared, **{"Distrust for TLS After Date": "8/6/2026"})]),
        "chrome": report(
            [row("Shared", shared), row("Chrome only", chrome_only, sct_not_after_sec="1761955199")]
        ),
        "apple": report([row("Shared", shared)]),
        "microsoft": report([]),
    }
    entries, ders = grs.build(reports)
    by_name = {e["name"]: e for e in entries}
    assert by_name["Shared"]["stores"] == ["mozilla", "chrome", "apple"]
    assert by_name["Shared"]["limits"] == {"mozilla": {"distrust_after": "8/6/2026"}}
    assert by_name["Chrome only"]["limits"] == {"chrome": {"distrust_after_unix": 1761955199}}
    bundle = grs.render_bundle(entries, ders)
    assert "# Chrome only (Owner): chrome" in bundle
    assert "Shared" not in bundle
    index = json.loads(grs.render_index(entries))
    assert index["stores"] == ["mozilla", "chrome", "apple", "microsoft"]


def test_a_pem_that_does_not_match_its_fingerprint_is_refused() -> None:
    bad = row("Bad", b"\x30\x03", **{"SHA-256 Fingerprint": "00" * 32})
    reports = {
        "mozilla": report([bad]),
        "chrome": report([]),
        "apple": report([]),
        "microsoft": report([]),
    }
    with pytest.raises(click.ClickException, match="does not match"):
        grs.build(reports)


def test_the_committed_index_and_bundles_are_consistent() -> None:
    index = json.loads((grs.ROOT / "src" / "trust_anchors" / "root_stores.json").read_text())
    outside = [e for e in index["roots"] if "mozilla" not in e["stores"]]
    bundle = (grs.ROOT / "src" / "trust_anchors" / "root_stores.pem").read_text()
    assert bundle.count("-----BEGIN CERTIFICATE-----") == len(outside)
    rds = (grs.ROOT / "src" / "trust_anchors" / "aws_rds.pem").read_bytes()
    assert (
        hashlib.sha256(rds).hexdigest()
        == "90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b"
    )
