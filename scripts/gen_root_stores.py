#!/usr/bin/env python3
"""Write and check the root store data and the AWS RDS CA bundle.

dcert's "publicly trusted" verdict uses Mozilla's website roots
(``webpki-root-certs``). Chrome, Apple and Microsoft trust TLS roots Mozilla
does not (90 different keys on 2026-11-21), and AWS publishes database CAs that
no store contains. This script writes, from ``scripts/trust_anchors.yaml``:

* ``root_stores.json``: for every root of the four CCADB TLS reports, its
  SHA-256, SPKI SHA-256, name, owner, the stores that include it and the
  limits a store applies (Mozilla's and Chrome's distrust-after dates,
  Chrome's permitted DNS names, Apple's constraints);
* ``root_stores.pem``: the roots of Chrome, Apple or Microsoft whose
  certificate Mozilla does not include, each verified against its SHA-256;
* ``aws_rds.pem``: the AWS RDS global bundle, verified against its pinned
  SHA-256.

Usage::

    python scripts/gen_root_stores.py            # (re)write the files
    python scripts/gen_root_stores.py --check    # compare, write nothing

CCADB data is under CDLA-Permissive-2.0; see ``src/trust_anchors/NOTICE``.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import sys
import urllib.request
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import click
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "scripts" / "trust_anchors.yaml"
TIMEOUT = 120
STORES = ("mozilla", "chrome", "apple", "microsoft")
PEM = re.compile(r"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", re.S)


def get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "dcert-root-stores"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310 - https only
        return bytes(response.read())


def der_of(pem_text: str) -> bytes:
    match = PEM.search(pem_text)
    if not match:
        raise click.ClickException("a CCADB row has no PEM certificate")
    return base64.b64decode("".join(match[1].split()))


def pem_of(der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def limits(store: str, row: Mapping[str, str]) -> dict[str, Any]:
    """The per store limits on TLS trust that dcert can evaluate or report."""
    out: dict[str, Any] = {}
    if store == "mozilla" and row.get("Distrust for TLS After Date"):
        out["distrust_after"] = row["Distrust for TLS After Date"]
    if store == "chrome":
        if row.get("sct_not_after_sec"):
            out["distrust_after_unix"] = int(row["sct_not_after_sec"])
        if row.get("permitted_dns_names"):
            out["permitted_dns_names"] = row["permitted_dns_names"]
    if store == "apple" and row.get("Apple Applied Constraints"):
        out["constraints"] = row["Apple Applied Constraints"]
    if store == "microsoft" and row.get("Microsoft Disabled Date"):
        out["disabled"] = row["Microsoft Disabled Date"]
    return out


def build(reports: Mapping[str, str]) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    """``(index entries, {sha256: der} of every root)`` from the four CSV texts."""
    entries: dict[str, dict[str, Any]] = {}
    ders: dict[str, bytes] = {}
    for store in STORES:
        for row in csv.DictReader(io.StringIO(reports[store])):
            der = der_of(row["X.509 Certificate (PEM)"])
            sha = hashlib.sha256(der).hexdigest().upper()
            if sha != row["SHA-256 Fingerprint"].upper():
                raise click.ClickException(
                    f"{row['Certificate Name']}: PEM does not match its SHA-256"
                )
            ders[sha] = der
            entry = entries.setdefault(
                sha,
                {
                    "sha256": sha,
                    "spki_sha256": row["SPKI SHA256"].upper(),
                    "name": row["Certificate Name"],
                    "owner": row["CA Owner"],
                    "stores": [],
                    "limits": {},
                },
            )
            entry["stores"].append(store)
            found = limits(store, row)
            if found:
                entry["limits"][store] = found
    ordered = sorted(entries.values(), key=lambda e: (e["owner"], e["name"], e["sha256"]))
    for entry in ordered:
        entry["stores"] = [s for s in STORES if s in entry["stores"]]
        if not entry["limits"]:
            del entry["limits"]
    return ordered, ders


def render_index(entries: Iterable[Mapping[str, Any]]) -> str:
    doc = {
        "source": "Common CA Database (CCADB) TLS server authentication reports, "
        "CDLA-Permissive-2.0",
        "stores": list(STORES),
        "roots": list(entries),
    }
    return json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=False) + "\n"


def render_bundle(entries: Iterable[Mapping[str, Any]], ders: Mapping[str, bytes]) -> str:
    out = [
        "# Roots of the Chrome, Apple or Microsoft TLS stores whose certificate Mozilla does not",
        "# include. Generated by scripts/gen_root_stores.py from CCADB data (see NOTICE).",
        "",
    ]
    for entry in entries:
        if "mozilla" in entry["stores"]:
            continue
        out.append(f"# {entry['name']} ({entry['owner']}): {', '.join(entry['stores'])}")
        out.append(f"# SHA-256 {entry['sha256']}")
        out.append(pem_of(ders[entry["sha256"]]))
    return "\n".join(out)


def rds_bundle(spec: Mapping[str, str]) -> str:
    data = get(spec["url"])
    digest = hashlib.sha256(data).hexdigest()
    if digest != spec["sha256"]:
        raise click.ClickException(
            f"{spec['url']}: SHA-256 {digest} differs from the pinned {spec['sha256']}; "
            "AWS changed the bundle (a new region?): review it and update the pin"
        )
    return data.decode("ascii")


@click.command()
@click.option("--check", is_flag=True, help="Fail when a file would change instead of writing it.")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=CONFIG)
def main(check: bool, config_path: Path) -> None:
    """Write (or check) the root store index, the extra roots and the RDS bundle."""
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    spec = config["root_stores"]
    reports = {store: get(url).decode("utf-8") for store, url in spec["reports"].items()}
    entries, ders = build(reports)
    outputs = {
        spec["index"]: render_index(entries),
        spec["bundle"]: render_bundle(entries, ders),
        config["aws_rds"]["output"]: rds_bundle(config["aws_rds"]),
    }
    stale = []
    for relative, text in outputs.items():
        path = ROOT / relative
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            stale.append(relative)
            if not check:
                path.write_text(text, encoding="utf-8")
    if check and stale:
        for relative in stale:
            click.echo(
                f"::error::{relative} differs from its source; a root store changed. Run "
                "python scripts/gen_root_stores.py and review the diff",
                err=True,
            )
        sys.exit(1)
    extra = sum(1 for e in entries if "mozilla" not in e["stores"])
    click.echo(
        f"{len(entries)} roots in the index, {extra} outside Mozilla; "
        + ("files are current" if not stale else f"wrote {len(stale)} file(s)")
    )


if __name__ == "__main__":
    main()
