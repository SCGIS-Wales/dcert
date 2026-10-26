#!/usr/bin/env python3
"""Generate dcert's cipher suite table from the IANA registry.

The IANA "TLS Cipher Suites" registry (``tls-parameters-4.csv``) gives each
suite's code point and standard name; a copy is vendored so the table
regenerates offline. The OpenSSL names come from
``scripts/cipher_openssl_names.yaml``, written by the ``openssl-names``
command from the linked OpenSSL's own mapping. The table is written to
``src/ciphers_table.rs`` and committed; CI regenerates it and fails on a diff.
Paths and the registry URL live in ``scripts/cipher_table.yaml``.

Usage::

    python scripts/gen_cipher_table.py generate          # write the table
    python scripts/gen_cipher_table.py generate --check  # exit 1 if stale (CI)
    python scripts/gen_cipher_table.py fetch --check     # vendored registry current?
    python scripts/gen_cipher_table.py fetch             # refresh the vendored registry
    python scripts/gen_cipher_table.py openssl-names     # refresh the name mapping
"""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import re
import shutil
import subprocess
import sys
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT_ROOT / "scripts" / "cipher_table.yaml"

# `0xC0,0x2F`: one assigned two byte code point (ranges and blocks are skipped).
CODE_RE = re.compile(r"^0x([0-9A-Fa-f]{2}),0x([0-9A-Fa-f]{2})$")
# `TLS_<kx>[_<au>]_WITH_<enc>_<mac>` for TLS 1.2 and earlier.
TLS12_RE = re.compile(r"^TLS_(?P<kxau>.+?)_WITH_(?P<enc>.+)_(?P<mac>[A-Z0-9]+)$")
# `TLS_<enc>_<hash>` for TLS 1.3 (code points 0x13xx).
TLS13_RE = re.compile(r"^TLS_(?P<enc>.+)_(?P<mac>SHA\d+)$")
KEY_EXCHANGES = (
    "ECDHE",
    "ECDH",
    "DHE",
    "DH",
    "RSA",
    "PSK",
    "SRP",
    "KRB5",
    "ECCPWD",
    "GOSTR341112",
    "NULL",
)
AEAD_MARKERS = ("_GCM", "_CCM", "CHACHA20_POLY1305", "_MGM")
# FIPS 140-3 approved for TLS: AES in GCM or CCM (not CCM_8) with forward
# secret ECDHE or DHE and RSA or ECDSA authentication, and the TLS 1.3 AES
# suites. Deliberately conservative; CBC suites are left unapproved.
FIPS_KX = {"ECDHE", "DHE"}
FIPS_AU = {"RSA", "ECDSA"}


@dataclass(frozen=True)
class Row:
    """One cipher suite as it appears in the generated table."""

    code: int
    iana: str
    openssl: str | None
    protocol: str
    kx: str
    au: str
    enc: str
    mac: str
    aead: bool
    pfs: bool
    export: bool
    null: bool
    anonymous: bool
    fips: bool
    recommended: bool
    discouraged: bool


def split_kx_au(kxau: str) -> tuple[str, str]:
    """Split `ECDHE_RSA` style prefixes into key exchange and authentication."""
    for kx in KEY_EXCHANGES:
        if kxau == kx:
            return kx, "RSA" if kx == "RSA" else ("none" if kx == "NULL" else kx)
        if kxau.startswith(kx + "_"):
            return kx, kxau[len(kx) + 1 :]
    return kxau, kxau


def classify(code: int, iana: str, openssl: str | None, status: str = "N") -> Row | None:
    """Derive a table row from the code point, standard name and IANA status.

    ``status`` is the registry's Recommended column: ``Y``, ``N`` or ``D``
    (discouraged).
    """
    if code >> 8 == 0x13:
        match = TLS13_RE.match(iana)
        if not match:
            return None
        enc, mac = match.group("enc"), "AEAD"
        kx, au, protocol = "any", "any", "tls13"
    else:
        match = TLS12_RE.match(iana)
        if not match:
            return None
        kx, au = split_kx_au(match.group("kxau"))
        enc, mac, protocol = match.group("enc"), match.group("mac"), "tls12"
        if mac in {"CCM", "GCM"} or mac.isdigit():
            # `..._AES_128_CCM` and `..._AES_128_CCM_8`: the tail is the mode.
            enc, mac = f"{enc}_{mac}", "AEAD"
        elif any(marker in enc for marker in AEAD_MARKERS):
            # The trailing hash of an AEAD suite names the PRF, not a MAC.
            mac = "AEAD"
    aead = protocol == "tls13" or any(marker in enc for marker in AEAD_MARKERS)
    anonymous = au.endswith("anon") or au == "anon"
    pfs = protocol == "tls13" or kx in {"ECDHE", "DHE"}
    fips = enc.startswith("AES_") and aead and "CCM_8" not in enc
    fips = fips and (protocol == "tls13" or (kx in FIPS_KX and au in FIPS_AU))
    if openssl is None and protocol == "tls13":
        # OpenSSL names TLS 1.3 suites by their standard names.
        openssl = iana
    return Row(
        code=code,
        iana=iana,
        openssl=openssl,
        protocol=protocol,
        kx=kx,
        au=au,
        enc=enc,
        mac=mac,
        aead=aead,
        pfs=pfs,
        export="EXPORT" in iana,
        null=enc == "NULL",
        anonymous=anonymous,
        fips=fips,
        recommended=status == "Y",
        discouraged=status == "D",
    )


def parse_registry(text: str, openssl_names: Mapping[str, str]) -> list[Row]:
    """Every assigned, named suite in the IANA CSV, in code point order."""
    rows: list[Row] = []
    for record in csv.DictReader(io.StringIO(text)):
        match = CODE_RE.match(record["Value"].strip())
        name = record["Description"].strip()
        if not match or not name.startswith("TLS_"):
            continue
        code = int(match.group(1) + match.group(2), 16)
        status = (record.get("Recommended") or "N").strip()
        row = classify(code, name, openssl_names.get(name), status)
        if row is not None:
            rows.append(row)
    return sorted(rows, key=lambda r: r.code)


def rust_str(value: str | None) -> str:
    return "None" if value is None else f'Some("{value}")'


def render(rows: Iterable[Row], source_digest: str) -> str:
    """The Rust source of the table."""
    lines = [
        "// @generated by scripts/gen_cipher_table.py from the IANA TLS Cipher Suites",
        f"// registry (tls-parameters-4.csv, sha256 {source_digest}). Do not edit.",
        "",
        "use super::{Cipher, Protocol};",
        "",
        "#[rustfmt::skip]",
        "pub(super) static CIPHERS: &[Cipher] = &[",
    ]
    for r in rows:
        proto = "Protocol::Tls13" if r.protocol == "tls13" else "Protocol::Tls12"
        lines.append(
            f'    Cipher {{ code: 0x{r.code:04X}, iana: "{r.iana}", '
            f"openssl: {rust_str(r.openssl)}, "
            f'protocol: {proto}, kx: "{r.kx}", au: "{r.au}", enc: "{r.enc}", mac: "{r.mac}", '
            f"aead: {str(r.aead).lower()}, pfs: {str(r.pfs).lower()}, "
            f"export: {str(r.export).lower()}, null: {str(r.null).lower()}, "
            f"anonymous: {str(r.anonymous).lower()}, fips: {str(r.fips).lower()}, "
            f"recommended: {str(r.recommended).lower()}, "
            f"discouraged: {str(r.discouraged).lower()} }},"
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def parse_openssl_listing(listing: str) -> dict[str, str]:
    """IANA name to OpenSSL name from `openssl ciphers -V -stdname` output."""
    names: dict[str, str] = {}
    for line in listing.splitlines():
        parts = line.split(" - ")
        if len(parts) >= 3:
            iana, openssl = parts[1].strip(), parts[2].split()[0]
            names[iana] = openssl
    return dict(sorted(names.items()))


def load_config(path: Path = CONFIG_FILE) -> dict[str, Any]:
    """The generator settings, with paths resolved against the repository."""
    config: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    for key in ("iana_csv", "openssl_names", "table"):
        config[key] = PROJECT_ROOT / config[key]
    return config


def download(url: str, limit: int, timeout: float) -> bytes:
    """The body at an https ``url``, refusing anything larger than ``limit``."""
    if not url.startswith("https://"):
        raise click.ClickException(f"refusing a non https registry URL: {url}")
    # The scheme is checked above and the URL comes from the repository's config.
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
        body: bytes = response.read(limit + 1)
    if len(body) > limit:
        raise click.ClickException(f"{url} is larger than {limit} bytes")
    return body


def transport_copy(body: bytes) -> str:
    """``body`` gzipped and base64 encoded, for carrying out of a CI log."""
    return base64.encodebytes(gzip.compress(body, mtime=0)).decode("ascii")


@click.group()
def main() -> None:
    """Build and check dcert's cipher suite table."""


@main.command()
@click.option("--iana-csv", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--names", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option("--check", is_flag=True, help="Fail instead of writing when the table is stale.")
def generate(iana_csv: Path | None, names: Path | None, output: Path | None, check: bool) -> None:
    """Write src/ciphers_table.rs from the IANA registry."""
    config = load_config()
    iana_csv = iana_csv or config["iana_csv"]
    names = names or config["openssl_names"]
    output = output or config["table"]
    raw = iana_csv.read_bytes()
    mapping = yaml.safe_load(names.read_text(encoding="utf-8")) or {}
    table = render(parse_registry(raw.decode("utf-8"), mapping), hashlib.sha256(raw).hexdigest())
    current = output.read_text(encoding="utf-8") if output.exists() else ""
    if current == table:
        click.echo(f"{output.name} is current")
        return
    if check:
        click.echo(f"{output.name} is stale; run scripts/gen_cipher_table.py generate", err=True)
        sys.exit(1)
    output.write_text(table, encoding="utf-8")
    click.echo(f"wrote {output}")


@main.command()
@click.option("--check", is_flag=True, help="Fail instead of writing when the copies differ.")
@click.option(
    "--print-copy",
    is_flag=True,
    help="On a difference, print the live registry gzipped and base64 encoded.",
)
def fetch(check: bool, print_copy: bool) -> None:
    """Compare the vendored IANA registry with the live one, or refresh it."""
    config = load_config()
    vendored: Path = config["iana_csv"]
    live = download(
        config["iana_url"], config["max_download_bytes"], config["download_timeout_seconds"]
    )
    current = vendored.read_bytes() if vendored.exists() else b""
    if current == live:
        click.echo(f"{vendored.name} matches {config['iana_url']}")
        return
    digest = hashlib.sha256(live).hexdigest()
    if not check:
        vendored.parent.mkdir(parents=True, exist_ok=True)
        vendored.write_bytes(live)
        click.echo(f"wrote {vendored} (sha256 {digest}); now run generate")
        return
    click.echo(f"{vendored.name} differs from the live registry (sha256 {digest})", err=True)
    if print_copy:
        click.echo("live registry, gzip then base64:")
        click.echo(transport_copy(live), nl=False)
    sys.exit(1)


@main.command("openssl-names")
@click.option("--names", type=click.Path(path_type=Path), default=None)
def openssl_names(names: Path | None) -> None:
    """Refresh the IANA to OpenSSL name mapping from the linked OpenSSL."""
    names = names or load_config()["openssl_names"]
    openssl = shutil.which("openssl")
    if openssl is None:
        raise click.ClickException("openssl is not on PATH")
    # Fixed arguments and a resolved executable: nothing here is user input.
    listing = subprocess.run(  # noqa: S603
        [openssl, "ciphers", "-V", "-stdname", "ALL:COMPLEMENTOFALL:@SECLEVEL=0"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    header = "# IANA name to OpenSSL name, from `openssl ciphers -V -stdname`.\n"
    names.write_text(header + yaml.safe_dump(parse_openssl_listing(listing)), encoding="utf-8")
    click.echo(f"wrote {names}")


if __name__ == "__main__":
    main()
