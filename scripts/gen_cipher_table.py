#!/usr/bin/env python3
"""Generate dcert's cipher suite table from the IANA registry.

The IANA "TLS Cipher Suites" registry (``tls-parameters-4.csv``) gives each
suite's code point and standard name. The OpenSSL names come from
``scripts/cipher_openssl_names.yaml``, written by the ``openssl-names``
command from the linked OpenSSL's own mapping. The table is written to
``src/ciphers_table.rs`` and committed; CI regenerates it and fails on a diff.

Usage::

    curl -sSfo tls-parameters-4.csv \\
        https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
    python scripts/gen_cipher_table.py generate --iana-csv tls-parameters-4.csv
    python scripts/gen_cipher_table.py generate --iana-csv tls-parameters-4.csv --check
    python scripts/gen_cipher_table.py openssl-names   # refresh the name mapping
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

import click
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NAMES_FILE = PROJECT_ROOT / "scripts" / "cipher_openssl_names.yaml"
TABLE_FILE = PROJECT_ROOT / "src" / "ciphers_table.rs"

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


def split_kx_au(kxau: str) -> tuple[str, str]:
    """Split `ECDHE_RSA` style prefixes into key exchange and authentication."""
    for kx in KEY_EXCHANGES:
        if kxau == kx:
            return kx, "RSA" if kx == "RSA" else ("none" if kx == "NULL" else kx)
        if kxau.startswith(kx + "_"):
            return kx, kxau[len(kx) + 1 :]
    return kxau, kxau


def classify(code: int, iana: str, openssl: str | None) -> Row | None:
    """Derive a table row from the code point and standard name."""
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
        row = classify(code, name, openssl_names.get(name))
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
        "use crate::ciphers::{CipherRow, Protocol};",
        "",
        "#[rustfmt::skip]",
        "pub(crate) static CIPHERS: &[CipherRow] = &[",
    ]
    for r in rows:
        proto = "Protocol::Tls13" if r.protocol == "tls13" else "Protocol::Tls12"
        lines.append(
            f'    CipherRow {{ code: 0x{r.code:04X}, iana: "{r.iana}", '
            f"openssl: {rust_str(r.openssl)}, "
            f'protocol: {proto}, kx: "{r.kx}", au: "{r.au}", enc: "{r.enc}", mac: "{r.mac}", '
            f"aead: {str(r.aead).lower()}, pfs: {str(r.pfs).lower()}, "
            f"export: {str(r.export).lower()}, null: {str(r.null).lower()}, "
            f"anonymous: {str(r.anonymous).lower()}, fips: {str(r.fips).lower()} }},"
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


@click.group()
def main() -> None:
    """Build and check dcert's cipher suite table."""


@main.command()
@click.option("--iana-csv", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--names", type=click.Path(exists=True, path_type=Path), default=NAMES_FILE)
@click.option("--output", type=click.Path(path_type=Path), default=TABLE_FILE)
@click.option("--check", is_flag=True, help="Fail instead of writing when the table is stale.")
def generate(iana_csv: Path, names: Path, output: Path, check: bool) -> None:
    """Write src/ciphers_table.rs from the IANA registry."""
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


@main.command("openssl-names")
@click.option("--names", type=click.Path(path_type=Path), default=NAMES_FILE)
def openssl_names(names: Path) -> None:
    """Refresh the IANA to OpenSSL name mapping from the linked OpenSSL."""
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
