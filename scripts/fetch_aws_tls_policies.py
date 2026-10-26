#!/usr/bin/env python3
"""Build dcert's TLS security policy catalogue from the published sources.

The AWS documentation pages (Application and Network Load Balancer,
CloudFront, API Gateway) publish each security policy's protocols and
ciphers as HTML tables, and Mozilla publishes its server side TLS
guidelines as JSON. ``download`` reduces each source to what matters (the
tables with their headings, or the JSON) and keeps it as a snapshot, so the
catalogue regenerates offline. Sources and paths live in
``scripts/tls_policies.yaml``.

Usage::

    python scripts/fetch_aws_tls_policies.py download          # refresh the snapshot
    python scripts/fetch_aws_tls_policies.py download --check  # snapshot current?
    python scripts/fetch_aws_tls_policies.py generate          # write kb/tls_policies.yaml
    python scripts/fetch_aws_tls_policies.py generate --check  # catalogue current? (CI)

Facts a page states only in prose (the ALB post quantum groups and the
console and CLI defaults) are recorded in the config's ``statements``.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import sys
import urllib.request
from collections.abc import Callable, Mapping
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import click
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT_ROOT / "scripts" / "tls_policies.yaml"
HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
#: Tags that only style text; every other tag boundary inside a cell separates
#: items (the AWS pages put each cipher and policy name in its own element).
INLINE = {"a", "b", "i", "em", "strong", "sup", "sub", "abbr"}
#: A table is kept with this many characters of the text before it.
CONTEXT_CHARS = 400

Table = dict[str, Any]
Fetch = Callable[[str], bytes]


def load_config(path: Path = CONFIG_FILE) -> dict[str, Any]:
    """The script settings, with paths resolved against the repository."""
    config: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    for key in ("snapshot", "catalogue", "openssl_names"):
        config[key] = PROJECT_ROOT / config[key]
    config["config_path"] = path
    return config


def set_retrieved(path: Path, day: dt.date) -> None:
    """Record the snapshot date in the config, keeping its comments."""
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(r"(?m)^retrieved: .*$", f'retrieved: "{day.isoformat()}"', text)
    if count != 1:
        raise click.ClickException(f"{path} has no single top level 'retrieved:' line")
    path.write_text(updated, encoding="utf-8")


class TableExtractor(HTMLParser):
    """Collect every ``<table>`` as rows of cell text, with the heading and
    the text that precede it. Images inside cells contribute their ``alt``
    text, which is how the AWS pages mark a supported cipher."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[Table] = []
        self._heading = ""
        self._in_heading = False
        self._heading_text: list[str] = []
        self._recent: list[str] = []
        self._stack: list[Table] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in {"script", "style"}:
            self._skip += 1
        elif tag in HEADINGS:
            self._in_heading = True
            self._heading_text = []
        elif tag == "table":
            context = " ".join("".join(self._recent).split())[-CONTEXT_CHARS:]
            self._stack.append({"heading": self._heading, "context": context, "rows": []})
        elif tag == "tr" and self._stack:
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell = []
        elif tag == "img" and self._cell is not None:
            alt = attributes.get("alt") or attributes.get("title") or ""
            if alt:
                self._cell.append(f" {alt} ")
        elif self._cell is not None and tag not in INLINE:
            self._cell.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._skip = max(0, self._skip - 1)
        elif tag in HEADINGS and self._in_heading:
            self._in_heading = False
            self._heading = " ".join("".join(self._heading_text).split())
            self._recent = []
        elif tag in {"td", "th"} and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None and self._stack:
            if self._row:
                self._stack[-1]["rows"].append(self._row)
            self._row = None
        elif self._cell is not None and tag not in INLINE and tag != "table":
            self._cell.append(" ")
        elif tag == "table" and self._stack:
            table = self._stack.pop()
            if table["rows"]:
                self.tables.append(table)
            self._recent = []

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._in_heading:
            self._heading_text.append(data)
        if self._cell is not None:
            self._cell.append(data)
        elif not self._stack:
            self._recent.append(data)
            if sum(map(len, self._recent)) > 4 * CONTEXT_CHARS:
                self._recent = self._recent[-50:]


def extract_tables(html: str) -> list[Table]:
    """Every non empty table of an HTML page, in document order."""
    parser = TableExtractor()
    parser.feed(html)
    parser.close()
    return parser.tables


def download(url: str, limit: int, timeout: float) -> bytes:
    """The body at an https ``url``, refusing anything larger than ``limit``."""
    if not url.startswith("https://"):
        raise click.ClickException(f"refusing a non https source URL: {url}")
    # The scheme is checked above and the URL comes from the repository's config.
    request = urllib.request.Request(url, headers={"User-Agent": "dcert-tls-policy-catalogue"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        body: bytes = response.read(limit + 1)
    if len(body) > limit:
        raise click.ClickException(f"{url} is larger than {limit} bytes")
    return body


def reduce_source(url: str, body: bytes) -> dict[str, Any]:
    """What the catalogue needs from one source: its tables, or its JSON."""
    if url.endswith(".json"):
        return {"url": url, "json": json.loads(body)}
    return {"url": url, "tables": extract_tables(body.decode("utf-8", errors="replace"))}


def build_snapshot(sources: Mapping[str, str], fetch: Fetch) -> dict[str, Any]:
    """Every source reduced, keyed by provider, in a stable order."""
    return {name: reduce_source(url, fetch(url)) for name, url in sorted(sources.items())}


def encode(snapshot: Mapping[str, Any]) -> bytes:
    """The snapshot as stable, readable JSON."""
    return (json.dumps(snapshot, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


# --------------------------------------------------------------------------
# Catalogue generation
# --------------------------------------------------------------------------

PROTOCOL_COLUMNS = {"TLS 1.3": "1.3", "TLS 1.2": "1.2", "TLS 1.1": "1.1", "TLS 1.0": "1.0"}
CLOUDFRONT_PROTOCOLS = {"TLSv1.3": "1.3", "TLSv1.2": "1.2", "TLSv1.1": "1.1", "TLSv1": "1.0"}
GATEWAY_PROTOCOLS = {"TLS1.3": "1.3", "TLS1.2": "1.2", "TLS1.1": "1.1", "TLS1.0": "1.0"}
MOZILLA_PROTOCOLS = {"TLSv1.3": "1.3", "TLSv1.2": "1.2", "TLSv1.1": "1.1", "TLSv1": "1.0"}
#: Edge-optimized API Gateway policies that share a name with a Regional one.
EDGE_SUFFIX = "/edge"

Policy = dict[str, Any]


class CatalogueError(click.ClickException):
    """The snapshot does not say what the generator expects."""


def name_map(snapshot: Mapping[str, Any], openssl_names: Mapping[str, str]) -> dict[str, str]:
    """OpenSSL (and s2n) cipher names to IANA names: the pages' own name
    tables first, then the linked OpenSSL's mapping."""
    mapping = {openssl: iana for iana, openssl in openssl_names.items()}
    for source in snapshot.values():
        for table in source.get("tables", []):
            header = " ".join(table["rows"][0]).lower()
            if "rfc cipher name" in header:
                for row in table["rows"][1:]:
                    if len(row) == 2 and row[1].startswith("TLS_"):
                        mapping[row[0]] = row[1]
            if header.startswith("cipher name"):
                for row in table["rows"][1:]:
                    words = row[0].replace("–", " ").split()
                    if "OpenSSL" in words and "IANA" in words:
                        openssl = words[words.index("OpenSSL") + 1]
                        iana = words[words.index("IANA") + 1]
                        mapping[openssl] = iana
    return mapping


def split_ciphers(
    tokens: list[str], mapping: Mapping[str, str], where: str
) -> tuple[list[str], list[str]]:
    """TLS 1.3 suites and TLS 1.2 ciphers, by IANA name, from cipher names in
    any notation. Tokens that are not cipher names (``TLS1.2`` markers) are
    skipped; an unknown name that looks like a cipher is an error."""
    tls13: list[str] = []
    tls12: list[str] = []
    for token in tokens:
        if token in GATEWAY_PROTOCOLS or token.startswith("TLS1."):
            continue
        iana = mapping.get(token, token if token.startswith("TLS_") else None)
        if iana is None:
            raise CatalogueError(f"{where}: no IANA name for cipher {token!r}")
        target = tls13 if iana.startswith("TLS_AES_") or iana.startswith("TLS_CHACHA20_") else tls12
        if iana not in target:
            target.append(iana)
    return tls13, tls12


def policy(provider: str, policy_id: str, protocols: list[str], url: str, retrieved: str) -> Policy:
    """A catalogue entry with the fields every provider fills."""
    return {
        "id": policy_id,
        "provider": provider,
        "protocols": sorted(protocols, reverse=True),
        "tls13_suites": [],
        "tls12_ciphers": [],
        "groups": [],
        "unspecified_classical": True,
        "fips": False,
        "post_quantum": False,
        "default_for": [],
        "source_url": url,
        "retrieved": retrieved,
    }


def elb_policies(
    provider: str,
    source: Mapping[str, Any],
    mapping: Mapping[str, str],
    statements: Mapping[str, Any],
) -> list[Policy]:
    """Load balancer policies from the protocols and ciphers tables, checked
    against the policies by cipher tables."""
    url, retrieved = source["url"], statements["retrieved"]
    tables = source["tables"]
    protocols: dict[str, list[str]] = {}
    group_of: dict[str, str] = {}
    ciphers: dict[str, list[str]] = {}
    by_cipher: dict[str, set[str]] = {}
    for table in tables:
        header, rows = table["rows"][0], table["rows"][1:]
        if header[0] == "Security policies":
            columns = [PROTOCOL_COLUMNS[h] for h in header[1:]]
            for row in rows:
                protocols[row[0]] = [
                    c for c, cell in zip(columns, row[1:], strict=True) if cell == "Yes"
                ]
                group_of[row[0]] = table["context"]
        elif header[0] == "Security policy":
            for row in rows:
                for name in row[0].split():
                    ciphers[name] = row[1].split()
        elif header[0] == "Cipher name":
            for row in rows:
                words = row[0].replace("–", " ").split()
                cipher = words[words.index("OpenSSL") + 1]
                by_cipher.setdefault(cipher, set()).update(row[1].split())
    if set(protocols) != set(ciphers):
        raise CatalogueError(f"{provider}: protocol and cipher tables name different policies")
    # The ciphers by policy table states each policy directly and is kept;
    # where the policies by cipher table disagrees, the entry says so.
    disagreements: dict[str, list[str]] = {}
    for cipher, names in by_cipher.items():
        listed = {name for name, list_ in ciphers.items() if cipher in list_}
        for name in sorted(listed - names):
            disagreements.setdefault(name, []).append(f"omits {cipher}")
        for name in sorted(names - listed):
            disagreements.setdefault(name, []).append(f"adds {cipher}")
    defaults = statements.get("defaults", {})
    pq_groups = statements.get("post_quantum_groups", [])
    out = []
    for name, versions in protocols.items():
        entry = policy(provider, name, versions, url, retrieved)
        entry["tls13_suites"], entry["tls12_ciphers"] = split_ciphers(ciphers[name], mapping, name)
        entry["fips"] = "FIPS" in name
        entry["post_quantum"] = "-PQ-" in name
        if entry["post_quantum"] and pq_groups:
            entry["groups"] = list(pq_groups)
        entry["default_for"] = list(defaults.get(name, []))
        context = group_of[name]
        if "RFC 9151" in context:
            entry["notes"] = "RFC 9151 (CNSA suite) policy."
        elif "FS supported" in context:
            entry["notes"] = "Forward secrecy policy."
        if entry["post_quantum"] and not pq_groups:
            entry["notes"] = "Named post quantum by AWS; the page lists no key exchange groups."
        if name in disagreements:
            conflict = (
                "The page's policies by cipher table "
                + ", ".join(disagreements[name])
                + "; the ciphers by policy table is used."
            )
            entry["notes"] = f"{entry.get('notes', '')} {conflict}".strip()
            click.echo(f"warning: {provider} {name}: {conflict}", err=True)
        out.append(entry)
    return out


def cloudfront_policies(
    source: Mapping[str, Any], mapping: Mapping[str, str], retrieved: str
) -> list[Policy]:
    """CloudFront viewer policies from the protocol and cipher matrix."""
    table = source["tables"][0]
    names = table["rows"][1][1:]
    protocols: dict[str, list[str]] = {n: [] for n in names}
    tokens: dict[str, list[str]] = {n: [] for n in names}
    sslv3: set[str] = set()
    for row in table["rows"][2:]:
        if len(row) != len(names) + 1:
            continue
        for name, cell in zip(names, row[1:], strict=True):
            if not cell.strip():
                continue
            if row[0] in CLOUDFRONT_PROTOCOLS:
                protocols[name].append(CLOUDFRONT_PROTOCOLS[row[0]])
            elif row[0] == "SSLv3":
                sslv3.add(name)
            else:
                tokens[name].append(row[0])
    out = []
    for name in names:
        entry = policy("aws_cloudfront", name, protocols[name], source["url"], retrieved)
        entry["tls13_suites"], entry["tls12_ciphers"] = split_ciphers(tokens[name], mapping, name)
        if name in sslv3:
            entry["notes"] = "Also accepts SSLv3, which dcert does not test."
        out.append(entry)
    return out


def gateway_policies(
    source: Mapping[str, Any], mapping: Mapping[str, str], retrieved: str
) -> list[Policy]:
    """API Gateway policies for Regional and private, and for edge-optimized
    endpoints, with the defaults the page lists."""
    tables = source["tables"]
    regional = next(
        t for t in tables if t["heading"].startswith("Supported security policies for Regional")
    )
    edge = next(
        t for t in tables if t["heading"].startswith("Supported security policies for edge")
    )
    out: list[Policy] = []
    for table, suffix, scope in (
        (regional, "", "Regional and private"),
        (edge, EDGE_SUFFIX, "Edge-optimized"),
    ):
        for row in table["rows"][1:]:
            base = row[0].split(" (")[0]
            name = base + suffix if base in {"TLS_1_0", "TLS_1_2"} and suffix else base
            versions = [GATEWAY_PROTOCOLS[v] for v in row[1].split()]
            entry = policy("aws_api_gateway", name, versions, source["url"], retrieved)
            entry["tls13_suites"], entry["tls12_ciphers"] = split_ciphers(
                row[2].split(), mapping, name
            )
            entry["fips"] = "FIPS" in name
            entry["post_quantum"] = "_PQ_" in name
            entry["notes"] = f"{scope} APIs and custom domain names."
            if entry["post_quantum"]:
                entry["notes"] += (
                    " Named post quantum by AWS; the page lists no key exchange groups."
                )
            out.append(entry)
    defaults = next(t for t in tables if t["heading"] == "Default security policies")
    for resource, name in defaults["rows"][1:]:
        target = (
            name + EDGE_SUFFIX
            if resource.startswith("Edge") and name in {"TLS_1_0", "TLS_1_2"}
            else name
        )
        entry = next(p for p in out if p["id"] == target)
        entry["default_for"].append(resource)
    return out


def mozilla_policies(source: Mapping[str, Any], retrieved: str) -> list[Policy]:
    """Mozilla's modern and intermediate server configurations."""
    guidelines = source["json"]
    out = []
    for level in ("modern", "intermediate"):
        config = guidelines["configurations"][level]
        versions = [MOZILLA_PROTOCOLS[v] for v in config["tls_versions"]]
        entry = policy("mozilla", f"mozilla-{level}", versions, guidelines["href"], retrieved)
        entry["tls13_suites"] = list(config["ciphersuites"])
        entry["tls12_ciphers"] = list(config["ciphers"]["iana"])
        entry["groups"] = list(config["tls_curves"])
        entry["unspecified_classical"] = False
        entry["post_quantum"] = any("MLKEM" in g for g in entry["groups"])
        entry["notes"] = f"Mozilla server side TLS guidelines {guidelines['version']}, {level}."
        out.append(entry)
    return out


def build_catalogue(
    snapshot: Mapping[str, Any], config: Mapping[str, Any], openssl_names: Mapping[str, str]
) -> list[Policy]:
    """Every policy, providers in a fixed order and pages in theirs."""
    mapping = name_map(snapshot, openssl_names)
    retrieved = str(config["retrieved"])
    statements = config.get("statements", {})
    policies: list[Policy] = []
    for provider in ("aws_alb", "aws_nlb"):
        facts = {"retrieved": retrieved, **statements.get(provider, {})}
        policies += elb_policies(provider, snapshot[provider], mapping, facts)
    policies += cloudfront_policies(snapshot["aws_cloudfront"], mapping, retrieved)
    policies += gateway_policies(snapshot["aws_api_gateway"], mapping, retrieved)
    policies += mozilla_policies(snapshot["mozilla"], retrieved)
    # ALB and NLB publish policies of the same names, so ids are unique per provider.
    keys = [(p["provider"], p["id"]) for p in policies]
    if len(keys) != len(set(keys)):
        raise CatalogueError(
            f"duplicate policies: {sorted({k for k in keys if keys.count(k) > 1})}"
        )
    return policies


def compact(entry: Policy) -> Policy:
    """Drop empty and false fields, as the Rust loader defaults them."""
    return {k: v for k, v in entry.items() if v not in ([], False, None, "") or k == "protocols"}


def render_catalogue(policies: list[Policy], snapshot_digest: str) -> str:
    """The catalogue YAML."""
    header = (
        "# @generated by scripts/fetch_aws_tls_policies.py from the AWS and Mozilla\n"
        f"# pages listed in scripts/tls_policies.yaml (snapshot sha256 {snapshot_digest}).\n"
        "# Do not edit; refresh the snapshot and regenerate. Schema: tls_policies.schema.json\n"
    )
    body = yaml.safe_dump(
        {"version": 1, "policies": [compact(p) for p in policies]},
        sort_keys=False,
        allow_unicode=True,
        width=100,
    )
    return header + body


@click.group()
def main() -> None:
    """Build and check dcert's TLS security policy catalogue."""


@main.command("download")
@click.option("--check", is_flag=True, help="Fail instead of writing when the snapshot is stale.")
@click.option(
    "--print-copy",
    is_flag=True,
    help="On a difference, print the live snapshot base64 encoded with its SHA-256.",
)
def download_command(check: bool, print_copy: bool) -> None:
    """Reduce the source pages to a snapshot, or check the vendored one."""
    config = load_config()
    snapshot_path: Path = config["snapshot"]
    limit = config["max_download_bytes"]
    timeout = config["download_timeout_seconds"]
    live = encode(build_snapshot(config["sources"], lambda url: download(url, limit, timeout)))
    current = snapshot_path.read_bytes() if snapshot_path.exists() else b""
    if current == live:
        click.echo(f"{snapshot_path.name} matches the published sources")
        return
    digest = hashlib.sha256(live).hexdigest()
    if not check:
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_bytes(live)
        today = dt.datetime.now(dt.UTC).date()
        if "config_path" in config:
            set_retrieved(config["config_path"], today)
        click.echo(
            f"wrote {snapshot_path} (sha256 {digest}, retrieved {today.isoformat()}); "
            "now run generate"
        )
        return
    click.echo(
        f"{snapshot_path.name} differs from the published sources (sha256 {digest})", err=True
    )
    if print_copy:
        click.echo("live snapshot, base64:")
        click.echo(base64.encodebytes(live).decode("ascii"), nl=False)
    sys.exit(1)


@main.command("generate")
@click.option("--check", is_flag=True, help="Fail instead of writing when the catalogue is stale.")
def generate_command(check: bool) -> None:
    """Write kb/tls_policies.yaml from the snapshot."""
    config = load_config()
    raw = config["snapshot"].read_bytes()
    names = yaml.safe_load(config["openssl_names"].read_text(encoding="utf-8")) or {}
    catalogue = render_catalogue(
        build_catalogue(json.loads(raw), config, names), hashlib.sha256(raw).hexdigest()
    )
    output: Path = config["catalogue"]
    current = output.read_text(encoding="utf-8") if output.exists() else ""
    if current == catalogue:
        click.echo(f"{output.name} is current")
        return
    if check:
        click.echo(
            f"{output.name} is stale; run scripts/fetch_aws_tls_policies.py generate", err=True
        )
        sys.exit(1)
    output.write_text(catalogue, encoding="utf-8")
    click.echo(f"wrote {output}")


if __name__ == "__main__":
    main()
