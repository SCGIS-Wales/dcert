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
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
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
    for key in ("snapshot", "catalogue"):
        config[key] = PROJECT_ROOT / config[key]
    return config


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
        click.echo(f"wrote {snapshot_path} (sha256 {digest}, {dt.date.today().isoformat()})")
        return
    click.echo(
        f"{snapshot_path.name} differs from the published sources (sha256 {digest})", err=True
    )
    if print_copy:
        click.echo("live snapshot, base64:")
        click.echo(base64.encodebytes(live).decode("ascii"), nl=False)
    sys.exit(1)


if __name__ == "__main__":
    main()
