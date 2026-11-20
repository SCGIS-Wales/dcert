#!/usr/bin/env python3
"""Fail when an advisory ignore entry has no expiry or is past it.

Every entry in an ``ignore = [...]`` list of ``.cargo/audit.toml`` and
``deny.toml`` must carry an ``expires: YYYY-MM-DD`` note in the comment lines
directly above it (or on the same line), and that date must not have passed.
An exception is allowed only when no upstream fix exists; see section 2 of the
security plan. Empty lists, the target state, pass.

Usage::

    python scripts/check_exceptions.py
"""

from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path

import click
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FILES = (".cargo/audit.toml", "deny.toml", "scripts/openssl_floor.yaml")
# The body of an ignore list: everything up to the first closing bracket.
IGNORE_BLOCK_RE = re.compile(r"^ignore\s*=\s*\[(?P<body>[^\]]*)\]", re.MULTILINE)
EXPIRES_RE = re.compile(r"expires:\s*(\d{4}-\d{2}-\d{2})")
ENTRY_RE = re.compile(
    r'^\s*(?:"(?P<plain>[^"]+)"|\{.*?id\s*=\s*"(?P<table>[^"]+)".*?\})\s*,?\s*(?P<tail>#.*)?$'
)


def entries(text: str) -> list[tuple[str, list[str]]]:
    """``(id, comments)`` per ignore entry: the comment lines above it plus a trailing one."""
    found: list[tuple[str, list[str]]] = []
    for block in IGNORE_BLOCK_RE.finditer(text):
        pending: list[str] = []
        for line in block.group("body").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                pending.append(stripped)
                continue
            if not stripped:
                continue
            match = ENTRY_RE.match(line)
            if match:
                advisory = match.group("plain") or match.group("table")
                comments = [*pending, match.group("tail") or ""]
                found.append((advisory, comments))
            pending = []
    return found


def problems(text: str, today: datetime.date) -> list[str]:
    """Human readable problems with the ignore entries in one file."""
    out: list[str] = []
    for advisory, comments in entries(text):
        dates = EXPIRES_RE.findall("\n".join(comments))
        if not dates:
            out.append(f"{advisory}: no 'expires: YYYY-MM-DD' comment")
            continue
        expires = datetime.date.fromisoformat(dates[-1])
        if expires < today:
            out.append(f"{advisory}: expired on {expires}")
    return out


def yaml_problems(text: str, today: datetime.date) -> list[str]:
    """Problems with the ``exceptions`` list of ``scripts/openssl_floor.yaml``."""
    out: list[str] = []
    for entry in (yaml.safe_load(text) or {}).get("exceptions") or []:
        name = f"OpenSSL {entry.get('branch', '?')}"
        expires = entry.get("expires")
        if not isinstance(expires, datetime.date):
            out.append(f"{name}: no expires date")
        elif expires < today:
            out.append(f"{name}: expired on {expires}")
    return out


@click.command()
@click.argument("files", nargs=-1, type=click.Path(path_type=Path))
@click.option(
    "--today",
    type=click.DateTime(formats=["%Y-%m-%d"]),
    default=None,
    help="Override today (tests).",
)
def main(files: tuple[Path, ...], today: datetime.datetime | None) -> None:
    """Check every ignore list for missing or expired exceptions."""
    day = today.date() if today else datetime.datetime.now(datetime.timezone.utc).date()
    targets = files or tuple(PROJECT_ROOT / name for name in DEFAULT_FILES)
    failed = False
    for path in targets:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        found = yaml_problems(text, day) if path.suffix == ".yaml" else problems(text, day)
        for problem in found:
            click.echo(f"{path.name}: {problem}", err=True)
            failed = True
    if failed:
        sys.exit(1)
    click.echo("no missing or expired advisory exceptions")


if __name__ == "__main__":
    main()
