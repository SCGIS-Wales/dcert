#!/usr/bin/env python3
"""Fail when a built dcert binary links an OpenSSL below its recorded floor.

Runs ``<binary> --version``, reads the OpenSSL version it reports and compares
it with ``scripts/openssl_floor.yaml``.

Usage::

    python scripts/check_openssl_floor.py dist-bin/dcert
"""

from __future__ import annotations

import datetime
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import click
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FLOORS = PROJECT_ROOT / "scripts" / "openssl_floor.yaml"
VERSION_RE = re.compile(r"^OpenSSL (\d+)\.(\d+)\.(\d+)", re.MULTILINE)
MAX_EXCEPTION_DAYS = 30

Version = tuple[int, int, int]


def parse_openssl_version(version_output: str) -> Version:
    """The ``(major, minor, patch)`` of the OpenSSL line in ``--version`` output."""
    match = VERSION_RE.search(version_output)
    if not match:
        raise click.ClickException("no 'OpenSSL x.y.z' line in the --version output")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def parse_triplet(text: str) -> Version:
    parts = text.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise click.ClickException(f"not a x.y.z version: {text!r}")
    return int(parts[0]), int(parts[1]), int(parts[2])


def branch_key(branch: str) -> tuple[int, int]:
    major, minor = branch.split(".")
    return int(major), int(minor)


def effective_floors(spec: Mapping[str, Any], today: datetime.date) -> dict[str, str]:
    """The floors in force on ``today``: base floors plus every scheduled bump that is due."""
    floors = {str(k): str(v) for k, v in spec["floors"].items()}
    for entry in sorted(spec.get("scheduled") or [], key=lambda e: e["date"]):
        if entry["date"] <= today:
            floors.update({str(k): str(v) for k, v in entry["floors"].items()})
    return floors


def expired_exceptions(spec: Mapping[str, Any], today: datetime.date) -> list[str]:
    """Problems with the exception list itself: missing fields, too long, or expired."""
    problems: list[str] = []
    for entry in spec.get("exceptions") or []:
        branch = entry.get("branch", "?")
        missing = [k for k in ("branch", "owner", "reason", "expires") if not entry.get(k)]
        if missing:
            problems.append(f"exception for {branch} lacks {', '.join(missing)}")
            continue
        if entry["expires"] < today:
            problems.append(f"exception for {branch} expired on {entry['expires']}")
    return problems


def verdict(version: Version, spec: Mapping[str, Any], today: datetime.date) -> str | None:
    """None when the version is acceptable, otherwise the reason it is not."""
    problems = expired_exceptions(spec, today)
    if problems:
        return "; ".join(problems)
    text = ".".join(map(str, version))
    branch = f"{version[0]}.{version[1]}"
    floors = effective_floors(spec, today)
    if branch in floors:
        if version >= parse_triplet(floors[branch]):
            return None
        return f"OpenSSL {text} is below the {branch} floor {floors[branch]}"
    if branch in {str(b) for b in spec.get("distro_managed") or []}:
        return None
    if branch_key(branch) > max(branch_key(b) for b in floors):
        return None
    for entry in spec.get("exceptions") or []:
        if str(entry["branch"]) == branch:
            limit = today + datetime.timedelta(days=MAX_EXCEPTION_DAYS)
            if entry["expires"] > limit:
                return (
                    f"exception for {branch} expires {entry['expires']}, "
                    f"more than {MAX_EXCEPTION_DAYS} days ahead"
                )
            click.echo(
                f"note: OpenSSL {text} is covered by an exception until {entry['expires']}",
                err=True,
            )
            return None
    return f"OpenSSL {text} is on branch {branch}, which has no floor and no exception"


def run_version(binary: Path) -> str:
    result = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=False)  # noqa: S603
    if result.returncode != 0:
        raise click.ClickException(f"{binary} --version failed: {result.stderr.strip()}")
    return result.stdout


@click.command()
@click.option(
    "--report-only",
    is_flag=True,
    help="Print the verdict but exit 0 (for binaries that link the host's OpenSSL dynamically).",
)
@click.argument("binary", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--floors",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_FLOORS,
    show_default=True,
)
@click.option(
    "--today",
    type=click.DateTime(formats=["%Y-%m-%d"]),
    default=None,
    help="Override today's date (tests).",
)
def main(binary: Path, floors: Path, today: datetime.datetime | None, report_only: bool) -> None:
    """Check the OpenSSL linked into BINARY against the recorded floor."""
    spec = yaml.safe_load(floors.read_text(encoding="utf-8"))
    day = today.date() if today else datetime.datetime.now(datetime.timezone.utc).date()  # noqa: UP017 - 3.10 runners lack datetime.UTC
    version = parse_openssl_version(run_version(binary))
    reason = verdict(version, spec, day)
    text = ".".join(map(str, version))
    if reason:
        if report_only:
            click.echo(f"report only {binary}: {reason}", err=True)
            return
        click.echo(f"FAIL {binary}: {reason}", err=True)
        sys.exit(1)
    click.echo(f"ok {binary}: OpenSSL {text}")


if __name__ == "__main__":
    main()
