#!/usr/bin/env python3
"""Keep the OpenSSL floors and the Windows source pin in step with upstream.

The floors in ``scripts/openssl_floor.yaml`` are the newest patch release on
each supported branch, and the Windows build links the pinned 3.5 source.
OpenSSL publishes security fixes as patch releases at no fixed date, so this
script compares the file with the releases on github.com/openssl/openssl
instead of a guessed calendar:

``check``
    Exit 1, naming the command to run, when a branch has a newer patch release
    than its floor or the Windows pin. The scheduled audit runs it daily, so a
    new OpenSSL release opens the "Security audit failing" issue the same day.

``update``
    Raise the floors and the Windows pin to the newest releases. The new
    tarball is downloaded and its SHA256 compared with the ``.sha256`` file
    published with the release before the pin is written; the build verifies
    that pin again before compiling. Comments in the YAML file are kept.

Usage::

    python scripts/ci/openssl_upstream.py check
    python scripts/ci/openssl_upstream.py update

Set ``GH_TOKEN`` (or ``GITHUB_TOKEN``) to avoid the unauthenticated API rate limit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.request
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import click
import yaml

FLOORS = Path(__file__).resolve().parent.parent / "openssl_floor.yaml"
RELEASES_API = "https://api.github.com/repos/openssl/openssl/releases?per_page=100&page={page}"
ASSET_URL = "https://github.com/openssl/openssl/releases/download/openssl-{v}/openssl-{v}.tar.gz"
#: Stable release tags only: ``openssl-3.5.9``, not ``openssl-4.0.0-beta1``.
TAG = re.compile(r"^openssl-(\d+)\.(\d+)\.(\d+)$")
TIMEOUT = 60

Version = tuple[int, int, int]


def parse(version: str) -> Version:
    """``"3.5.9"`` as ``(3, 5, 9)``."""
    major, minor, patch = (int(p) for p in version.split("."))
    return major, minor, patch


def show(version: Version) -> str:
    return ".".join(str(p) for p in version)


def latest_patches(tags: Iterable[str], branches: Iterable[str]) -> dict[str, Version]:
    """The newest stable patch release per ``branches`` entry (``"3.5"``) among ``tags``."""
    wanted = {tuple(int(p) for p in b.split(".")): b for b in branches}
    newest: dict[str, Version] = {}
    for tag in tags:
        match = TAG.match(tag)
        if not match:
            continue
        version: Version = (int(match[1]), int(match[2]), int(match[3]))
        branch = wanted.get(version[:2])
        if branch is not None and version > newest.get(branch, (0, 0, 0)):
            newest[branch] = version
    return newest


def lagging(spec: Mapping[str, Any], latest: Mapping[str, Version]) -> list[str]:
    """One line per floor or pin that is older than the newest upstream release."""
    problems = []
    for branch, floor in sorted((spec.get("floors") or {}).items()):
        newest = latest.get(branch)
        if newest is not None and parse(str(floor)) < newest:
            problems.append(
                f"OpenSSL {show(newest)} is released; the {branch} floor is still {floor}"
            )
    pin = str(spec["windows_source"]["version"])
    newest_pin = latest.get(".".join(pin.split(".")[:2]))
    if newest_pin is not None and parse(pin) < newest_pin:
        problems.append(
            f"OpenSSL {show(newest_pin)} is released; the Windows build still pins {pin}"
        )
    return problems


def rewrite(
    text: str, latest: Mapping[str, Version], pin_version: str | None, pin_sha256: str | None
) -> str:
    """``text`` with raised floors and, when given, a new Windows pin. Comments are kept."""
    for branch, version in latest.items():
        pattern = re.compile(rf'(?m)^(\s*"{re.escape(branch)}":\s*)"(\d+\.\d+\.\d+)"')

        def raise_floor(match: re.Match[str], newest: Version = version) -> str:
            return match[1] + f'"{show(max(parse(match[2]), newest))}"'

        text = pattern.sub(raise_floor, text, count=1)
    if pin_version is not None and pin_sha256 is not None:
        section = text.index("windows_source:")
        head, tail = text[:section], text[section:]
        tail = re.sub(r'(?m)^(  version:\s*)"[^"]*"', rf'\g<1>"{pin_version}"', tail, count=1)
        tail = re.sub(r'(?m)^(  sha256:\s*)"[^"]*"', rf'\g<1>"{pin_sha256}"', tail, count=1)
        text = head + tail
    return text


def sha256_line(text: str) -> str:
    """The hex digest in a ``.sha256`` file (``<hex>`` or ``<hex>  <name>``)."""
    match = re.search(r"\b([0-9a-f]{64})\b", text.lower())
    if not match:
        raise click.ClickException("the published .sha256 file has no SHA256 digest")
    return match[1]


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "dcert-openssl-upstream"})  # noqa: S310
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310 (https only)
        return bytes(response.read())


def release_tags() -> list[str]:
    tags: list[str] = []
    for page in range(1, 6):
        batch = json.loads(_get(RELEASES_API.format(page=page)))
        tags.extend(
            str(r["tag_name"]) for r in batch if not r.get("draft") and not r.get("prerelease")
        )
        if len(batch) < 100:
            break
    return tags


def verified_sha256(version: str) -> str:
    """Download the release tarball and return its SHA256 once it matches the published one."""
    url = ASSET_URL.format(v=version)
    published = sha256_line(_get(url + ".sha256").decode("utf-8", "replace"))
    actual = hashlib.sha256(_get(url)).hexdigest()
    if actual != published:
        raise click.ClickException(
            f"{url}: SHA256 {actual} does not match the published {published}"
        )
    return actual


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


@click.group()
def main() -> None:
    """Compare or update scripts/openssl_floor.yaml against OpenSSL releases."""


@main.command()
@click.option("--floors", type=click.Path(path_type=Path), default=FLOORS, show_default=True)
def check(floors: Path) -> None:
    """Fail when a newer OpenSSL patch release exists than the floors or the pin."""
    spec = yaml.safe_load(floors.read_text(encoding="utf-8"))
    latest = latest_patches(release_tags(), (spec.get("floors") or {}).keys())
    problems = lagging(spec, latest)
    for branch, version in sorted(latest.items()):
        click.echo(f"OpenSSL {branch}: newest release {show(version)}")
    if problems:
        for line in problems:
            click.echo(f"::error::{line}", err=True)
        click.echo(
            "Run: python scripts/ci/openssl_upstream.py update  (then open a pull request)",
            err=True,
        )
        sys.exit(1)
    click.echo("floors and the Windows pin are current")


@main.command()
@click.option("--floors", type=click.Path(path_type=Path), default=FLOORS, show_default=True)
def update(floors: Path) -> None:
    """Raise the floors and the Windows pin to the newest releases."""
    text = floors.read_text(encoding="utf-8")
    spec = yaml.safe_load(text)
    latest = latest_patches(release_tags(), (spec.get("floors") or {}).keys())
    pin = str(spec["windows_source"]["version"])
    newest_pin = latest.get(".".join(pin.split(".")[:2]))
    pin_version = pin_sha = None
    if newest_pin is not None and parse(pin) < newest_pin:
        pin_version = show(newest_pin)
        pin_sha = verified_sha256(pin_version)
        click.echo(
            f"Windows pin {pin} -> {pin_version} (sha256 {pin_sha}, verified against the release)"
        )
    updated = rewrite(text, latest, pin_version, pin_sha)
    if updated == text:
        click.echo("already current")
        return
    floors.write_text(updated, encoding="utf-8")
    if lagging(yaml.safe_load(updated), latest):
        raise click.ClickException("the file was rewritten but still lags; edit it by hand")
    click.echo(f"updated {floors}")


if __name__ == "__main__":
    main()
