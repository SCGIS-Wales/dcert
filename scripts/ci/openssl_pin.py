#!/usr/bin/env python3
"""Print one field of the pinned Windows OpenSSL source from openssl_floor.yaml.

Used by scripts/ci/build_openssl_windows.ps1, which cannot read YAML itself.

Usage::

    python scripts/ci/openssl_pin.py version
    python scripts/ci/openssl_pin.py url
    python scripts/ci/openssl_pin.py sha256
"""

from __future__ import annotations

from pathlib import Path

import click
import yaml

FLOORS = Path(__file__).resolve().parent.parent / "openssl_floor.yaml"


def pinned(field: str, text: str) -> str:
    """The value of ``field`` in the ``windows_source`` section, with ``{version}`` filled in."""
    section = yaml.safe_load(text)["windows_source"]
    if field not in section:
        raise click.ClickException(f"windows_source has no {field!r}")
    return str(section[field]).replace("{version}", str(section["version"]))


@click.command()
@click.argument("field", type=click.Choice(["version", "url", "sha256"]))
def main(field: str) -> None:
    """Print FIELD of the pinned Windows OpenSSL source."""
    click.echo(pinned(field, FLOORS.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
