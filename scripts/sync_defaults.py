#!/usr/bin/env python3
"""Keep the Python package's defaults in step with the Rust CLI.

``src/limits.rs`` defines every default once. This script copies the values
named in ``scripts/sync_defaults.yaml`` into ``python/src/dcert/config.yaml``,
editing only the value of each listed key so comments and layout survive.

Usage::

    python scripts/sync_defaults.py            # rewrite config.yaml
    python scripts/sync_defaults.py --check    # exit 1 if it is stale (CI)
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path

import click
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MAPPING = PROJECT_ROOT / "scripts" / "sync_defaults.yaml"

# `pub const NAME: TYPE = VALUE;` with a string or integer literal value.
CONST_RE = re.compile(
    r'^pub const (?P<name>[A-Z0-9_]+): [^=]+= (?P<value>"(?:[^"\\]|\\.)*"|[0-9_]+);',
    re.MULTILINE,
)


def rust_constants(source: str) -> dict[str, str | int]:
    """Every string and integer constant in a Rust source file."""
    constants: dict[str, str | int] = {}
    for match in CONST_RE.finditer(source):
        raw = match.group("value")
        value: str | int = json.loads(raw) if raw.startswith('"') else int(raw.replace("_", ""))
        constants[match.group("name")] = value
    return constants


def render(value: str | int) -> str:
    """A YAML scalar for ``value``: integers bare, strings double quoted."""
    return str(value) if isinstance(value, int) else json.dumps(value)


def set_value(lines: list[str], dotted_key: str, value: str | int) -> list[str]:
    """Return ``lines`` with the value of ``section.key`` replaced.

    Only two level keys are supported, which is all the mapping uses.
    """
    section, key = dotted_key.split(".", 1)
    in_section = False
    for index, line in enumerate(lines):
        if not line.startswith((" ", "#")) and line.strip():
            in_section = line.rstrip() == f"{section}:"
            continue
        match = re.match(rf"^(\s+){re.escape(key)}:\s", line)
        if in_section and match:
            updated = list(lines)
            updated[index] = f"{match.group(1)}{key}: {render(value)}\n"
            return updated
    raise click.ClickException(f"{dotted_key} not found in the target file")


def synced(target_text: str, keys: Mapping[str, str], constants: Mapping[str, str | int]) -> str:
    """The target file text with every mapped key set from ``constants``."""
    lines = target_text.splitlines(keepends=True)
    for dotted_key, constant in keys.items():
        if constant not in constants:
            raise click.ClickException(f"{constant} is not defined in the source file")
        lines = set_value(lines, dotted_key, constants[constant])
    return "".join(lines)


@click.command()
@click.option(
    "--mapping",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_MAPPING,
    show_default=True,
)
@click.option("--check", is_flag=True, help="Fail instead of rewriting when the target is stale.")
def main(mapping: Path, check: bool) -> None:
    """Copy the Rust defaults into the Python configuration file."""
    spec = yaml.safe_load(mapping.read_text(encoding="utf-8"))
    source = PROJECT_ROOT / spec["source"]
    target = PROJECT_ROOT / spec["target"]
    current = target.read_text(encoding="utf-8")
    expected = synced(current, spec["keys"], rust_constants(source.read_text(encoding="utf-8")))
    if current == expected:
        click.echo(f"{spec['target']} matches {spec['source']}")
        return
    if check:
        click.echo(f"{spec['target']} is stale; run python scripts/sync_defaults.py", err=True)
        sys.exit(1)
    target.write_text(expected, encoding="utf-8")
    click.echo(f"updated {spec['target']} from {spec['source']}")


if __name__ == "__main__":
    main()
