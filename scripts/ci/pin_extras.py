#!/usr/bin/env python3
"""Hash-pinned requirement files for the extras of python/dcert-mcp.

``pip install "dcert-mcp[proxy]"`` resolves FastMCP and about sixty other
packages at install time, to whatever is newest within the declared ranges.
The files written here pin each of them, with hashes, for every platform:

* ``requirements/proxy.txt``: the ``proxy`` extra
* ``requirements/otel.txt``: ``proxy`` and ``otel``
* ``requirements/dev.txt``: ``proxy``, ``otel`` and ``dev`` (what CI installs)

Users who want a reproducible, verified install use
``pip install --require-hashes -r requirements/proxy.txt`` next to the
``dcert-mcp`` wheel. The files are compiled from the extras alone, not from
``dcert-mcp`` itself, because ``dcert-mcp`` pins ``dcert==<version>``, which
is not on PyPI until the release publishes it.

``uv pip compile`` keeps the pins already in a file when they still satisfy
the declared ranges, so ``--check`` only fails when ``pyproject.toml``
changes an extra; Dependabot raises the pins in place.

Usage::

    python scripts/ci/pin_extras.py           # write the files
    python scripts/ci/pin_extras.py --check   # fail if a file is out of date
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import click

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "python" / "dcert-mcp"
OUTPUT = PACKAGE / "requirements"
#: Requirement file name and the extras it combines.
FILES = {"proxy": ("proxy",), "otel": ("proxy", "otel"), "dev": ("proxy", "otel", "dev")}
#: The lowest Python the package supports; --universal covers every platform.
PYTHON = "3.12"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extras_requirements import requirements  # noqa: E402


def compile_file(uv: str, extras: tuple[str, ...], output: Path) -> None:
    """Compile the requirements of ``extras`` into ``output``.

    The input goes through stdin, so the "via" annotations name no temporary
    path and the file is the same on every machine.
    """
    subprocess.run(  # noqa: S603 - uv with fixed arguments
        [
            uv,
            "pip",
            "compile",
            "--quiet",
            "--universal",
            "--python-version",
            PYTHON,
            "--generate-hashes",
            "--no-header",
            "-",
            "-o",
            str(output),
        ],
        input="\n".join(requirements(list(extras))) + "\n",
        text=True,
        check=True,
    )


@click.command()
@click.option("--check", is_flag=True, help="Fail when a file would change instead of writing it.")
def main(check: bool) -> None:
    """Write (or check) the hash-pinned requirement files of the extras."""
    uv = shutil.which("uv")
    if uv is None:
        raise click.ClickException("uv is not on PATH (pip install uv)")
    OUTPUT.mkdir(exist_ok=True)
    stale = []
    for name, extras in FILES.items():
        target = OUTPUT / f"{name}.txt"
        before = target.read_text(encoding="utf-8") if target.exists() else None
        compile_file(uv, extras, target)
        after = target.read_text(encoding="utf-8")
        if before != after:
            stale.append(target)
            if check and before is not None:
                target.write_text(before, encoding="utf-8")
    if check and stale:
        for target in stale:
            click.echo(
                f"::error::{target.relative_to(ROOT)} is out of date; run "
                "python scripts/ci/pin_extras.py",
                err=True,
            )
        sys.exit(1)
    click.echo("requirement files are current" if not stale else f"wrote {len(stale)} file(s)")


if __name__ == "__main__":
    main()
