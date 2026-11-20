#!/usr/bin/env python3
"""Check the dcert CLI dependency tree against its budget.

Runs ``cargo tree`` for the CLI feature set named in
``scripts/cli_deps_budget.yaml`` and compares the result with ``max_crates``
and ``banned_crates``. With ``enforce: false`` in the budget (or without
``--enforce``) it only reports.

Usage::

    python scripts/check_cli_deps.py            # follow the budget file
    python scripts/check_cli_deps.py --enforce  # always fail on a violation
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import click
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUDGET = PROJECT_ROOT / "scripts" / "cli_deps_budget.yaml"

# `name vX.Y.Z` optionally followed by `(proc-macro)`, a path or `(*)`.
LINE_RE = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+) v(?P<version>\S+)")


def parse_tree(text: str) -> set[tuple[str, str]]:
    """Unique ``(name, version)`` pairs in ``cargo tree --prefix none`` output."""
    crates: set[tuple[str, str]] = set()
    for line in text.splitlines():
        match = LINE_RE.match(line.strip())
        if match:
            crates.add((match.group("name"), match.group("version")))
    return crates


def violations(crates: Iterable[tuple[str, str]], budget: Mapping[str, Any]) -> list[str]:
    """Human readable budget violations, empty when the tree is within budget."""
    found = sorted(set(crates))
    problems: list[str] = []
    limit = int(budget["max_crates"])
    if len(found) > limit:
        problems.append(f"{len(found)} crates, budget is {limit}")
    banned = set(budget.get("banned_crates") or [])
    present = sorted({name for name, _ in found} & banned)
    problems.extend(f"banned crate in the CLI tree: {name}" for name in present)
    return problems


def cargo_tree(extra_args: Sequence[str], cwd: Path = PROJECT_ROOT) -> str:
    """The normal dependency tree of the package for the given feature flags."""
    command = ["cargo", "tree", "--locked", "-e", "normal", "--prefix", "none", *extra_args]
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)  # noqa: S603 - fixed argv, no shell
    if result.returncode != 0:
        raise click.ClickException(f"{' '.join(command)} failed:\n{result.stderr.strip()}")
    return result.stdout


@click.command()
@click.option(
    "--budget",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_BUDGET,
    show_default=True,
)
@click.option(
    "--enforce", is_flag=True, help="Fail on a violation even if the budget says report only."
)
def main(budget: Path, enforce: bool) -> None:
    """Report, or enforce, the CLI dependency budget."""
    spec = yaml.safe_load(budget.read_text(encoding="utf-8"))
    crates = parse_tree(cargo_tree(spec.get("cargo_args") or []))
    problems = violations(crates, spec)
    click.echo(f"dcert CLI tree: {len(crates)} unique crates (budget {spec['max_crates']})")
    if not problems:
        click.echo("within budget")
        return
    for problem in problems:
        click.echo(f"violation: {problem}", err=True)
    if enforce or spec.get("enforce"):
        sys.exit(1)
    click.echo("report only: not failing the build", err=True)


if __name__ == "__main__":
    main()
