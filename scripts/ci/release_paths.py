#!/usr/bin/env python3
"""Decide whether a push to main cuts a release.

Every merge to main used to tag a release, so documentation-only pull requests
published new versions to every channel. ``auto-tag`` in ``ci.yml`` now asks
this script first: when every path the push changed matches
``scripts/release_paths.yaml``, or the head commit title carries the skip
marker, it prints ``release=false`` and no tag is created.

``auto-tag`` passes the newest release tag as ``--before``, so the paths are
everything merged since the last release. Comparing with the previous push
instead would lose a change whose run was cancelled while it waited in the
main queue (a newer push cancels a pending run).

Usage::

    python scripts/ci/release_paths.py --before <sha> --after <sha> --title "<commit title>"

The answer is written to ``$GITHUB_OUTPUT`` when that is set, and always to
stdout. Anything uncertain (no tag, a failed diff) means a release, so the
filter can only ever skip a release for a change it has positively
classified.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import click
import yaml

CONFIG = Path(__file__).resolve().parent.parent / "release_paths.yaml"
NULL_SHA = re.compile(r"^0+$")


def pattern_regex(pattern: str) -> re.Pattern[str]:
    """A regex for one glob: ``*`` within a segment, ``**/`` any leading dirs, ``/**`` below."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("/**", i) and i + 3 == len(pattern):
            out.append("/.+")
            i += 3
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def releasable(paths: Iterable[str], patterns: Sequence[str]) -> list[str]:
    """The paths that match no ``no_release`` pattern, so they need a release."""
    regexes = [pattern_regex(p) for p in patterns]
    return [p for p in paths if not any(r.match(p) for r in regexes)]


def decide(paths: Sequence[str] | None, title: str, config: dict[str, Any]) -> tuple[bool, str]:
    """``(release, reason)`` for a push with ``paths`` changed (None: unknown)."""
    marker = str(config.get("skip_marker") or "")
    if marker and marker in title:
        return False, f"the commit title contains {marker}"
    if paths is None:
        return True, "the changed paths are unknown, so release"
    if not paths:
        return False, "nothing changed since the last release"
    needing = releasable(paths, list(config.get("no_release") or []))
    if needing:
        shown = ", ".join(needing[:5]) + (" ..." if len(needing) > 5 else "")
        return True, f"{len(needing)} changed path(s) need a release: {shown}"
    return False, f"all {len(paths)} changed path(s) are documentation only"


def changed_paths(before: str, after: str) -> list[str] | None:
    """Paths changed between two commits, or None when git cannot tell."""
    if not before or NULL_SHA.match(before):
        return None
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "diff", "--name-only", "--no-renames", before, after],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


@click.command()
@click.option("--before", default="", help="The newest release tag (or any earlier commit).")
@click.option("--after", default="HEAD", show_default=True, help="The pushed commit.")
@click.option("--title", default="", help="The head commit title.")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=CONFIG)
def main(before: str, after: str, title: str, config_path: Path) -> None:
    """Print release=true or release=false for this push."""
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    first_line = title.splitlines()[0] if title else ""
    release, reason = decide(changed_paths(before, after), first_line, config)
    line = f"release={'true' if release else 'false'}"
    click.echo(f"{line} ({reason})")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


if __name__ == "__main__":
    main()
