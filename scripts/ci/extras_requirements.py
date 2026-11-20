"""Print the requirements of the named extras of python/dcert-mcp, one per line.

CI installs these instead of the package itself: ``dcert-mcp`` pins ``dcert`` at
its own version, which is not on PyPI until the release publishes it.

Usage: ``python scripts/ci/extras_requirements.py proxy otel dev``
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10, where the matrix starts
    import tomli as tomllib  # type: ignore[no-redef]

PYPROJECT = Path(__file__).resolve().parents[2] / "python" / "dcert-mcp" / "pyproject.toml"


def requirements(extras: list[str], pyproject: Path = PYPROJECT) -> list[str]:
    """Return the requirements of *extras*, in order and without duplicates.

    Raises:
        KeyError: If an extra is not declared.
    """
    with pyproject.open("rb") as handle:
        declared = tomllib.load(handle)["project"]["optional-dependencies"]
    seen: dict[str, None] = {}
    for extra in extras:
        for requirement in declared[extra]:
            seen.setdefault(requirement)
    return list(seen)


def main(argv: list[str]) -> int:
    """Print the requirements; returns the process exit status."""
    if not argv:
        sys.stderr.write("usage: extras_requirements.py EXTRA [EXTRA...]\n")
        return 2
    try:
        sys.stdout.write("\n".join(requirements(argv)) + "\n")
    except KeyError as exc:
        sys.stderr.write(f"unknown extra {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
