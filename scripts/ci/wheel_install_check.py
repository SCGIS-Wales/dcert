"""Install the built ``dcert`` and ``dcert-mcp`` wheels the way a user would.

Usage: ``python scripts/ci/wheel_install_check.py WHEEL_DIR``

Each scenario runs in a fresh virtual environment and installs from the local
wheel directory, because the packages are not on PyPI until the release
publishes them:

1. ``pip install dcert`` runs the Rust CLI and installs no third party package.
2. ``pip install dcert-mcp`` runs the Rust server, installs ``dcert`` at the
   same version and nothing else, and ``dcert-mcp-proxy`` explains the missing
   extra in one line.
3. ``pip install "dcert-mcp[proxy]"`` (the extra's packages come from PyPI)
   makes ``dcert-mcp-proxy --help`` and the typed helpers work.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

EXTRA_HINT = 'pip install "dcert-mcp[proxy]"'


def bin_dir(env_dir: Path) -> Path:
    """Return the directory holding the scripts of a virtual environment."""
    return env_dir / ("Scripts" if sys.platform == "win32" else "bin")


def run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command, echo it and its output, and return the result."""
    print("+", " ".join(args), flush=True)
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=900)  # noqa: S603
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if check and result.returncode != 0:
        raise SystemExit(f"command failed with status {result.returncode}: {' '.join(args)}")
    return result


class Env:
    """A virtual environment with helpers to install into it and run its scripts."""

    def __init__(self, root: Path, name: str) -> None:
        self.path = root / name
        venv.create(self.path, with_pip=True)
        self.bin = bin_dir(self.path)
        self.python = str(self.bin / "python")

    def pip(self, *args: str) -> None:
        """Run ``pip`` with *args* in this environment."""
        run([self.python, "-m", "pip", "install", "--quiet", *args])

    def script(self, name: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        """Run the console script *name*."""
        return run([str(self.bin / name), *args], check=check)

    def installed(self) -> dict[str, str]:
        """Return ``{distribution: version}`` for everything except pip tooling."""
        out = run([self.python, "-m", "pip", "list", "--format", "json"]).stdout
        packages = {p["name"].lower(): p["version"] for p in json.loads(out)}
        return {k: v for k, v in packages.items() if k not in {"pip", "setuptools", "wheel"}}


def check_dcert(root: Path, wheels: Path) -> str:
    """Scenario 1; returns the installed version."""
    env = Env(root, "dcert")
    env.pip("--no-index", "--find-links", str(wheels), "dcert")
    installed = env.installed()
    if set(installed) != {"dcert"}:
        raise SystemExit(f"pip install dcert installed {sorted(installed)}")
    out = env.script("dcert", "--version").stdout
    if not out.startswith("dcert "):
        raise SystemExit(f"unexpected `dcert --version` output: {out!r}")
    return installed["dcert"]


def check_dcert_mcp(root: Path, wheels: Path, version: str) -> None:
    """Scenario 2."""
    env = Env(root, "mcp")
    env.pip("--no-index", "--find-links", str(wheels), "dcert-mcp")
    installed = env.installed()
    if installed != {"dcert": version, "dcert-mcp": version}:
        raise SystemExit(f"pip install dcert-mcp installed {installed}, expected only dcert")
    if not env.script("dcert-mcp", "--version").stdout.startswith("dcert-mcp "):
        raise SystemExit("`dcert-mcp --version` did not print the Rust server version")
    env.script("dcert", "--version")
    proxy = env.script("dcert-mcp-proxy", check=False)
    lines = proxy.stderr.strip().splitlines()
    if proxy.returncode != 1 or len(lines) != 1 or EXTRA_HINT not in lines[0]:
        raise SystemExit(f"dcert-mcp-proxy without the extra printed {proxy.stderr!r}")
    imported = run([env.python, "-c", "import dcert_mcp; print(dcert_mcp.__version__)"])
    if imported.stdout.strip() != version:
        raise SystemExit("dcert_mcp.__version__ does not match the wheel version")


def check_proxy_extra(root: Path, wheels: Path, version: str) -> None:
    """Scenario 3: the extra's third party packages come from PyPI."""
    env = Env(root, "proxy")
    env.pip("--find-links", str(wheels), f"dcert-mcp[proxy]=={version}")
    env.script("dcert-mcp-proxy", "--help")
    run(
        [
            env.python,
            "-c",
            "import dcert_mcp; dcert_mcp.create_server; dcert_mcp.analyze_certificate",
        ]
    )


def main(argv: list[str]) -> int:
    """Run the scenarios against the wheels in ``argv[0]``; returns the exit status."""
    if len(argv) != 1 or not Path(argv[0]).is_dir():
        sys.stderr.write("usage: wheel_install_check.py WHEEL_DIR\n")
        return 2
    wheels = Path(argv[0]).resolve()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        version = check_dcert(root, wheels)
        check_dcert_mcp(root, wheels, version)
        check_proxy_extra(root, wheels, version)
    print(f"dcert and dcert-mcp {version} install and run on {sys.platform}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
