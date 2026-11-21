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
4. The same with uv: ``uv pip install`` into a fresh environment, ``uv tool
   install dcert-mcp --with-executables-from dcert`` (three commands on PATH)
   and ``uvx --from dcert==<version> dcert``.

Scenarios 2 and 3 also hold an MCP session over stdio with the Rust server
and with the proxy: ``initialize`` must report ``dcert-mcp`` at the wheel
version, and ``tools/list`` must name exactly the tools in the README table.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import venv
from collections.abc import Mapping
from pathlib import Path

EXTRA_HINT = 'pip install "dcert-mcp[proxy]"'
README = Path(__file__).resolve().parent.parent.parent / "README.md"
EXE = ".exe" if sys.platform == "win32" else ""
HANDSHAKE = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "wheel-install-check", "version": "0"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
]


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


def readme_tools() -> list[str]:
    """Tool names in the first table after ``### Tools`` in the README."""
    lines = README.read_text(encoding="utf-8").splitlines()
    names: list[str] = []
    for line in lines[lines.index("### Tools") + 1 :]:
        match = re.match(r"^\|\s*`([a-z0-9_]+)`\s*\|", line)
        if match:
            names.append(match[1])
        elif names and not line.startswith("|"):
            break
    return sorted(names)


def handshake(command: list[str], version: str, env: Mapping[str, str] | None = None) -> None:
    """``initialize`` and ``tools/list`` over stdio; checks identity and the tool list."""
    print("+ handshake:", " ".join(command), flush=True)
    with subprocess.Popen(  # noqa: S603 - an installed dcert-mcp or proxy
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env=dict(env) if env is not None else None,
    ) as proc:
        if proc.stdin is None or proc.stdout is None:
            raise SystemExit("could not open the server's stdio")
        proc.stdin.write("".join(json.dumps(m) + "\n" for m in HANDSHAKE))
        proc.stdin.flush()
        replies: dict[int, dict[str, object]] = {}
        for line in proc.stdout:
            message = json.loads(line)
            if message.get("id") in (1, 2):
                replies[message["id"]] = message
            if len(replies) == 2:
                break
        proc.kill()
    if len(replies) != 2 or any("result" not in r for r in replies.values()):
        raise SystemExit(f"{command[0]} did not answer initialize and tools/list: {replies}")
    info = replies[1]["result"]["serverInfo"]  # type: ignore[index]
    tools = sorted(t["name"] for t in replies[2]["result"]["tools"])  # type: ignore[index]
    if info["name"] != "dcert-mcp" or info["version"] != version:
        raise SystemExit(f"{command[0]} reports {info}, expected dcert-mcp {version}")
    if tools != readme_tools():
        raise SystemExit(
            f"{command[0]} tools differ from the README: {set(tools) ^ set(readme_tools())}"
        )
    print(f"  {info['name']} {info['version']}: {len(tools)} tools", flush=True)


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
    handshake([str(env.bin / f"dcert-mcp{EXE}")], version)


def check_proxy_extra(root: Path, wheels: Path, version: str) -> None:
    """Scenario 3: the extra's third party packages come from PyPI."""
    env = Env(root, "proxy")
    # The local wheels first, so the extra keeps them even when PyPI already
    # has a release of the same version (a re-run, or a local check).
    env.pip("--no-index", "--find-links", str(wheels), "dcert-mcp")
    env.pip("--find-links", str(wheels), f"dcert-mcp[proxy]=={version}")
    env.script("dcert-mcp-proxy", "--help")
    run(
        [
            env.python,
            "-c",
            "import dcert_mcp; dcert_mcp.create_server; dcert_mcp.analyze_certificate",
        ]
    )
    # The proxy finds dcert-mcp on PATH, as it does for a user with the
    # environment activated.
    path = os.pathsep.join([str(env.bin), os.environ.get("PATH", "")])
    handshake([str(env.bin / f"dcert-mcp-proxy{EXE}")], version, {**os.environ, "PATH": path})


def check_uv(root: Path, wheels: Path, version: str) -> None:
    """Scenario 4: uv pip, uv tool install and uvx, all from the local wheels."""
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv is not on PATH (pip install uv)")
    local = ["--no-index", "--find-links", str(wheels)]
    env = {**os.environ, "UV_CACHE_DIR": str(root / "uv-cache")}

    target = root / "uv-env"
    run([uv, "venv", "--quiet", str(target)])
    run([uv, "pip", "install", "--quiet", "--python", str(target), *local, "dcert-mcp"])
    listed = json.loads(
        run([uv, "pip", "list", "--python", str(target), "--format", "json"]).stdout
    )
    installed = {p["name"].lower(): p["version"] for p in listed}
    if installed != {"dcert": version, "dcert-mcp": version}:
        raise SystemExit(f"uv pip install dcert-mcp installed {installed}")
    run([str(bin_dir(target) / f"dcert-mcp{EXE}"), "--version"])

    tool_bin = root / "uv-tool-bin"
    tool_env = {**env, "UV_TOOL_DIR": str(root / "uv-tools"), "UV_TOOL_BIN_DIR": str(tool_bin)}
    print("+ uv tool install dcert-mcp --with-executables-from dcert", flush=True)
    subprocess.run(  # noqa: S603 - uv with fixed arguments
        [uv, "tool", "install", *local, "dcert-mcp", "--with-executables-from", "dcert"],
        check=True,
        env=tool_env,
        timeout=900,
    )
    linked = sorted(p.name.removesuffix(".exe") for p in tool_bin.iterdir())
    if linked != ["dcert", "dcert-mcp", "dcert-mcp-proxy"]:
        raise SystemExit(f"uv tool install linked {linked}")
    run([str(tool_bin / f"dcert{EXE}"), "--version"])

    print(f"+ uvx --from dcert=={version} dcert --version", flush=True)
    out = subprocess.run(  # noqa: S603 - uvx with fixed arguments
        [uv, "tool", "run", *local, "--from", f"dcert=={version}", "dcert", "--version"],
        check=True,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    ).stdout
    if not out.startswith(f"dcert {version}"):
        raise SystemExit(f"uvx dcert --version printed {out!r}")


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
        check_uv(root, wheels, version)
    print(f"dcert and dcert-mcp {version} install and run on {sys.platform}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
