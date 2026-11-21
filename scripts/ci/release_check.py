#!/usr/bin/env python3
"""Verify that a release reached every channel.

PyPI is missing dcert versions that have a git tag and a GitHub release,
because a publish job failed and nothing compared the channels afterwards.
These commands close that gap:

``wait-pypi``
    Poll the PyPI JSON API until both projects serve a version (the CDN can
    lag the upload by minutes), then exit 0; exit 1 after the timeout.

``handshake``
    Start an installed ``dcert-mcp``, send ``initialize`` and ``tools/list``
    over stdio, and require the expected version and the tools named in the
    README tool table.

``consistency``
    Check every channel of one release (GitHub release assets, both PyPI
    projects, the GHCR image tag, the Homebrew formula, the Chocolatey job's
    result) and write a table to ``$GITHUB_STEP_SUMMARY``. Exit 1 when a
    required channel is missing.

``pypi-parity``
    For the scheduled audit: the newest release older than the grace period
    must be installable (present and not yanked) from both PyPI projects.

Usage::

    python scripts/ci/release_check.py wait-pypi --version 4.0.9
    python scripts/ci/release_check.py handshake --binary .venv/bin/dcert-mcp --version 4.0.9
    python scripts/ci/release_check.py consistency --version 4.0.9 --chocolatey success
    python scripts/ci/release_check.py pypi-parity

Set ``GH_TOKEN`` (or ``GITHUB_TOKEN``) for the GitHub API calls.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any

import click

ROOT = Path(__file__).resolve().parent.parent.parent
PROJECTS = ("dcert", "dcert-mcp")
REPOSITORY = "SCGIS-Wales/dcert"
TAP = "SCGIS-Wales/homebrew-tap"
TIMEOUT = 60
#: Platform tags every release publishes, for each project.
WHEEL_PLATFORMS = (
    "manylinux_2_34_x86_64",
    "macosx_10_15_x86_64",
    "macosx_11_0_arm64",
    "win_amd64",
)
ARCHIVES = (
    "dcert-x86_64-unknown-linux-gnu.tar.gz",
    "dcert-x86_64-apple-darwin.tar.gz",
    "dcert-aarch64-apple-darwin.tar.gz",
    "dcert-x86_64-pc-windows-msvc.zip",
)
OTHER_ASSETS = ("dcert-cli-sbom.cdx.json", "dcert-mcp-sbom.cdx.json", "SHA256SUMS")
TABLE_TOOL = re.compile(r"^\|\s*`([a-z0-9_]+)`\s*\|")
STABLE_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def get(url: str, headers: Mapping[str, str] | None = None, method: str = "GET") -> bytes:
    request = urllib.request.Request(url, method=method)  # noqa: S310 - https URLs only
    request.add_header("User-Agent", "dcert-release-check")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", f"Bearer {token}")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
        return bytes(response.read())


def get_json(url: str) -> Any:  # noqa: ANN401 - parsed JSON
    return json.loads(get(url))


def pypi_release(project: str, version: str) -> Any | None:  # noqa: ANN401 - parsed JSON
    """The PyPI JSON of ``project`` at ``version``, or None when it is not served."""
    try:
        return get_json(f"https://pypi.org/pypi/{project}/{version}/json")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


# ---------------------------------------------------------------------------
# Pure checks
# ---------------------------------------------------------------------------


def expected_assets(version: str) -> list[str]:
    wheels = [
        f"{dist}-{version}-py3-none-{platform}.whl"
        for dist in ("dcert", "dcert_mcp")
        for platform in WHEEL_PLATFORMS
    ]
    return [*ARCHIVES, *wheels, *OTHER_ASSETS]


def missing_assets(names: Iterable[str], version: str) -> list[str]:
    present = set(names)
    return [name for name in expected_assets(version) if name not in present]


def pypi_problems(project: str, version: str, release: Mapping[str, Any] | None) -> list[str]:
    """Problems with one project's PyPI release: absent, yanked, or wheels missing."""
    if release is None:
        return [f"{project} {version} is not on PyPI"]
    files = [f["filename"] for f in release.get("urls", [])]
    dist = project.replace("-", "_")
    problems = [
        f"{project} {version} has no {platform} wheel"
        for platform in WHEEL_PLATFORMS
        if f"{dist}-{version}-py3-none-{platform}.whl" not in files
    ]
    if any(f.get("yanked") for f in release.get("urls", [])):
        problems.append(f"{project} {version} is yanked")
    return problems


def formula_version(text: str) -> str | None:
    match = re.search(r'^\s*version "([^"]+)"', text, re.MULTILINE)
    return match[1] if match else None


def tool_table(readme: str) -> list[str]:
    """Tool names in the first table after ``### Tools`` in the README."""
    lines = readme.splitlines()
    names: list[str] = []
    started = False
    for line in lines[lines.index("### Tools") + 1 :]:
        if line.startswith("|"):
            started = True
            match = TABLE_TOOL.match(line)
            if match:
                names.append(match[1])
        elif started:
            break
    return names


def newest(versions: Iterable[str]) -> str | None:
    parsed = []
    for version in versions:
        match = STABLE_TAG.match("v" + version.removeprefix("v"))
        if match:
            parsed.append((tuple(int(p) for p in match.groups()), version.removeprefix("v")))
    return max(parsed)[1] if parsed else None


def installable(releases: Mapping[str, Sequence[Mapping[str, Any]]]) -> set[str]:
    """PyPI versions with at least one file that is not yanked."""
    return {v for v, files in releases.items() if any(not f.get("yanked") for f in files)}


def parity_problems(tag: str | None, pypi: Mapping[str, set[str]]) -> list[str]:
    """The newest settled release must be installable from PyPI for every project."""
    if tag is None:
        return ["no settled v* release found"]
    return [
        f"release v{tag} is not installable from PyPI as {project}"
        for project, versions in pypi.items()
        if tag not in versions
    ]


@dataclass(frozen=True)
class Channel:
    """One row of the consistency table."""

    name: str
    required: bool
    problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.problems


def summary_table(version: str, channels: Sequence[Channel]) -> str:
    rows = [f"## Release {version}", "", "| Channel | Status | Detail |", "| --- | --- | --- |"]
    for channel in channels:
        status = "ok" if channel.ok else ("missing" if channel.required else "warning")
        rows.append(f"| {channel.name} | {status} | {'; '.join(channel.problems) or '-'} |")
    return "\n".join(rows) + "\n"


# ---------------------------------------------------------------------------
# Channel probes (network)
# ---------------------------------------------------------------------------


def probe(name: str, required: bool, check: Callable[[], list[str]]) -> Channel:
    try:
        problems = check()
    except (OSError, ValueError, KeyError) as exc:
        problems = [f"could not check: {exc}"]
    return Channel(name, required, tuple(problems))


def github_release(repo: str, version: str) -> list[str]:
    release = get_json(f"https://api.github.com/repos/{repo}/releases/tags/v{version}")
    names = [a["name"] for a in release.get("assets", [])]
    return [f"asset {n} is missing" for n in missing_assets(names, version)]


def ghcr_tag(repo: str, version: str) -> list[str]:
    image = repo.lower()
    token = get_json(f"https://ghcr.io/token?scope=repository:{image}:pull")["token"]
    accept = ", ".join(
        [
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ]
    )
    try:
        get(
            f"https://ghcr.io/v2/{image}/manifests/{version}",
            {"Authorization": f"Bearer {token}", "Accept": accept},
            method="HEAD",
        )
    except urllib.error.HTTPError as exc:
        return [f"ghcr.io/{image}:{version} answered {exc.code}"]
    return []


def homebrew(version: str) -> list[str]:
    content = get_json(f"https://api.github.com/repos/{TAP}/contents/Formula/dcert.rb")
    found = formula_version(base64.b64decode(content["content"]).decode("utf-8"))
    return [] if found == version else [f"the tap formula is at {found}"]


def pypi_channel(project: str, version: str) -> list[str]:
    return pypi_problems(project, version, pypi_release(project, version))


def chocolatey(result: str) -> list[str]:
    # The publish job is skipped when no API key is configured, and the
    # community feed shows a version only after moderation, so the job result
    # is the evidence available at release time.
    if result in ("success", "skipped"):
        return []
    return [f"the publish-chocolatey job result is {result or 'unknown'}"]


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


@click.group()
def main() -> None:
    """Check that a release reached every channel."""


@main.command("wait-pypi")
@click.option("--version", required=True)
@click.option("--timeout", default=900, show_default=True, help="Seconds to wait.")
@click.option("--interval", default=20, show_default=True)
def wait_pypi(version: str, timeout: int, interval: int) -> None:
    """Wait until both PyPI projects serve VERSION."""
    deadline = time.monotonic() + timeout
    while True:
        problems = [
            p
            for project in PROJECTS
            for p in pypi_problems(project, version, pypi_release(project, version))
        ]
        if not problems:
            click.echo(f"PyPI serves dcert and dcert-mcp {version}")
            return
        if time.monotonic() >= deadline:
            for problem in problems:
                click.echo(f"::error::{problem}", err=True)
            sys.exit(1)
        click.echo(f"waiting: {'; '.join(problems)}")
        time.sleep(interval)


@main.command()
@click.option("--binary", type=click.Path(path_type=Path, dir_okay=False), required=True)
@click.option("--version", required=True)
@click.option("--readme", type=click.Path(path_type=Path), default=ROOT / "README.md")
def handshake(binary: Path, version: str, readme: Path) -> None:
    """initialize and tools/list against an installed dcert-mcp."""
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "release-check", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    with subprocess.Popen(  # noqa: S603 - the installed server, fixed arguments
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ) as proc:
        if proc.stdin is None or proc.stdout is None:
            raise click.ClickException("could not open the server's stdio")
        proc.stdin.write("".join(json.dumps(m) + "\n" for m in messages))
        proc.stdin.flush()
        replies: dict[int, Any] = {}
        for line in proc.stdout:
            message = json.loads(line)
            if message.get("id") in (1, 2):
                replies[message["id"]] = message["result"]
            if len(replies) == 2:
                break
        proc.kill()
    if len(replies) != 2:
        raise click.ClickException(f"{binary} did not answer initialize and tools/list")
    served = replies[1]["serverInfo"]["version"]
    tools = sorted(t["name"] for t in replies[2]["tools"])
    expected = sorted(tool_table(readme.read_text(encoding="utf-8")))
    problems = []
    if served != version:
        problems.append(f"serverInfo.version is {served}, expected {version}")
    if tools != expected:
        problems.append(
            f"tools/list differs from the README table: {sorted(set(tools) ^ set(expected))}"
        )
    for problem in problems:
        click.echo(f"::error::{problem}", err=True)
    if problems:
        sys.exit(1)
    click.echo(f"dcert-mcp {served}: {len(tools)} tools")


@main.command()
@click.option("--version", required=True)
@click.option("--repo", default=REPOSITORY, show_default=True)
@click.option("--chocolatey", "choco_result", default="", help="The publish-chocolatey job result.")
def consistency(version: str, repo: str, choco_result: str) -> None:
    """Every channel of one release, as a job summary table."""
    channels = [
        probe("GitHub release assets", True, lambda: github_release(repo, version)),
        *[probe(f"PyPI {p}", True, partial(pypi_channel, p, version)) for p in PROJECTS],
        probe("GHCR image", True, lambda: ghcr_tag(repo, version)),
        probe("Homebrew tap", True, lambda: homebrew(version)),
        probe("Chocolatey push", False, lambda: chocolatey(choco_result)),
    ]
    table = summary_table(version, channels)
    click.echo(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(table)
    failed = [c for c in channels if c.required and not c.ok]
    for channel in failed:
        click.echo(f"::error::{channel.name}: {'; '.join(channel.problems)}", err=True)
    if failed:
        sys.exit(1)


def settled_tags(releases: Iterable[Mapping[str, Any]], now: float, grace: float) -> list[str]:
    """Tags of published releases older than ``grace`` seconds (PyPI follows them)."""
    tags = []
    for release in releases:
        if release.get("draft") or release.get("prerelease") or not release.get("published_at"):
            continue
        published = datetime.fromisoformat(str(release["published_at"]).replace("Z", "+00:00"))
        if now - published.timestamp() >= grace:
            tags.append(str(release["tag_name"]))
    return tags


@main.command("pypi-parity")
@click.option("--repo", default=REPOSITORY, show_default=True)
@click.option(
    "--grace-minutes",
    default=90,
    show_default=True,
    help="Ignore releases younger than this: their PyPI upload may still be running.",
)
def pypi_parity(repo: str, grace_minutes: int) -> None:
    """The newest settled release is installable from both PyPI projects."""
    releases = get_json(f"https://api.github.com/repos/{repo}/releases?per_page=30")
    tag = newest(settled_tags(releases, time.time(), grace_minutes * 60))
    pypi = {
        p: installable(get_json(f"https://pypi.org/pypi/{p}/json")["releases"]) for p in PROJECTS
    }
    problems = parity_problems(tag, pypi)
    for problem in problems:
        click.echo(f"::error::{problem}", err=True)
    if problems:
        sys.exit(1)
    click.echo(f"release v{tag} is installable from PyPI as dcert and dcert-mcp")


if __name__ == "__main__":
    main()
