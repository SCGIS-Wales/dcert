"""Contract tests for the ``dcert-mcp`` wheel built by ``scripts/build_wheels.py``."""

from __future__ import annotations

import subprocess
import sys
import venv
from pathlib import Path
from zipfile import ZipFile

import pytest
from build_wheels import build_cli_wheel, read_project
from test_dcert_wheel import LICENSE, LINUX_ARCHIVE, make_archive

PROJECT = Path(__file__).resolve().parent.parent / "python" / "dcert-mcp"
FAKE_MCP = b"#!/bin/sh\necho dcert-mcp-fake\n"
TAG = "manylinux_2_34_x86_64"


@pytest.fixture
def wheel(tmp_path: Path) -> Path:
    archive = make_archive(
        tmp_path / "in" / LINUX_ARCHIVE, {"dcert": b"cli", "dcert-mcp": FAKE_MCP}
    )
    return build_cli_wheel(PROJECT, archive, TAG, tmp_path / "out", LICENSE)


def names(wheel: Path) -> list[str]:
    with ZipFile(wheel) as zf:
        return zf.namelist()


def metadata(wheel: Path) -> list[str]:
    version = read_project(PROJECT)["version"]
    with ZipFile(wheel) as zf:
        return zf.read(f"dcert_mcp-{version}.dist-info/METADATA").decode().splitlines()


def test_depends_only_on_dcert_at_the_same_version(wheel: Path) -> None:
    version = read_project(PROJECT)["version"]
    plain = [
        line
        for line in metadata(wheel)
        if line.startswith("Requires-Dist:") and "extra ==" not in line
    ]
    assert plain == [f"Requires-Dist: dcert=={version}"]


def test_third_party_packages_sit_behind_extras(wheel: Path) -> None:
    lines = metadata(wheel)
    assert "Provides-Extra: proxy" in lines
    assert "Provides-Extra: otel" in lines
    assert "Provides-Extra: dev" not in lines
    assert any(
        line.startswith("Requires-Dist: fastmcp") and 'extra == "proxy"' in line for line in lines
    )
    assert any(
        line.startswith("Requires-Dist: opentelemetry-sdk") and 'extra == "otel"' in line
        for line in lines
    )


def test_versions_match_between_the_two_projects() -> None:
    cli = read_project(PROJECT.parent / "dcert-cli")["version"]
    assert read_project(PROJECT)["version"] == cli


def test_the_rust_server_is_a_wheel_script_and_the_cli_is_not_included(
    wheel: Path,
) -> None:
    version = read_project(PROJECT)["version"]
    listing = names(wheel)
    assert f"dcert_mcp-{version}.data/scripts/dcert-mcp" in listing
    assert not any(n.endswith("/scripts/dcert") for n in listing)


def test_python_package_and_entry_point(wheel: Path) -> None:
    version = read_project(PROJECT)["version"]
    listing = names(wheel)
    for module in ("__init__.py", "proxy.py", "cli.py", "config.yaml", "py.typed"):
        assert f"dcert_mcp/{module}" in listing
    assert not any("__pycache__" in n or n.endswith(".pyc") for n in listing)
    assert not any(n.endswith(("download.py", "checksums.json")) for n in listing)
    with ZipFile(wheel) as zf:
        entry = zf.read(f"dcert_mcp-{version}.dist-info/entry_points.txt").decode()
    assert "dcert-mcp-proxy = dcert_mcp.proxy:main" in entry
    assert "dcert-mcp =" not in entry.replace("dcert-mcp-proxy =", "")


def test_wheel_tag_and_filename(wheel: Path) -> None:
    version = read_project(PROJECT)["version"]
    assert wheel.name == f"dcert_mcp-{version}-py3-none-{TAG}.whl"


def test_archive_without_the_server_is_refused(tmp_path: Path) -> None:
    archive = make_archive(tmp_path / "in" / LINUX_ARCHIVE, {"dcert": b"cli"})
    with pytest.raises(RuntimeError, match="dcert-mcp executable not found"):
        build_cli_wheel(PROJECT, archive, TAG, tmp_path / "out")


@pytest.mark.skipif(sys.platform == "win32", reason="the fake executable is a shell script")
def test_pip_install_gives_both_commands_without_the_extra(tmp_path: Path) -> None:
    archive = make_archive(
        tmp_path / "in" / LINUX_ARCHIVE, {"dcert": b"cli", "dcert-mcp": FAKE_MCP}
    )
    wheel = build_cli_wheel(PROJECT, archive, "any", tmp_path / "out", LICENSE)
    env_dir = tmp_path / "venv"
    venv.create(env_dir, with_pip=True)
    bindir = env_dir / "bin"
    subprocess.run(
        [
            str(bindir / "python"),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            str(wheel),
        ],
        check=True,
        capture_output=True,
    )
    server = subprocess.run([str(bindir / "dcert-mcp")], capture_output=True, text=True, check=True)
    assert server.stdout.strip() == "dcert-mcp-fake"
    proxy = subprocess.run([str(bindir / "dcert-mcp-proxy")], capture_output=True, text=True)
    assert proxy.returncode == 1
    assert proxy.stderr.count("\n") == 1
    assert 'pip install "dcert-mcp[proxy]"' in proxy.stderr
    imported = subprocess.run(
        [
            str(bindir / "python"),
            "-c",
            "import dcert_mcp; print(dcert_mcp.__version__)",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert imported.stdout.strip() == read_project(PROJECT)["version"]
