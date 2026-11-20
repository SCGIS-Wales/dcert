"""Contract tests for the ``dcert`` wheel (security plan S5.1, PyPI split phase 1).

They run against the wheel that ``scripts/build_wheels.py --project`` really
builds, not the source tree: the wheel must have no Python dependencies, no
Python code, an executable in ``.data/scripts`` and a correct RECORD.
"""

from __future__ import annotations

import base64
import hashlib
import io
import subprocess
import sys
import tarfile
import venv
from pathlib import Path
from zipfile import ZipFile

import pytest
from build_wheels import PLATFORM_MAP, build_all_cli, build_cli_wheel, main, read_project

PROJECT = Path(__file__).resolve().parent.parent / "python" / "dcert"
LICENSE = Path(__file__).resolve().parent.parent / "LICENSE"
FAKE_CLI = b"#!/bin/sh\necho dcert-fake\n"
LINUX_ARCHIVE = "dcert-x86_64-unknown-linux-gnu.tar.gz"


def make_archive(path: Path, binaries: dict[str, bytes]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tar:
        for name, data in binaries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return path


@pytest.fixture
def wheel(tmp_path: Path) -> Path:
    archive = make_archive(
        tmp_path / "in" / LINUX_ARCHIVE, {"dcert": FAKE_CLI, "dcert-mcp": b"mcp"}
    )
    return build_cli_wheel(PROJECT, archive, "manylinux_2_34_x86_64", tmp_path / "out", LICENSE)


def metadata(wheel: Path) -> str:
    name = read_project(PROJECT)
    with ZipFile(wheel) as zf:
        return zf.read(f"dcert-{name['version']}.dist-info/METADATA").decode()


def test_wheel_has_no_python_dependencies(wheel: Path) -> None:
    assert "Requires-Dist:" not in metadata(wheel)


def test_project_declares_no_dependencies() -> None:
    assert read_project(PROJECT)["dependencies"] == []


def test_wheel_has_no_python_code(wheel: Path) -> None:
    with ZipFile(wheel) as zf:
        python_files = [n for n in zf.namelist() if n.endswith((".py", ".pyc", ".pth"))]
    assert python_files == []


def test_executable_is_a_script_with_the_exec_bit(wheel: Path) -> None:
    version = read_project(PROJECT)["version"]
    with ZipFile(wheel) as zf:
        info = zf.getinfo(f"dcert-{version}.data/scripts/dcert")
        assert (info.external_attr >> 16) & 0o111
        assert zf.read(info) == FAKE_CLI


def test_mcp_binary_is_not_in_the_cli_wheel(wheel: Path) -> None:
    with ZipFile(wheel) as zf:
        assert not [n for n in zf.namelist() if "dcert-mcp" in n]


def test_wheel_tag_and_filename(wheel: Path) -> None:
    version = read_project(PROJECT)["version"]
    assert wheel.name == f"dcert-{version}-py3-none-manylinux_2_34_x86_64.whl"
    with ZipFile(wheel) as zf:
        text = zf.read(f"dcert-{version}.dist-info/WHEEL").decode()
    assert "Root-Is-Purelib: false" in text
    assert "Tag: py3-none-manylinux_2_34_x86_64" in text


def test_license_is_included(wheel: Path) -> None:
    with ZipFile(wheel) as zf:
        assert any(n.endswith("licenses/LICENSE") for n in zf.namelist())


def test_record_hashes_match_every_file(wheel: Path) -> None:
    version = read_project(PROJECT)["version"]
    with ZipFile(wheel) as zf:
        record = zf.read(f"dcert-{version}.dist-info/RECORD").decode().splitlines()
        listed = {line.split(",")[0] for line in record}
        assert listed == set(zf.namelist())
        for line in record:
            name, digest, size = line.split(",")
            if not digest:
                assert name.endswith("RECORD")
                continue
            data = zf.read(name)
            expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
            assert digest == f"sha256={expected.decode()}"
            assert int(size) == len(data)


def test_archive_without_the_cli_is_refused(tmp_path: Path) -> None:
    archive = make_archive(tmp_path / LINUX_ARCHIVE, {"dcert-mcp": b"mcp"})
    with pytest.raises(RuntimeError, match="dcert executable not found"):
        build_cli_wheel(PROJECT, archive, "manylinux_2_34_x86_64", tmp_path / "out")


def test_manylinux_tag_older_than_the_binary_needs_is_refused(tmp_path: Path) -> None:
    archive = make_archive(tmp_path / LINUX_ARCHIVE, {"dcert": b"GLIBC_2.99"})
    with pytest.raises(RuntimeError, match="glibc"):
        build_cli_wheel(PROJECT, archive, "manylinux_2_34_x86_64", tmp_path / "out")


def test_batch_builds_a_wheel_per_present_archive(tmp_path: Path) -> None:
    archives = tmp_path / "archives"
    make_archive(archives / LINUX_ARCHIVE, {"dcert": FAKE_CLI})
    make_archive(archives / "dcert-x86_64-apple-darwin.tar.gz", {"dcert": FAKE_CLI})
    wheels = build_all_cli(PROJECT, archives, tmp_path / "out", LICENSE)
    assert sorted(w.name.split("-py3-none-")[1] for w in wheels) == [
        "macosx_10_15_x86_64.whl",
        "manylinux_2_34_x86_64.whl",
    ]
    assert len(PLATFORM_MAP) == 4


def test_command_line_builds_the_cli_wheel(tmp_path: Path) -> None:
    archives = tmp_path / "archives"
    make_archive(archives / LINUX_ARCHIVE, {"dcert": FAKE_CLI})
    code = main(
        [
            "--project",
            str(PROJECT),
            "--archives-dir",
            str(archives),
            "--output",
            str(tmp_path / "o"),
        ]
    )
    assert code == 0
    assert len(list((tmp_path / "o").glob("dcert-*.whl"))) == 1


@pytest.mark.skipif(sys.platform == "win32", reason="the fake executable is a shell script")
def test_pip_install_puts_a_working_executable_on_the_path(tmp_path: Path) -> None:
    # Built with the neutral tag so it installs on whatever host runs the test.
    archive = make_archive(tmp_path / "in" / LINUX_ARCHIVE, {"dcert": FAKE_CLI})
    wheel = build_cli_wheel(PROJECT, archive, "any", tmp_path / "out", LICENSE)
    env_dir = tmp_path / "venv"
    venv.create(env_dir, with_pip=True)
    bindir = env_dir / "bin"
    subprocess.run(
        [str(bindir / "python"), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
        check=True,
        capture_output=True,
    )
    result = subprocess.run([str(bindir / "dcert")], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "dcert-fake"
    shown = subprocess.run(
        [str(bindir / "python"), "-m", "pip", "show", "dcert"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Requires: \n" in shown.stdout or "Requires:\n" in shown.stdout
