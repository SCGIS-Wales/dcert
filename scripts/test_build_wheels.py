"""Tests for the helpers of scripts/build_wheels.py (the wheels are covered by
test_dcert_wheel.py and test_dcert_mcp_wheel.py)."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from zipfile import ZipFile

import pytest
from build_wheels import (
    BINARY_NAMES,
    PLATFORM_MAP,
    check_platform_tag,
    extract_binaries_from_archive,
    main,
    record_entry,
    required_glibc,
)

TAR_BINARIES = {"dcert": b"#!/bin/sh\necho dcert", "dcert-mcp": b"#!/bin/sh\necho dcert-mcp"}


def make_tar(path: Path, members: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def test_record_entry_format() -> None:
    entry = record_entry("a/b.txt", b"hello")
    name, digest, size = entry.split(",")
    assert name == "a/b.txt"
    assert digest == "sha256=LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
    assert size == "5"


def test_platform_map_covers_the_four_release_archives() -> None:
    assert PLATFORM_MAP == {
        "dcert-x86_64-unknown-linux-gnu.tar.gz": "manylinux_2_34_x86_64",
        "dcert-x86_64-apple-darwin.tar.gz": "macosx_10_15_x86_64",
        "dcert-aarch64-apple-darwin.tar.gz": "macosx_11_0_arm64",
        "dcert-x86_64-pc-windows-msvc.zip": "win_amd64",
    }


def test_binary_names() -> None:
    assert set(BINARY_NAMES) == {"dcert", "dcert-mcp", "dcert.exe", "dcert-mcp.exe"}


def test_extract_tar_with_directory_prefix(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", {f"dcert-1/{k}": v for k, v in TAR_BINARIES.items()})
    assert extract_binaries_from_archive(archive) == TAR_BINARIES


def test_extract_ignores_other_files(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", {"README.md": b"x", "dcert": b"cli"})
    assert extract_binaries_from_archive(archive) == {"dcert": b"cli"}


def test_extract_windows_zip(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    with ZipFile(path, "w") as zf:
        zf.writestr("dcert.exe", b"MZ1")
        zf.writestr("bin/", b"")
        zf.writestr("dcert-mcp.exe", b"MZ2")
    assert extract_binaries_from_archive(path) == {"dcert.exe": b"MZ1", "dcert-mcp.exe": b"MZ2"}


def test_required_glibc_reads_the_newest_symbol_version() -> None:
    blob = b"\x00GLIBC_2.17\x00GLIBC_2.34\x00GLIBC_2.5\x00"
    assert required_glibc(blob) == (2, 34)
    assert required_glibc(b"MZ no glibc here") is None


def test_check_platform_tag_refuses_a_tag_older_than_the_binary() -> None:
    with pytest.raises(RuntimeError, match="glibc 2.35"):
        check_platform_tag("manylinux_2_34_x86_64", {"dcert": b"GLIBC_2.35\x00"})
    check_platform_tag("manylinux_2_34_x86_64", {"dcert": b"GLIBC_2.34\x00"})
    check_platform_tag("macosx_11_0_arm64", {"dcert": b"GLIBC_9.99\x00"})


def test_main_errors(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parent.parent / "python" / "dcert-cli"
    out = str(tmp_path / "o")
    assert (
        main(["--project", str(project), "--archives-dir", str(tmp_path / "none"), "--output", out])
        == 1
    )
    (tmp_path / "empty").mkdir()
    assert (
        main(
            ["--project", str(project), "--archives-dir", str(tmp_path / "empty"), "--output", out]
        )
        == 1
    )
