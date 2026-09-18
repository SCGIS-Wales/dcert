"""Tests for scripts/build_wheels.py."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from zipfile import ZipFile

import pytest
from build_wheels import (
    BINARY_NAMES,
    PLATFORM_MAP,
    archive_name_for_host,
    build_all,
    build_platform_wheel,
    extract_binaries_from_archive,
    load_platform_rows,
    main,
    parse_wheel_filename,
    platform_map,
    record_entry,
    resolve_wheel,
)

TAR_BINARIES = {"dcert": b"#!/bin/sh\necho dcert", "dcert-mcp": b"#!/bin/sh\necho dcert-mcp"}
ZIP_BINARIES = {"dcert.exe": b"MZ\x90\x00dcert", "dcert-mcp.exe": b"MZ\x90\x00dcert-mcp"}


def make_tar_archive(path: Path, binaries: dict[str, bytes] | None = None) -> Path:
    """Write a tar.gz containing *binaries* (fake ones by default)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tar:
        for name, data in (binaries or TAR_BINARIES).items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return path


def make_zip_archive(path: Path, binaries: dict[str, bytes] | None = None) -> Path:
    """Write a Windows style zip containing *binaries*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w") as zf:
        for name, data in (binaries or ZIP_BINARIES).items():
            zf.writestr(name, data)
    return path


def make_archive_for(path: Path) -> Path:
    """Write a fake archive whose format matches the file extension."""
    return make_zip_archive(path) if path.suffix == ".zip" else make_tar_archive(path)


@pytest.fixture
def universal_wheel(tmp_path: Path) -> Path:
    """A minimal universal wheel."""
    whl_path = tmp_path / "src" / "dcert-1.0.0-py3-none-any.whl"
    whl_path.parent.mkdir()
    with ZipFile(whl_path, "w") as zf:
        zf.writestr("dcert/__init__.py", "__version__ = '1.0.0'\n")
        zf.writestr(
            "dcert-1.0.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: dcert\nVersion: 1.0.0\n",
        )
        zf.writestr(
            "dcert-1.0.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        zf.writestr("dcert-1.0.0.dist-info/RECORD", "")
    return whl_path


@pytest.fixture
def tar_archive(tmp_path: Path) -> Path:
    return make_tar_archive(tmp_path / "archives" / "test.tar.gz")


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    return out


@pytest.fixture
def built_wheel(universal_wheel: Path, tar_archive: Path, output_dir: Path) -> Path:
    return build_platform_wheel(universal_wheel, tar_archive, "macosx_11_0_arm64", output_dir)


# -- record entry / wheel filename ---------------------------------------------


def test_record_entry_format():
    data = b"hello world"
    entry = record_entry("some/file.py", data)
    assert entry.startswith("some/file.py,sha256=")
    assert entry.endswith(f",{len(data)}")
    assert record_entry("f.py", b"aaa") != record_entry("f.py", b"bbb")


def test_parse_wheel_filename():
    assert parse_wheel_filename(Path("dcert-1.0.0-py3-none-any.whl")) == ("dcert", "1.0.0")
    with pytest.raises(ValueError, match="Invalid wheel filename"):
        parse_wheel_filename(Path("bad.whl"))


# -- platform table from config.yaml -----------------------------------------


def test_platform_map_from_config():
    assert PLATFORM_MAP == {
        "dcert-x86_64-unknown-linux-gnu.tar.gz": "manylinux_2_35_x86_64",
        "dcert-x86_64-apple-darwin.tar.gz": "macosx_10_15_x86_64",
        "dcert-aarch64-apple-darwin.tar.gz": "macosx_11_0_arm64",
        "dcert-x86_64-pc-windows-msvc.zip": "win_amd64",
    }
    assert platform_map(load_platform_rows()) == PLATFORM_MAP


def test_archive_name_for_host():
    rows = load_platform_rows()
    assert archive_name_for_host("Linux", "x86_64", rows) == "dcert-x86_64-unknown-linux-gnu.tar.gz"
    assert archive_name_for_host("Windows", "AMD64", rows) == "dcert-x86_64-pc-windows-msvc.zip"
    assert archive_name_for_host("Linux", "aarch64", rows) is None


def test_load_platform_rows_rejects_bad_file(tmp_path: Path):
    bad = tmp_path / "config.yaml"
    bad.write_text("platforms: {}\n")
    with pytest.raises(ValueError, match="platforms"):
        load_platform_rows(bad)


def test_binary_names():
    assert set(BINARY_NAMES) == {"dcert", "dcert-mcp", "dcert.exe", "dcert-mcp.exe"}


# -- extraction --------------------------------------------------------------


def test_extract_both_binaries(tar_archive: Path):
    assert extract_binaries_from_archive(tar_archive) == TAR_BINARIES


def test_extract_with_directory_prefix(tmp_path: Path):
    archive = make_tar_archive(
        tmp_path / "prefixed.tar.gz",
        {"release/dcert": b"a", "release/dcert-mcp": b"b", "release/README.md": b"c"},
    )
    assert extract_binaries_from_archive(archive) == {"dcert": b"a", "dcert-mcp": b"b"}


def test_extract_windows_zip(tmp_path: Path):
    archive = make_zip_archive(tmp_path / "dcert-x86_64-pc-windows-msvc.zip")
    assert extract_binaries_from_archive(archive) == ZIP_BINARIES


# -- build_platform_wheel ----------------------------------------------------


def test_creates_wheel_with_tag_and_binaries(built_wheel: Path):
    assert built_wheel.exists()
    assert "macosx_11_0_arm64" in built_wheel.name
    with ZipFile(built_wheel, "r") as zf:
        names = zf.namelist()
        assert "dcert/bin/dcert-mcp" in names
        assert "dcert/bin/dcert" in names
        assert "Tag: py3-none-macosx_11_0_arm64" in zf.read("dcert-1.0.0.dist-info/WHEEL").decode()


def test_wheel_has_executable_permissions(built_wheel: Path):
    with ZipFile(built_wheel, "r") as zf:
        for info in zf.infolist():
            if info.filename.startswith("dcert/bin/"):
                assert info.create_system == 3
                assert (info.external_attr >> 16) & 0o777 == 0o755


def test_wheel_has_valid_record(built_wheel: Path):
    with ZipFile(built_wheel, "r") as zf:
        record = zf.read("dcert-1.0.0.dist-info/RECORD").decode()
        for info in zf.infolist():
            assert info.filename in record
        assert "dcert-1.0.0.dist-info/RECORD,," in record


def test_build_windows_wheel(universal_wheel: Path, output_dir: Path, tmp_path: Path):
    archive = make_zip_archive(tmp_path / "archives" / "dcert-x86_64-pc-windows-msvc.zip")
    result = build_platform_wheel(universal_wheel, archive, "win_amd64", output_dir)
    assert "win_amd64" in result.name
    with ZipFile(result, "r") as zf:
        assert {"dcert/bin/dcert.exe", "dcert/bin/dcert-mcp.exe"} <= set(zf.namelist())


def test_missing_dcert_mcp_raises(universal_wheel: Path, output_dir: Path, tmp_path: Path):
    archive = make_tar_archive(tmp_path / "archives" / "test.tar.gz", {"dcert": b"only"})
    with pytest.raises(RuntimeError, match="dcert-mcp binary not found"):
        build_platform_wheel(universal_wheel, archive, "macosx_11_0_arm64", output_dir)


# -- build_all ---------------------------------------------------------------


def test_batch_builds_all_platforms(universal_wheel: Path, output_dir: Path, tmp_path: Path):
    archives_dir = tmp_path / "archives"
    archives_dir.mkdir()
    for name in PLATFORM_MAP:
        make_archive_for(archives_dir / name)
    wheels = build_all(universal_wheel, archives_dir, output_dir)
    assert len(wheels) == len(PLATFORM_MAP)
    assert all(any(tag in wheel.name for tag in PLATFORM_MAP.values()) for wheel in wheels)


def test_batch_skips_unknown_archives(universal_wheel: Path, output_dir: Path, tmp_path: Path):
    archives_dir = tmp_path / "archives"
    archives_dir.mkdir()
    make_tar_archive(archives_dir / next(iter(PLATFORM_MAP)))
    make_tar_archive(archives_dir / "dcert-unknown-platform.tar.gz")
    assert len(build_all(universal_wheel, archives_dir, output_dir)) == 1


def test_batch_empty_dir(universal_wheel: Path, output_dir: Path, tmp_path: Path):
    archives_dir = tmp_path / "archives"
    archives_dir.mkdir()
    assert build_all(universal_wheel, archives_dir, output_dir) == []


# -- command line ------------------------------------------------------------


def test_resolve_wheel(universal_wheel: Path, tmp_path: Path):
    assert resolve_wheel(str(universal_wheel)) == universal_wheel
    assert resolve_wheel(str(tmp_path / "src" / "dcert-*.whl")) == universal_wheel
    with pytest.raises(FileNotFoundError, match="wheel not found"):
        resolve_wheel(str(tmp_path / "missing-*.whl"))
    (tmp_path / "src" / "dcert-2.0.0-py3-none-any.whl").write_bytes(b"")
    with pytest.raises(ValueError, match="multiple wheels match"):
        resolve_wheel(str(tmp_path / "src" / "dcert-*.whl"))


def test_main_batch_mode(universal_wheel: Path, output_dir: Path, tmp_path: Path):
    archives_dir = tmp_path / "archives"
    archives_dir.mkdir()
    make_tar_archive(archives_dir / "dcert-x86_64-unknown-linux-gnu.tar.gz")
    argv = [
        "--wheel",
        str(universal_wheel),
        "--archives-dir",
        str(archives_dir),
        "--output",
        str(output_dir),
    ]
    assert main(argv) == 0
    assert list(output_dir.glob("*manylinux_2_35_x86_64.whl"))


def test_main_single_mode(universal_wheel: Path, tar_archive: Path, output_dir: Path):
    argv = [
        "--wheel",
        str(universal_wheel),
        "--archive",
        str(tar_archive),
        "--platform",
        "macosx_11_0_arm64",
        "--output",
        str(output_dir),
    ]
    assert main(argv) == 0
    assert list(output_dir.glob("*macosx_11_0_arm64.whl"))


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--archives-dir", "/nonexistent"],
        ["--archive", "/nonexistent.tar.gz", "--platform", "x"],
    ],
)
def test_main_errors(universal_wheel: Path, output_dir: Path, extra: list[str]):
    assert main(["--wheel", str(universal_wheel), "--output", str(output_dir), *extra]) == 1


def test_main_missing_wheel(output_dir: Path):
    assert main(["--wheel", "/nonexistent.whl", "--output", str(output_dir)]) == 1
