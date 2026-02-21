"""Tests for the platform-specific wheel builder."""

import io
import tarfile
import textwrap
from pathlib import Path
from zipfile import ZipFile

import pytest

from build_wheels import (
    BINARY_NAMES,
    PLATFORM_MAP,
    _extract_binaries_from_archive,
    _parse_wheel_filename,
    _record_entry,
    build_all,
    build_platform_wheel,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tar_archive(path: Path, binaries: dict[str, bytes] | None = None) -> Path:
    """Create a fake tar.gz archive containing specified binaries."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if binaries is None:
        binaries = {
            "dcert": b"#!/bin/sh\necho dcert",
            "dcert-mcp": b"#!/bin/sh\necho dcert-mcp",
        }
    with tarfile.open(path, "w:gz") as tar:
        for name, data in binaries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return path


def _make_universal_wheel(directory: Path) -> Path:
    """Create a minimal universal wheel for testing."""
    directory.mkdir(parents=True, exist_ok=True)
    whl_path = directory / "dcert-1.0.0-py3-none-any.whl"
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


# ---------------------------------------------------------------------------
# Tests: record entry
# ---------------------------------------------------------------------------


class TestRecordEntry:
    def test_format(self):
        data = b"hello world"
        entry = _record_entry("some/file.py", data)
        assert entry.startswith("some/file.py,sha256=")
        assert entry.endswith(f",{len(data)}")

    def test_different_data_different_hash(self):
        e1 = _record_entry("f.py", b"aaa")
        e2 = _record_entry("f.py", b"bbb")
        assert e1 != e2


# ---------------------------------------------------------------------------
# Tests: parse wheel filename
# ---------------------------------------------------------------------------


class TestParseWheelFilename:
    def test_valid_name(self):
        p = Path("dcert-1.0.0-py3-none-any.whl")
        name, version = _parse_wheel_filename(p)
        assert name == "dcert"
        assert version == "1.0.0"

    def test_invalid_name(self):
        with pytest.raises(ValueError, match="Invalid wheel filename"):
            _parse_wheel_filename(Path("bad.whl"))


# ---------------------------------------------------------------------------
# Tests: extract binaries from archive
# ---------------------------------------------------------------------------


class TestExtractBinaries:
    def test_extract_both_binaries(self, tmp_path):
        archive = _make_tar_archive(tmp_path / "dcert-test.tar.gz")
        binaries = _extract_binaries_from_archive(archive)
        assert "dcert" in binaries
        assert "dcert-mcp" in binaries
        assert b"dcert" in binaries["dcert"]
        assert b"dcert-mcp" in binaries["dcert-mcp"]

    def test_extract_with_directory_prefix(self, tmp_path):
        """Test extraction strips directory prefixes."""
        archive_path = tmp_path / "dcert-test.tar.gz"
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive_path, "w:gz") as tar:
            for name in ["release/dcert", "release/dcert-mcp"]:
                data = f"#!/bin/sh\necho {Path(name).name}".encode()
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        binaries = _extract_binaries_from_archive(archive_path)
        assert "dcert" in binaries
        assert "dcert-mcp" in binaries

    def test_ignores_other_files(self, tmp_path):
        archive_path = tmp_path / "dcert-test.tar.gz"
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive_path, "w:gz") as tar:
            for name in ["dcert", "dcert-mcp", "README.md"]:
                data = name.encode()
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        binaries = _extract_binaries_from_archive(archive_path)
        assert set(binaries.keys()) == {"dcert", "dcert-mcp"}


# ---------------------------------------------------------------------------
# Tests: build_platform_wheel
# ---------------------------------------------------------------------------


class TestBuildPlatformWheel:
    def test_creates_wheel(self, tmp_path):
        src = _make_universal_wheel(tmp_path / "src")
        archive = _make_tar_archive(tmp_path / "archives" / "test.tar.gz")
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        result = build_platform_wheel(src, archive, "macosx_11_0_arm64", output_dir)
        assert result.exists()
        assert "macosx_11_0_arm64" in result.name

    def test_wheel_contains_both_binaries(self, tmp_path):
        src = _make_universal_wheel(tmp_path / "src")
        archive = _make_tar_archive(tmp_path / "archives" / "test.tar.gz")
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        result = build_platform_wheel(src, archive, "macosx_11_0_arm64", output_dir)
        with ZipFile(result, "r") as zf:
            names = zf.namelist()
            assert any("scripts/dcert-mcp" in n for n in names)
            assert any("scripts/dcert" in n for n in names)

    def test_wheel_has_executable_permissions(self, tmp_path):
        src = _make_universal_wheel(tmp_path / "src")
        archive = _make_tar_archive(tmp_path / "archives" / "test.tar.gz")
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        result = build_platform_wheel(src, archive, "macosx_11_0_arm64", output_dir)
        with ZipFile(result, "r") as zf:
            for info in zf.infolist():
                if "scripts/" in info.filename and info.filename.endswith(
                    ("dcert", "dcert-mcp")
                ):
                    assert (info.external_attr >> 16) & 0o755 == 0o755

    def test_wheel_has_correct_platform_tag(self, tmp_path):
        src = _make_universal_wheel(tmp_path / "src")
        archive = _make_tar_archive(tmp_path / "archives" / "test.tar.gz")
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        tag = "manylinux_2_35_x86_64"
        result = build_platform_wheel(src, archive, tag, output_dir)
        with ZipFile(result, "r") as zf:
            wheel_content = zf.read("dcert-1.0.0.dist-info/WHEEL").decode()
            assert f"Tag: py3-none-{tag}" in wheel_content

    def test_wheel_has_valid_record(self, tmp_path):
        src = _make_universal_wheel(tmp_path / "src")
        archive = _make_tar_archive(tmp_path / "archives" / "test.tar.gz")
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        result = build_platform_wheel(src, archive, "macosx_11_0_arm64", output_dir)
        with ZipFile(result, "r") as zf:
            record = zf.read("dcert-1.0.0.dist-info/RECORD").decode()
            # Every file except RECORD itself should have a hash
            for info in zf.infolist():
                if info.filename == "dcert-1.0.0.dist-info/RECORD":
                    assert "dcert-1.0.0.dist-info/RECORD,," in record
                else:
                    assert info.filename in record

    def test_missing_dcert_mcp_raises(self, tmp_path):
        src = _make_universal_wheel(tmp_path / "src")
        archive = _make_tar_archive(
            tmp_path / "archives" / "test.tar.gz",
            binaries={"dcert": b"#!/bin/sh\necho dcert"},
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        with pytest.raises(RuntimeError, match="dcert-mcp binary not found"):
            build_platform_wheel(src, archive, "macosx_11_0_arm64", output_dir)


# ---------------------------------------------------------------------------
# Tests: build_all (batch mode)
# ---------------------------------------------------------------------------


class TestBuildAll:
    def test_batch_builds_all_platforms(self, tmp_path):
        src = _make_universal_wheel(tmp_path / "src")
        archives_dir = tmp_path / "archives"
        archives_dir.mkdir()

        for archive_name in PLATFORM_MAP:
            _make_tar_archive(archives_dir / archive_name)

        output_dir = tmp_path / "out"
        output_dir.mkdir()

        wheels = build_all(src, archives_dir, output_dir)
        assert len(wheels) == len(PLATFORM_MAP)

        # Verify each platform tag
        for wheel in wheels:
            found = False
            for tag in PLATFORM_MAP.values():
                if tag in wheel.name:
                    found = True
                    break
            assert found, f"Wheel {wheel.name} doesn't match any platform tag"

    def test_batch_skips_unknown_archives(self, tmp_path):
        src = _make_universal_wheel(tmp_path / "src")
        archives_dir = tmp_path / "archives"
        archives_dir.mkdir()

        # Create one valid archive and one unknown
        first_archive = list(PLATFORM_MAP.keys())[0]
        _make_tar_archive(archives_dir / first_archive)
        _make_tar_archive(archives_dir / "dcert-unknown-platform.tar.gz")

        output_dir = tmp_path / "out"
        output_dir.mkdir()

        wheels = build_all(src, archives_dir, output_dir)
        assert len(wheels) == 1

    def test_batch_empty_dir(self, tmp_path):
        src = _make_universal_wheel(tmp_path / "src")
        archives_dir = tmp_path / "archives"
        archives_dir.mkdir()
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        wheels = build_all(src, archives_dir, output_dir)
        assert len(wheels) == 0


# ---------------------------------------------------------------------------
# Tests: platform map completeness
# ---------------------------------------------------------------------------


class TestPlatformMap:
    def test_all_platforms_present(self):
        assert "dcert-x86_64-unknown-linux-gnu.tar.gz" in PLATFORM_MAP
        assert "dcert-x86_64-apple-darwin.tar.gz" in PLATFORM_MAP
        assert "dcert-aarch64-apple-darwin.tar.gz" in PLATFORM_MAP

    def test_platform_count(self):
        assert len(PLATFORM_MAP) == 3

    def test_binary_names(self):
        assert "dcert" in BINARY_NAMES
        assert "dcert-mcp" in BINARY_NAMES
        assert len(BINARY_NAMES) == 2
