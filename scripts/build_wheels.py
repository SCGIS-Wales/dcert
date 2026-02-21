#!/usr/bin/env python3
"""Build platform-specific wheels by injecting Rust binaries into .data/scripts/.

When pip installs a wheel, files in .data/scripts/ are copied to the user's
scripts directory (e.g. ~/.local/bin, .venv/bin/) — the same place where
console_scripts entry points go. This makes both ``dcert`` and ``dcert-mcp``
available on PATH.

dcert archives are tar.gz files containing both binaries.  This script
extracts them and bundles them into the wheel.

Usage:
    # All platform wheels at once:
    python scripts/build_wheels.py \\
        --wheel python/dist/dcert-3.0.14-py3-none-any.whl \\
        --archives-dir release-assets/ \\
        --output dist/
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import logging
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

logger = logging.getLogger(__name__)

# Mapping from tar.gz archive names to wheel platform tags.
# Linux binary is built on ubuntu-22.04 (glibc 2.35).
PLATFORM_MAP: dict[str, str] = {
    "dcert-x86_64-unknown-linux-gnu.tar.gz": "manylinux_2_35_x86_64",
    "dcert-x86_64-apple-darwin.tar.gz": "macosx_10_15_x86_64",
    "dcert-aarch64-apple-darwin.tar.gz": "macosx_11_0_arm64",
}

# Binaries to extract from each archive
BINARY_NAMES = ["dcert", "dcert-mcp"]


def _record_entry(filename: str, data: bytes) -> str:
    """Create a RECORD entry: filename,sha256=<urlsafe-b64>,<size>."""
    digest = hashlib.sha256(data).digest()
    b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{filename},sha256={b64},{len(data)}"


def _parse_wheel_filename(wheel_path: Path) -> tuple[str, str]:
    """Extract (name, version) from a wheel filename."""
    stem = wheel_path.stem
    parts = stem.split("-")
    if len(parts) < 3:
        raise ValueError(f"Invalid wheel filename: {wheel_path.name}")
    return parts[0], parts[1]


def _extract_binaries_from_archive(archive_path: Path) -> dict[str, bytes]:
    """Extract dcert and dcert-mcp binaries from a tar.gz archive.

    Returns:
        Dict mapping binary name to its bytes content.
    """
    binaries: dict[str, bytes] = {}
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            name = Path(member.name).name
            if name in BINARY_NAMES:
                f = tar.extractfile(member)
                if f is not None:
                    binaries[name] = f.read()
    return binaries


def build_platform_wheel(
    source_wheel: Path,
    archive: Path,
    platform_tag: str,
    output_dir: Path,
) -> Path:
    """Build a platform-specific wheel from a universal wheel + Rust archive.

    Args:
        source_wheel: Path to the universal (py3-none-any) wheel.
        archive: Path to the platform tar.gz archive.
        platform_tag: Wheel platform tag (e.g. 'macosx_11_0_arm64').
        output_dir: Directory to write the new wheel to.

    Returns:
        Path to the newly created platform wheel.
    """
    name, version = _parse_wheel_filename(source_wheel)
    dist_info = f"{name}-{version}.dist-info"
    data_dir = f"{name}-{version}.data"

    # Output wheel filename
    out_name = f"{name}-{version}-py3-none-{platform_tag}.whl"
    out_path = output_dir / out_name

    # Extract binaries from the archive
    binaries = _extract_binaries_from_archive(archive)
    if "dcert-mcp" not in binaries:
        raise RuntimeError(f"dcert-mcp binary not found in {archive.name}")

    records: list[str] = []

    with ZipFile(source_wheel, "r") as src, ZipFile(out_path, "w", ZIP_DEFLATED) as dst:
        # Copy all existing files except WHEEL and RECORD
        for item in src.infolist():
            if item.filename in (f"{dist_info}/WHEEL", f"{dist_info}/RECORD"):
                continue
            data = src.read(item.filename)
            dst.writestr(item, data)
            records.append(_record_entry(item.filename, data))

        # Add both binaries with executable permissions
        for binary_name, binary_data in binaries.items():
            binary_path_in_wheel = f"{data_dir}/scripts/{binary_name}"
            info = ZipInfo(binary_path_in_wheel)
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o755 << 16  # rwxr-xr-x
            dst.writestr(info, binary_data)
            records.append(_record_entry(binary_path_in_wheel, binary_data))

        # Write updated WHEEL metadata with platform tag
        wheel_metadata = (
            "Wheel-Version: 1.0\n"
            "Generator: build_wheels.py\n"
            "Root-Is-Purelib: true\n"
            f"Tag: py3-none-{platform_tag}\n"
        )
        wheel_data = wheel_metadata.encode("utf-8")
        dst.writestr(f"{dist_info}/WHEEL", wheel_data)
        records.append(_record_entry(f"{dist_info}/WHEEL", wheel_data))

        # Write RECORD (self-entry has no hash)
        record_path = f"{dist_info}/RECORD"
        records.append(f"{record_path},,")
        record_content = "\n".join(records) + "\n"
        dst.writestr(record_path, record_content)

    logger.info("built %s (%.1f MB)", out_name, out_path.stat().st_size / 1e6)
    return out_path


def build_all(
    source_wheel: Path,
    archives_dir: Path,
    output_dir: Path,
) -> list[Path]:
    """Build platform wheels for all archives found in archives_dir.

    Returns:
        List of paths to the created platform wheels.
    """
    wheels: list[Path] = []

    for filename in sorted(os.listdir(archives_dir)):
        if filename not in PLATFORM_MAP:
            continue
        platform_tag = PLATFORM_MAP[filename]
        archive = archives_dir / filename
        if not archive.is_file():
            continue
        wheel = build_platform_wheel(source_wheel, archive, platform_tag, output_dir)
        wheels.append(wheel)

    return wheels


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build platform-specific Python wheels with bundled Rust binaries",
    )
    parser.add_argument(
        "--wheel",
        required=True,
        help="Path to the universal (py3-none-any) wheel",
    )
    parser.add_argument(
        "--archive",
        help="Path to a single platform tar.gz archive (use with --platform)",
    )
    parser.add_argument(
        "--platform",
        help="Wheel platform tag (e.g. macosx_11_0_arm64)",
    )
    parser.add_argument(
        "--archives-dir",
        help="Directory containing platform tar.gz archives (batch mode)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for platform wheels",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    source_wheel = Path(args.wheel)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not source_wheel.is_file():
        import glob

        matches = glob.glob(str(source_wheel))
        if len(matches) == 1:
            source_wheel = Path(matches[0])
        elif len(matches) == 0:
            logger.error("wheel not found: %s", args.wheel)
            sys.exit(1)
        else:
            logger.error("multiple wheels match: %s", matches)
            sys.exit(1)

    if args.archives_dir:
        archives_dir = Path(args.archives_dir)
        if not archives_dir.is_dir():
            logger.error("archives directory not found: %s", archives_dir)
            sys.exit(1)
        wheels = build_all(source_wheel, archives_dir, output_dir)
        logger.info("built %d platform wheels", len(wheels))
    elif args.archive and args.platform:
        archive = Path(args.archive)
        if not archive.is_file():
            logger.error("archive not found: %s", archive)
            sys.exit(1)
        build_platform_wheel(source_wheel, archive, args.platform, output_dir)
    else:
        logger.error("specify either --archives-dir or both --archive and --platform")
        sys.exit(1)


if __name__ == "__main__":
    main()
