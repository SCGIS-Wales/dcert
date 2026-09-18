#!/usr/bin/env python3
"""Build platform specific wheels by bundling the Rust binaries.

The universal ``py3-none-any`` wheel is copied and the ``dcert`` and
``dcert-mcp`` binaries from a release archive are added under
``dcert/bin/``. The console script wrappers installed by pip exec those
binaries and mark them executable on first use.

The platform table (archive name to wheel tag) is read from
``python/src/dcert/config.yaml`` so the package and this script agree.

Usage::

    python scripts/build_wheels.py \\
        --wheel python/dist/dcert-3.0.14-py3-none-any.whl \\
        --archives-dir release-assets/ \\
        --output dist/
"""

from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import logging
import sys
import tarfile
from pathlib import Path
from typing import TypedDict
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import yaml

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "python" / "src" / "dcert" / "config.yaml"

#: Binaries extracted from each archive (Windows uses ``.exe`` names).
BINARY_NAMES: tuple[str, ...] = ("dcert", "dcert-mcp", "dcert.exe", "dcert-mcp.exe")


class PlatformRow(TypedDict):
    """One row of the ``platforms`` table in ``config.yaml``."""

    system: str
    machine: str
    triple: str
    archive_extension: str
    wheel_tag: str


def load_platform_rows(config_path: Path = CONFIG_PATH) -> list[PlatformRow]:
    """Read the platform table from the packaged configuration file."""
    with config_path.open("rb") as handle:
        raw = yaml.safe_load(handle)
    rows = raw.get("platforms") if isinstance(raw, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{config_path}: 'platforms' must be a non-empty list")
    return [
        PlatformRow(
            system=str(row["system"]).lower(),
            machine=str(row["machine"]).lower(),
            triple=str(row["triple"]),
            archive_extension=str(row["archive_extension"]),
            wheel_tag=str(row["wheel_tag"]),
        )
        for row in rows
    ]


def archive_name(row: PlatformRow) -> str:
    """Return the release archive name for *row*."""
    return f"dcert-{row['triple']}.{row['archive_extension']}"


def platform_map(rows: list[PlatformRow]) -> dict[str, str]:
    """Map each archive name to its wheel platform tag."""
    return {archive_name(row): row["wheel_tag"] for row in rows}


def archive_name_for_host(system: str, machine: str, rows: list[PlatformRow]) -> str | None:
    """Return the archive name for a ``platform.system()``/``machine()`` pair."""
    key = (system.lower(), machine.lower())
    return next((archive_name(row) for row in rows if (row["system"], row["machine"]) == key), None)


PLATFORM_MAP: dict[str, str] = platform_map(load_platform_rows())


def record_entry(filename: str, data: bytes) -> str:
    """Return a RECORD line: ``filename,sha256=<urlsafe-b64>,<size>``."""
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"{filename},sha256={digest.decode('ascii')},{len(data)}"


def parse_wheel_filename(wheel_path: Path) -> tuple[str, str]:
    """Return ``(name, version)`` from a wheel filename."""
    parts = wheel_path.stem.split("-")
    if len(parts) < 3:
        raise ValueError(f"Invalid wheel filename: {wheel_path.name}")
    return parts[0], parts[1]


def extract_binaries_from_archive(archive_path: Path) -> dict[str, bytes]:
    """Return the binaries in a ``.tar.gz`` or ``.zip`` archive keyed by basename."""
    binaries: dict[str, bytes] = {}
    if archive_path.suffix == ".zip":
        with ZipFile(archive_path) as archive:
            for member in archive.infolist():
                name = Path(member.filename).name
                if name in BINARY_NAMES:
                    binaries[name] = archive.read(member)
        return binaries
    with tarfile.open(archive_path, "r:gz") as tar:
        for tar_member in tar.getmembers():
            name = Path(tar_member.name).name
            if name not in BINARY_NAMES:
                continue
            handle = tar.extractfile(tar_member)
            if handle is not None:
                binaries[name] = handle.read()
    return binaries


def _binary_zip_info(path_in_wheel: str) -> ZipInfo:
    """Return a ZipInfo marking *path_in_wheel* as an executable Unix file."""
    info = ZipInfo(path_in_wheel)
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100755 << 16
    return info


def build_platform_wheel(
    source_wheel: Path,
    archive: Path,
    platform_tag: str,
    output_dir: Path,
) -> Path:
    """Build a platform wheel from the universal wheel and a release archive.

    Returns:
        Path to the new wheel.

    Raises:
        RuntimeError: If ``dcert-mcp`` is not present in the archive.
    """
    name, version = parse_wheel_filename(source_wheel)
    dist_info = f"{name}-{version}.dist-info"
    out_path = output_dir / f"{name}-{version}-py3-none-{platform_tag}.whl"

    binaries = extract_binaries_from_archive(archive)
    if not {"dcert-mcp", "dcert-mcp.exe"} & binaries.keys():
        raise RuntimeError(f"dcert-mcp binary not found in {archive.name}")

    records: list[str] = []
    with ZipFile(source_wheel, "r") as src, ZipFile(out_path, "w", ZIP_DEFLATED) as dst:
        for item in src.infolist():
            if item.filename in (f"{dist_info}/WHEEL", f"{dist_info}/RECORD"):
                continue
            data = src.read(item.filename)
            dst.writestr(item, data)
            records.append(record_entry(item.filename, data))

        for binary_name, binary_data in binaries.items():
            path_in_wheel = f"dcert/bin/{binary_name}"
            dst.writestr(_binary_zip_info(path_in_wheel), binary_data)
            records.append(record_entry(path_in_wheel, binary_data))

        wheel_data = (
            "Wheel-Version: 1.0\n"
            "Generator: build_wheels.py\n"
            "Root-Is-Purelib: true\n"
            f"Tag: py3-none-{platform_tag}\n"
        ).encode()
        dst.writestr(f"{dist_info}/WHEEL", wheel_data)
        records.append(record_entry(f"{dist_info}/WHEEL", wheel_data))

        record_path = f"{dist_info}/RECORD"
        records.append(f"{record_path},,")
        dst.writestr(record_path, "\n".join(records) + "\n")

    logger.info("built %s (%.1f MB)", out_path.name, out_path.stat().st_size / 1e6)
    return out_path


def build_all(source_wheel: Path, archives_dir: Path, output_dir: Path) -> list[Path]:
    """Build a platform wheel for every known archive in *archives_dir*."""
    return [
        build_platform_wheel(source_wheel, archives_dir / filename, tag, output_dir)
        for filename, tag in sorted(PLATFORM_MAP.items())
        if (archives_dir / filename).is_file()
    ]


def resolve_wheel(pattern: str) -> Path:
    """Return the single wheel matching *pattern* (a path or a glob)."""
    candidate = Path(pattern)
    if candidate.is_file():
        return candidate
    matches = glob.glob(pattern)
    if len(matches) == 1:
        return Path(matches[0])
    if not matches:
        raise FileNotFoundError(f"wheel not found: {pattern}")
    raise ValueError(f"multiple wheels match: {matches}")


def build_parser() -> argparse.ArgumentParser:
    """Return the command line parser."""
    parser = argparse.ArgumentParser(
        description="Build platform specific Python wheels with bundled Rust binaries",
    )
    parser.add_argument("--wheel", required=True, help="Path to the universal wheel")
    parser.add_argument("--archive", help="A single platform archive (use with --platform)")
    parser.add_argument("--platform", help="Wheel platform tag (e.g. macosx_11_0_arm64)")
    parser.add_argument("--archives-dir", help="Directory of platform archives (batch mode)")
    parser.add_argument("--output", required=True, help="Output directory for platform wheels")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Command line entry point; returns the process exit status."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr
    )
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        source_wheel = resolve_wheel(args.wheel)
        if args.archives_dir:
            archives_dir = Path(args.archives_dir)
            if not archives_dir.is_dir():
                raise FileNotFoundError(f"archives directory not found: {archives_dir}")
            wheels = build_all(source_wheel, archives_dir, output_dir)
            logger.info("built %d platform wheels", len(wheels))
        elif args.archive and args.platform:
            archive = Path(args.archive)
            if not archive.is_file():
                raise FileNotFoundError(f"archive not found: {archive}")
            build_platform_wheel(source_wheel, archive, args.platform, output_dir)
        else:
            raise ValueError("specify either --archives-dir or both --archive and --platform")
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        logger.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
