#!/usr/bin/env python3
"""Build the platform wheels of the ``dcert`` and ``dcert-mcp`` PyPI projects.

``--project python/dcert-cli`` builds the ``dcert`` CLI wheel: the executable
goes in ``.data/scripts`` (so pip installs it straight into ``bin/`` and no
Python runs), the wheel has no Python code and no dependencies. ``--project
python/dcert-mcp`` builds the ``dcert-mcp`` wheel: the server executable the
same way, plus the ``dcert_mcp`` package and its console scripts. Metadata,
extras and the package layout are read from each project's ``pyproject.toml``,
so there is one source of truth. One wheel is built per release archive.

Usage::

    python scripts/build_wheels.py \\
        --project python/dcert-cli \\
        --archives-dir release-assets/ \\
        --output dist/
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import logging
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

PROJECT_ROOT = Path(__file__).resolve().parent.parent

logger = logging.getLogger(__name__)

#: Release archive name to wheel platform tag. The Linux tag is the newest glibc
#: the binaries reference (GLIBC_2.34 from the Ubuntu 22.04 build, so RHEL 9 and
#: its rebuilds qualify); ``check_platform_tag`` refuses a tag older than what
#: the binaries need.
PLATFORM_MAP: dict[str, str] = {
    "dcert-x86_64-unknown-linux-gnu.tar.gz": "manylinux_2_34_x86_64",
    "dcert-x86_64-apple-darwin.tar.gz": "macosx_10_15_x86_64",
    "dcert-aarch64-apple-darwin.tar.gz": "macosx_11_0_arm64",
    "dcert-x86_64-pc-windows-msvc.zip": "win_amd64",
}

#: Binaries extracted from each archive (Windows uses ``.exe`` names).
BINARY_NAMES: tuple[str, ...] = ("dcert", "dcert-mcp", "dcert.exe", "dcert-mcp.exe")


#: A glibc symbol version an ELF binary links against, such as ``GLIBC_2.34``.
GLIBC_VERSION = re.compile(rb"GLIBC_(\d+)\.(\d+)")

#: The glibc version a ``manylinux_X_Y_<arch>`` wheel tag promises.
MANYLINUX_TAG = re.compile(r"^manylinux_(\d+)_(\d+)_")


def required_glibc(binary: bytes) -> tuple[int, int] | None:
    """Return the newest glibc symbol version *binary* references, if any.

    The version names of an ELF binary's needed symbols are stored in its
    dynamic string table, so a scan of the bytes finds them without an ELF
    parser. Non ELF binaries (macOS, Windows) reference none.
    """
    return max(((int(m[1]), int(m[2])) for m in GLIBC_VERSION.finditer(binary)), default=None)


def check_platform_tag(platform_tag: str, binaries: dict[str, bytes]) -> None:
    """Refuse a ``manylinux`` tag that promises an older glibc than a binary needs.

    pip would install such a wheel on hosts where the binary cannot start.

    Raises:
        RuntimeError: If a binary references a newer glibc than the tag.
    """
    match = MANYLINUX_TAG.match(platform_tag)
    if match is None:
        return
    promised = (int(match[1]), int(match[2]))
    for name, data in sorted(binaries.items()):
        needed = required_glibc(data)
        if needed is not None and needed > promised:
            raise RuntimeError(
                f"{name} needs glibc {needed[0]}.{needed[1]} but the wheel tag {platform_tag} "
                f"promises {promised[0]}.{promised[1]}; raise the tag in PLATFORM_MAP"
            )
        if needed is not None:
            logger.info("%s needs glibc %d.%d (tag %s)", name, *needed, platform_tag)


def record_entry(filename: str, data: bytes) -> str:
    """Return a RECORD line: ``filename,sha256=<urlsafe-b64>,<size>``."""
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"{filename},sha256={digest.decode('ascii')},{len(data)}"


def extract_binaries_from_archive(archive_path: Path) -> dict[str, bytes]:
    """Return the binaries in a ``.tar.gz`` or ``.zip`` archive keyed by basename."""
    wanted = set(BINARY_NAMES)
    found: dict[str, bytes] = {}
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                name = Path(info.filename).name
                if name in wanted and not info.is_dir():
                    found[name] = zf.read(info)
    else:
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                name = Path(member.name).name
                handle = tar.extractfile(member) if member.isfile() and name in wanted else None
                if handle is not None:
                    with handle:
                        found[name] = handle.read()
    return found


def _binary_zip_info(path_in_wheel: str) -> ZipInfo:
    """Return a ZipInfo marking *path_in_wheel* as an executable Unix file."""
    info = ZipInfo(path_in_wheel)
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100755 << 16
    return info


#: Executable names carried by the ``dcert`` wheel.
CLI_BINARY_NAMES: tuple[str, ...] = ("dcert", "dcert.exe")
#: Executable names each project's wheel carries; the other binary is never included.
PROJECT_BINARIES: dict[str, tuple[str, ...]] = {
    "dcert": CLI_BINARY_NAMES,
    "dcert-mcp": ("dcert-mcp", "dcert-mcp.exe"),
}
#: Extras that are for developing the project and are not published in METADATA.
UNPUBLISHED_EXTRAS = frozenset({"dev"})


def read_project(project_dir: Path) -> dict[str, object]:
    """Return the ``[project]`` table of ``project_dir/pyproject.toml``."""
    with (project_dir / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    if not isinstance(project, dict):
        raise ValueError(f"{project_dir}/pyproject.toml has no [project] table")
    return project


def render_metadata(project: dict[str, object], description: str) -> str:
    """Return the ``METADATA`` file (core metadata 2.1) for a ``[project]`` table.

    Dependencies are written as ``Requires-Dist`` lines, so a project with
    ``dependencies = []`` produces none; that is what the wheel contract tests
    assert for ``dcert``.
    """
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {project['name']}",
        f"Version: {project['version']}",
        f"Summary: {project['description']}",
    ]
    authors = project.get("authors")
    if isinstance(authors, list) and authors:
        lines.append(f"Author: {', '.join(str(a['name']) for a in authors)}")
    if project.get("license"):
        lines.append(f"License: {project['license']}")
    if project.get("keywords"):
        lines.append(f"Keywords: {','.join(str(k) for k in project['keywords'])}")  # type: ignore[attr-defined]
    for label, url in (project.get("urls") or {}).items():  # type: ignore[attr-defined]
        lines.append(f"Project-URL: {label}, {url}")
    for classifier in project.get("classifiers") or []:  # type: ignore[attr-defined]
        lines.append(f"Classifier: {classifier}")
    if project.get("requires-python"):
        lines.append(f"Requires-Python: {project['requires-python']}")
    for requirement in project.get("dependencies") or []:  # type: ignore[attr-defined]
        lines.append(f"Requires-Dist: {requirement}")
    extras = project.get("optional-dependencies") or {}
    for extra, requirements in extras.items():  # type: ignore[attr-defined]
        if extra in UNPUBLISHED_EXTRAS:
            continue
        lines.append(f"Provides-Extra: {extra}")
        lines += [
            f'Requires-Dist: {requirement}; extra == "{extra}"' for requirement in requirements
        ]
    lines += ["Description-Content-Type: text/markdown", "", description]
    return "\n".join(lines) + "\n"


def read_package_layout(project_dir: Path) -> tuple[dict[str, bytes], dict[str, str]]:
    """Return the Python files to ship and the console scripts for a project.

    Both are empty for a project without a ``[tool.dcert-wheel]`` table, so the
    ``dcert`` wheel stays free of Python code.
    """
    with (project_dir / "pyproject.toml").open("rb") as handle:
        table = tomllib.load(handle).get("tool", {}).get("dcert-wheel")
    if not table:
        return {}, {}
    package_dir = project_dir / str(table["python-package"])
    files = {
        f"{package_dir.name}/{path.relative_to(package_dir).as_posix()}": path.read_bytes()
        for path in sorted(package_dir.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    if not files:
        raise RuntimeError(f"no files found in {package_dir}")
    return files, dict(table.get("entry-points", {}))


def build_cli_wheel(
    project_dir: Path,
    archive: Path,
    platform_tag: str,
    output_dir: Path,
    license_file: Path | None = None,
) -> Path:
    """Build the ``dcert`` or ``dcert-mcp`` wheel for one platform from a release archive.

    The executable goes in ``<name>-<version>.data/scripts``. The ``dcert``
    wheel holds that and the ``dist-info`` files and nothing else: no Python
    modules, no ``Requires-Dist``. A project with a ``[tool.dcert-wheel]`` table
    (``dcert-mcp``) also carries its Python package and console scripts.

    Raises:
        RuntimeError: If the archive has no executable for the project, or it
            needs a newer glibc than a ``manylinux`` tag promises.
    """
    project = read_project(project_dir)
    name, version = str(project["name"]), str(project["version"])
    if name not in PROJECT_BINARIES:
        raise RuntimeError(f"no binary known for project {name!r}")
    wanted = PROJECT_BINARIES[name]
    package_files, entry_points = read_package_layout(project_dir)
    readme = (project_dir / str(project.get("readme", "README.md"))).read_text(encoding="utf-8")
    # Wheel file and directory names escape runs of "-", "_" and "." as "_" (PEP 427).
    stem = f"{re.sub(r'[-_.]+', '_', name)}-{version}"
    dist_info = f"{stem}.dist-info"
    scripts = f"{stem}.data/scripts"
    out_path = output_dir / f"{stem}-py3-none-{platform_tag}.whl"

    found = {n: d for n, d in extract_binaries_from_archive(archive).items() if n in wanted}
    if not found:
        raise RuntimeError(f"{wanted[0]} executable not found in {archive.name}")
    check_platform_tag(platform_tag, found)

    files: dict[str, bytes] = {f"{dist_info}/METADATA": render_metadata(project, readme).encode()}
    files.update(package_files)
    if entry_points:
        lines = [f"{command} = {target}" for command, target in sorted(entry_points.items())]
        files[f"{dist_info}/entry_points.txt"] = (
            "[console_scripts]\n" + "\n".join(lines) + "\n"
        ).encode()
    if license_file is not None and license_file.is_file():
        files[f"{dist_info}/licenses/{license_file.name}"] = license_file.read_bytes()
    files[f"{dist_info}/WHEEL"] = (
        "Wheel-Version: 1.0\n"
        "Generator: build_wheels.py\n"
        "Root-Is-Purelib: false\n"
        f"Tag: py3-none-{platform_tag}\n"
    ).encode()

    output_dir.mkdir(parents=True, exist_ok=True)
    records: list[str] = []
    with ZipFile(out_path, "w", ZIP_DEFLATED) as wheel:
        for binary_name, data in sorted(found.items()):
            path_in_wheel = f"{scripts}/{binary_name}"
            wheel.writestr(_binary_zip_info(path_in_wheel), data)
            records.append(record_entry(path_in_wheel, data))
        for path_in_wheel, data in files.items():
            wheel.writestr(path_in_wheel, data)
            records.append(record_entry(path_in_wheel, data))
        record_path = f"{dist_info}/RECORD"
        records.append(f"{record_path},,")
        wheel.writestr(record_path, "\n".join(records) + "\n")

    logger.info("built %s (%.1f MB)", out_path.name, out_path.stat().st_size / 1e6)
    return out_path


def build_all_cli(
    project_dir: Path,
    archives_dir: Path,
    output_dir: Path,
    license_file: Path | None = None,
) -> list[Path]:
    """Build the project's wheel for every known archive in *archives_dir*."""
    return [
        build_cli_wheel(project_dir, archives_dir / filename, tag, output_dir, license_file)
        for filename, tag in sorted(PLATFORM_MAP.items())
        if (archives_dir / filename).is_file()
    ]


def build_parser() -> argparse.ArgumentParser:
    """Return the command line parser."""
    parser = argparse.ArgumentParser(
        description="Build platform specific Python wheels with a bundled Rust executable",
    )
    parser.add_argument(
        "--project",
        required=True,
        help="Project directory to build: python/dcert-cli or python/dcert-mcp",
    )
    parser.add_argument("--archives-dir", required=True, help="Directory of release archives")
    parser.add_argument("--output", required=True, help="Output directory for the wheels")
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
        archives_dir = Path(args.archives_dir)
        if not archives_dir.is_dir():
            raise FileNotFoundError(f"archives directory not found: {archives_dir}")
        license_file = PROJECT_ROOT / "LICENSE"
        wheels = build_all_cli(Path(args.project), archives_dir, output_dir, license_file)
        if not wheels:
            raise FileNotFoundError(f"no known platform archive in {archives_dir}")
        logger.info("built %d wheels", len(wheels))
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        logger.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
