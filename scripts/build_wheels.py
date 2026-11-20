#!/usr/bin/env python3
"""Build platform specific wheels by bundling the Rust binaries.

Two modes. ``--project python/dcert-cli`` builds the ``dcert`` CLI wheel from
scratch: the executable goes in ``.data/scripts`` (so pip installs it straight
into ``bin/`` and no Python runs), the wheel has no Python code and no
dependencies, and its metadata is read from that project's ``pyproject.toml``.

``--wheel`` (the legacy mode, until the PyPI split is complete) takes the
universal ``py3-none-any`` wheel, copies it and the ``dcert`` and
``dcert-mcp`` binaries from a release archive are added under
``dcert/bin/``. The console script wrappers installed by pip exec those
binaries and mark them executable on first use.

The platform table (archive name to wheel tag) and the archive reader come
from the ``dcert`` package in ``python/src`` so the two cannot disagree.

Usage::

    python scripts/build_wheels.py \\
        --project python/dcert-cli \\
        --archives-dir release-assets/ \\
        --output dist/

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
import importlib.util
import logging
import re
import sys
import tomllib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = PROJECT_ROOT / "python" / "src" / "dcert"


def _register_source_package() -> None:
    """Make ``dcert.*`` importable from the source tree without running ``dcert/__init__``.

    The package ``__init__`` imports FastMCP, which this script does not
    need and the CI job that runs it does not install. The modules used
    here depend only on the standard library and PyYAML, so the package is
    registered with its search path but its ``__init__`` is left unexecuted.
    """
    if "dcert" in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        "dcert",
        PACKAGE_DIR / "__init__.py",
        submodule_search_locations=[str(PACKAGE_DIR)],
    )
    if spec is None:
        raise ImportError(f"dcert package not found at {PACKAGE_DIR}")
    sys.modules["dcert"] = importlib.util.module_from_spec(spec)


_register_source_package()

from dcert.config import archive_name_for, find_platform, load_config  # noqa: E402
from dcert.download import iter_archive_members  # noqa: E402

logger = logging.getLogger(__name__)

#: Binaries extracted from each archive (Windows uses ``.exe`` names).
BINARY_NAMES: tuple[str, ...] = ("dcert", "dcert-mcp", "dcert.exe", "dcert-mcp.exe")

#: Release archive name to wheel platform tag, from the packaged config.
PLATFORM_MAP: dict[str, str] = {
    archive_name_for(row): row.wheel_tag for row in load_config().platforms
}


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
                f"promises {promised[0]}.{promised[1]}; raise wheel_tag in config.yaml"
            )
        if needed is not None:
            logger.info("%s needs glibc %d.%d (tag %s)", name, *needed, platform_tag)


def archive_name_for_host(system: str, machine: str) -> str | None:
    """Return the archive name for a ``platform.system()``/``machine()`` pair."""
    target = find_platform(system, machine)
    return archive_name_for(target) if target else None


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
    return {
        name: handle.read()
        for name, handle in iter_archive_members(archive_path, set(BINARY_NAMES))
    }


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
        RuntimeError: If ``dcert-mcp`` is not present in the archive, or a
            binary needs a newer glibc than a ``manylinux`` tag promises.
    """
    name, version = parse_wheel_filename(source_wheel)
    dist_info = f"{name}-{version}.dist-info"
    out_path = output_dir / f"{name}-{version}-py3-none-{platform_tag}.whl"

    binaries = extract_binaries_from_archive(archive)
    if not {"dcert-mcp", "dcert-mcp.exe"} & binaries.keys():
        raise RuntimeError(f"dcert-mcp binary not found in {archive.name}")
    check_platform_tag(platform_tag, binaries)

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
    parser.add_argument(
        "--project",
        help="Build the wheel of this project directory (python/dcert-cli or python/dcert-mcp)",
    )
    parser.add_argument("--wheel", help="Path to the universal wheel (legacy mode)")
    parser.add_argument("--archive", help="A single platform archive (use with --platform)")
    parser.add_argument("--platform", help="Wheel platform tag (e.g. macosx_11_0_arm64)")
    parser.add_argument("--archives-dir", help="Directory of platform archives (batch mode)")
    parser.add_argument("--output", required=True, help="Output directory for platform wheels")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Command line entry point; returns the process exit status."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        if args.project:
            archives_dir = Path(args.archives_dir or "")
            if not args.archives_dir or not archives_dir.is_dir():
                raise FileNotFoundError(f"archives directory not found: {args.archives_dir}")
            wheels = build_all_cli(
                Path(args.project), archives_dir, output_dir, PROJECT_ROOT / "LICENSE"
            )
            if not wheels:
                raise FileNotFoundError(f"no known platform archive in {archives_dir}")
            logger.info("built %d wheels", len(wheels))
            return 0
        if not args.wheel:
            raise ValueError(
                "specify --project (a dcert or dcert-mcp wheel) or --wheel (legacy mode)"
            )
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
