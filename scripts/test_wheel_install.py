"""End to end test: build a platform wheel, install it, check the commands.

Run with ``pytest -v scripts/test_wheel_install.py`` (needs ``build``).
"""

from __future__ import annotations

import io
import os
import platform
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest
from build_wheels import (
    PLATFORM_MAP,
    archive_name_for_host,
    build_platform_wheel,
    load_platform_rows,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHON_DIR = PROJECT_ROOT / "python"
SUBPROCESS_TIMEOUT = 600

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="the dcert package requires Python 3.12 or later"
)


def make_fake_archive(archive_path: Path) -> Path:
    """Write a tar.gz of shell scripts that print a version string."""
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "w:gz") as tar:
        for name in ("dcert", "dcert-mcp"):
            data = f"#!/bin/sh\necho '{name} 0.0.0-test'\n".encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return archive_path


def run(args: list[str], timeout: int = SUBPROCESS_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Run *args* with output captured and a timeout."""
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


@pytest.fixture(scope="module")
def platform_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the universal wheel from source, then a platform wheel with fake binaries."""
    pytest.importorskip("build")
    archive_name = archive_name_for_host(
        platform.system(), platform.machine(), load_platform_rows()
    )
    if archive_name is None or archive_name.endswith(".zip"):
        pytest.skip(f"Unsupported platform: {platform.system()}/{platform.machine()}")

    tmp_path = tmp_path_factory.mktemp("wheel")
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    result = run(
        [sys.executable, "-m", "build", "--wheel", str(PYTHON_DIR), "--outdir", str(dist_dir)]
    )
    assert result.returncode == 0, f"build failed:\n{result.stderr}"
    wheels = list(dist_dir.glob("dcert-*-py3-none-any.whl"))
    assert len(wheels) == 1, f"Expected one universal wheel, got: {wheels}"

    archive = make_fake_archive(tmp_path / "archives" / archive_name)
    output_dir = tmp_path / "platform-dist"
    output_dir.mkdir()
    return build_platform_wheel(wheels[0], archive, PLATFORM_MAP[archive_name], output_dir)


@pytest.fixture
def venv(tmp_path: Path) -> Path:
    """An isolated virtual environment."""
    venv_dir = tmp_path / "venv"
    result = run([sys.executable, "-m", "venv", str(venv_dir)])
    assert result.returncode == 0, result.stderr
    return venv_dir


@pytest.fixture
def install_wheel(venv: Path, platform_wheel: Path) -> Path:
    """Install the platform wheel into the venv and return its bin directory."""
    venv_python = venv / "bin" / "python"
    result = run([str(venv_python), "-m", "pip", "install", str(platform_wheel)])
    assert result.returncode == 0, f"pip install failed:\n{result.stderr}"
    return venv / "bin"


@pytest.mark.parametrize("command", ["dcert", "dcert-mcp", "dcert-python"])
def test_command_available(install_wheel: Path, command: str):
    path = install_wheel / command
    assert path.exists(), f"{command} not found at {path}"
    assert os.access(path, os.X_OK), f"{command} is not executable"


@pytest.mark.parametrize("command", ["dcert", "dcert-mcp"])
def test_command_executes_bundled_binary(install_wheel: Path, command: str):
    result = run([str(install_wheel / command)], timeout=30)
    assert f"{command} 0.0.0-test" in result.stdout


def test_dcert_python_help(install_wheel: Path):
    result = run([str(install_wheel / "dcert-python"), "--help"], timeout=30)
    assert result.returncode == 0, result.stderr
    assert "dcert" in result.stdout.lower()


def test_binaries_and_config_bundled_in_package(install_wheel: Path):
    script = textwrap.dedent("""
        from pathlib import Path
        import dcert

        pkg = Path(dcert.__file__).parent
        print(sorted(p.name for p in (pkg / "bin").iterdir()), (pkg / "config.yaml").exists())
    """)
    result = run([str(install_wheel / "python"), "-c", script], timeout=30)
    assert result.returncode == 0, result.stderr
    assert "['dcert', 'dcert-mcp'] True" in result.stdout
