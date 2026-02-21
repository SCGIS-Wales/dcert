"""Functional test: build a platform wheel, install it, and verify CLI entry points.

This test simulates the end-to-end user experience:
  1. Build a universal wheel from the source tree
  2. Build a platform-specific wheel (with fake binaries)
  3. Install the platform wheel into an isolated virtualenv
  4. Verify that ``dcert``, ``dcert-mcp``, and ``dcert-python`` commands are
     all available and executable

Run with:
    pytest -v scripts/test_wheel_install.py
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path
from zipfile import ZipFile

import pytest

# Root of the project
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHON_DIR = PROJECT_ROOT / "python"


def _make_fake_archive(archive_path: Path) -> Path:
    """Create a tar.gz with fake binaries that print a version string."""
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "w:gz") as tar:
        for name in ["dcert", "dcert-mcp"]:
            script = f"#!/bin/sh\necho '{name} 0.0.0-test'\n"
            data = script.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return archive_path


class TestWheelInstall:
    """End-to-end test: build wheel, install, verify commands work."""

    @pytest.fixture
    def venv(self, tmp_path):
        """Create an isolated virtualenv for installation testing."""
        venv_dir = tmp_path / "venv"
        subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)])
        return venv_dir

    @pytest.fixture
    def venv_python(self, venv):
        """Return the Python executable inside the virtualenv."""
        return str(venv / "bin" / "python")

    @pytest.fixture
    def venv_bin(self, venv):
        """Return the bin directory inside the virtualenv."""
        return venv / "bin"

    @pytest.fixture
    def platform_wheel(self, tmp_path):
        """Build a platform-specific wheel with fake binaries."""
        # 1. Build the universal wheel from the source tree
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "build"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                str(PYTHON_DIR),
                "--outdir",
                str(dist_dir),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Find the built universal wheel
        wheels = list(dist_dir.glob("dcert-*-py3-none-any.whl"))
        assert len(wheels) == 1, f"Expected 1 universal wheel, got: {wheels}"
        universal_wheel = wheels[0]

        # 2. Create a fake archive with test binaries
        import platform as plat

        system = plat.system().lower()
        machine = plat.machine().lower()
        archive_map = {
            ("darwin", "arm64"): "dcert-aarch64-apple-darwin.tar.gz",
            ("darwin", "x86_64"): "dcert-x86_64-apple-darwin.tar.gz",
            ("linux", "x86_64"): "dcert-x86_64-unknown-linux-gnu.tar.gz",
            ("linux", "aarch64"): "dcert-x86_64-unknown-linux-gnu.tar.gz",
        }
        archive_name = archive_map.get((system, machine))
        if archive_name is None:
            pytest.skip(f"Unsupported platform: {system}/{machine}")

        archive_dir = tmp_path / "archives"
        archive = _make_fake_archive(archive_dir / archive_name)

        # 3. Build the platform-specific wheel
        sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
        try:
            from build_wheels import PLATFORM_MAP, build_platform_wheel

            platform_tag = PLATFORM_MAP[archive_name]
            output_dir = tmp_path / "platform-dist"
            output_dir.mkdir()
            wheel_path = build_platform_wheel(
                universal_wheel, archive, platform_tag, output_dir
            )
        finally:
            sys.path.pop(0)

        return wheel_path

    def test_wheel_installs_successfully(self, venv_python, platform_wheel):
        """Test that the platform wheel can be installed without errors."""
        result = subprocess.run(
            [venv_python, "-m", "pip", "install", str(platform_wheel)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"pip install failed:\n{result.stderr}"

    def test_dcert_command_available(self, venv_python, venv_bin, platform_wheel):
        """Test that the 'dcert' command is available after installation."""
        subprocess.check_call(
            [venv_python, "-m", "pip", "install", str(platform_wheel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dcert_cmd = venv_bin / "dcert"
        assert dcert_cmd.exists(), f"dcert command not found at {dcert_cmd}"
        assert os.access(str(dcert_cmd), os.X_OK), "dcert command is not executable"

    def test_dcert_mcp_command_available(self, venv_python, venv_bin, platform_wheel):
        """Test that the 'dcert-mcp' command is available after installation."""
        subprocess.check_call(
            [venv_python, "-m", "pip", "install", str(platform_wheel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        mcp_cmd = venv_bin / "dcert-mcp"
        assert mcp_cmd.exists(), f"dcert-mcp command not found at {mcp_cmd}"
        assert os.access(str(mcp_cmd), os.X_OK), "dcert-mcp command is not executable"

    def test_dcert_python_command_available(
        self, venv_python, venv_bin, platform_wheel
    ):
        """Test that the 'dcert-python' command is available after installation."""
        subprocess.check_call(
            [venv_python, "-m", "pip", "install", str(platform_wheel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        py_cmd = venv_bin / "dcert-python"
        assert py_cmd.exists(), f"dcert-python command not found at {py_cmd}"
        assert os.access(str(py_cmd), os.X_OK), "dcert-python command is not executable"

    def test_dcert_command_executes_binary(
        self, venv_python, venv_bin, platform_wheel
    ):
        """Test that 'dcert' command executes the bundled binary."""
        subprocess.check_call(
            [venv_python, "-m", "pip", "install", str(platform_wheel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result = subprocess.run(
            [str(venv_bin / "dcert")],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # The fake binary prints "dcert 0.0.0-test"
        assert "dcert 0.0.0-test" in result.stdout

    def test_dcert_mcp_command_executes_binary(
        self, venv_python, venv_bin, platform_wheel
    ):
        """Test that 'dcert-mcp' command executes the bundled binary."""
        subprocess.check_call(
            [venv_python, "-m", "pip", "install", str(platform_wheel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result = subprocess.run(
            [str(venv_bin / "dcert-mcp")],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # The fake binary prints "dcert-mcp 0.0.0-test"
        assert "dcert-mcp 0.0.0-test" in result.stdout

    def test_dcert_python_help(self, venv_python, venv_bin, platform_wheel):
        """Test that 'dcert-python --help' works."""
        subprocess.check_call(
            [venv_python, "-m", "pip", "install", str(platform_wheel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result = subprocess.run(
            [str(venv_bin / "dcert-python"), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "dcert" in result.stdout.lower()

    def test_binaries_bundled_in_package(self, venv_python, platform_wheel):
        """Test that binaries are bundled inside the dcert/bin/ package directory."""
        subprocess.check_call(
            [venv_python, "-m", "pip", "install", str(platform_wheel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result = subprocess.run(
            [
                venv_python,
                "-c",
                "from pathlib import Path; import dcert; "
                "bin_dir = Path(dcert.__file__).parent / 'bin'; "
                "print(list(sorted(p.name for p in bin_dir.iterdir())))",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"Failed: {result.stderr}"
        assert "'dcert'" in result.stdout
        assert "'dcert-mcp'" in result.stdout
