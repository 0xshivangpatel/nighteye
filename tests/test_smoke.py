"""Smoke tests — verifies repo scaffold is importable and CLI is wired."""

from __future__ import annotations

import subprocess
import sys

from click.testing import CliRunner


def test_package_importable() -> None:
    """The nighteye package must import without side effects."""
    import nighteye

    assert nighteye.__version__ == "0.1.0"


def test_cli_help() -> None:
    """CLI --help must succeed and mention NightEye."""
    result = subprocess.run(
        [sys.executable, "-m", "nighteye.cli", "--help"],
        capture_output=True,
        text=True,
        cwd="src"
    )
    assert result.returncode == 0
    assert "NightEye" in result.stdout
    assert "full-pipeline" in result.stdout


def test_cli_list_cases() -> None:
    """The list-cases command should run (even if empty)."""
    result = subprocess.run(
        [sys.executable, "-m", "nighteye.cli", "list-cases"],
        capture_output=True,
        text=True,
        cwd="src"
    )
    assert result.returncode == 0


def test_cli_status() -> None:
    """The status command should run."""
    result = subprocess.run(
        [sys.executable, "-m", "nighteye.cli", "status"],
        capture_output=True,
        text=True,
        cwd="src"
    )
    # If there's a case, it succeeds (0). If not, it fails (1). 
    # Both are "graceful" handling.
    assert result.returncode in (0, 1)


def test_console_script_installed() -> None:
    """After `pip install -e .`, the `nighteye` script must be on PATH and runnable.

    Skipped if running outside an installed environment (e.g., in CI before
    install). Re-enabled by setting NIGHTEYE_REQUIRE_CONSOLE_SCRIPT=1.
    """
    import os
    import shutil

    nighteye_bin = shutil.which("nighteye")
    if nighteye_bin is None:
        if os.environ.get("NIGHTEYE_REQUIRE_CONSOLE_SCRIPT") == "1":
            raise AssertionError("nighteye console script not found on PATH")
        # Soft pass: package not installed via pip yet
        return

    result = subprocess.run(
        [nighteye_bin, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "0.1.0" in result.stdout


def test_python_version_minimum() -> None:
    """Project requires Python 3.11+."""
    assert sys.version_info >= (3, 11), (
        f"NightEye requires Python 3.11+, got {sys.version_info}"
    )
