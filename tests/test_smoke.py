"""Smoke tests — verifies repo scaffold is importable and CLI is wired."""

from __future__ import annotations

import subprocess
import sys

from click.testing import CliRunner


def test_package_importable() -> None:
    """The nighteye package must import without side effects."""
    import nighteye

    assert nighteye.__version__ == "0.1.0"


def test_cli_help_via_runner() -> None:
    """CLI --help must succeed and mention the project."""
    from nighteye.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "NightEye" in result.output
    assert "case" in result.output
    assert "ingest" in result.output
    assert "serve" in result.output


def test_cli_version() -> None:
    """--version must print the version string."""
    from nighteye.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_subcommands_stub() -> None:
    """Stub subcommands exit with code 2 and a not-yet-implemented message.

    This locks the CLI surface so accidentally renaming a command breaks
    the test before it breaks anyone's workflow.

    Note: 'case' is a real group (shows help, exit 0), not a stub.
    """
    from nighteye.cli import main

    runner = CliRunner()
    for cmd in ("constructors", "serve", "review", "report"):
        result = runner.invoke(main, [cmd])
        assert result.exit_code == 2, f"{cmd}: expected exit 2, got {result.exit_code}"
        assert "not yet implemented" in result.output, f"{cmd}: missing stub message"


def test_cli_case_group_shows_help() -> None:
    """The 'case' group shows usage info (not a 'not yet implemented' stub)."""
    from nighteye.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["case"])
    # Click groups exit 2 when no subcommand is given, but show help
    assert "Case management" in result.output or "Commands" in result.output
    assert "not yet implemented" not in result.output


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
