"""NightEye CLI entry point.

For D1 (repo scaffold) only the skeleton is wired. Subcommands land in
later build days per docs/BUILD_PLAN.md.
"""

from __future__ import annotations

import sys
from typing import NoReturn

import click

from nighteye import __version__


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.version_option(__version__, prog_name="nighteye")
@click.pass_context
def main(ctx: click.Context) -> None:
    """NightEye — autonomous AI-driven DFIR agent.

    Built for the SANS FindEvil! Hackathon 2026.

    Common workflow:

        nighteye case init "Investigation name"
        nighteye ingest /path/to/evidence
        nighteye serve     # starts MCP (4509) and portal (4510)
        # connect Claude Code to http://127.0.0.1:4509/mcp
        # open http://127.0.0.1:4510/

    See `nighteye <command> --help` for details on each subcommand.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
def case() -> NoReturn:
    """Case management (init, activate, list, status, close)."""
    click.echo("not yet implemented — see docs/BUILD_PLAN.md D2")
    sys.exit(2)


@main.command()
def ingest() -> NoReturn:
    """Ingest forensic evidence (E01 / KAPE zip / EVTX folder / memory)."""
    click.echo("not yet implemented — see docs/BUILD_PLAN.md D4-D7")
    sys.exit(2)


@main.command()
def normalize() -> NoReturn:
    """Run canonical event normalization pass."""
    click.echo("not yet implemented — see docs/BUILD_PLAN.md D8")
    sys.exit(2)


@main.command()
def constructors() -> NoReturn:
    """Run behavior constructors over canonical events."""
    click.echo("not yet implemented — see docs/BUILD_PLAN.md D9-D12")
    sys.exit(2)


@main.command()
def serve() -> NoReturn:
    """Start MCP server (4509) and portal (4510)."""
    click.echo("not yet implemented — see docs/BUILD_PLAN.md D13-D16")
    sys.exit(2)


@main.command()
def review() -> NoReturn:
    """Review hypotheses, audit log, evidence."""
    click.echo("not yet implemented — see docs/BUILD_PLAN.md D14")
    sys.exit(2)


@main.command()
def report() -> NoReturn:
    """Generate the case report (Markdown + JSON)."""
    click.echo("not yet implemented — see docs/BUILD_PLAN.md D17")
    sys.exit(2)


if __name__ == "__main__":
    main()
