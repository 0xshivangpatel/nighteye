"""NightEye CLI entry point.

Subcommands land per docs/BUILD_PLAN.md.

D1 wired: skeleton + version
D2 wired: case (init, list, status, activate, close, reopen)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import NoReturn

import click

from nighteye import __version__
from nighteye.case import (
    CaseError,
    case_status,
    close_case,
    get_case_dir,
    init_case,
    list_cases,
    reopen_case,
    set_active_case,
)
from nighteye.identity import get_examiner, warn_if_unconfigured


# ============================================================
# Top-level group
# ============================================================


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.version_option(__version__, prog_name="nighteye")
@click.option(
    "--examiner",
    "examiner_override",
    default=None,
    help="Override examiner identity (env: NIGHTEYE_EXAMINER, config: ~/.nighteye/config.yaml).",
)
@click.pass_context
def main(ctx: click.Context, examiner_override: str | None) -> None:
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
    ctx.ensure_object(dict)
    examiner = get_examiner(examiner_override)
    warn_if_unconfigured(examiner)
    ctx.obj["examiner"] = examiner

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ============================================================
# case subcommand group
# ============================================================


@main.group()
@click.pass_context
def case(ctx: click.Context) -> None:
    """Case management (init, activate, list, status, close, reopen)."""
    pass


@case.command("init")
@click.argument("name", required=False)
@click.option("--case-id", default=None, help="Override auto-generated case ID.")
@click.option("--description", default="", help="Optional case description.")
@click.option(
    "--cases-dir",
    default=None,
    type=click.Path(file_okay=False, path_type=Path),
    help="Cases root directory (default: $NIGHTEYE_CASES_DIR or ~/cases).",
)
@click.option(
    "--no-activate",
    is_flag=True,
    default=False,
    help="Do not set the new case as active.",
)
@click.pass_context
def case_init(
    ctx: click.Context,
    name: str | None,
    case_id: str | None,
    description: str,
    cases_dir: Path | None,
    no_activate: bool,
) -> None:
    """Initialize a new case.

    NAME is the human-readable case name. If omitted, prompted interactively.
    """
    if not name:
        if not sys.stdin.isatty():
            click.echo(
                'Error: case name required. Usage: nighteye case init "<name>"',
                err=True,
            )
            sys.exit(1)
        name = click.prompt("Case name").strip()
        if not name:
            click.echo("Aborted.", err=True)
            sys.exit(1)

    examiner = ctx.obj["examiner"]
    try:
        info = init_case(
            name=name,
            examiner=examiner,
            case_id=case_id,
            description=description,
            cases_dir=cases_dir,
            set_active=not no_activate,
        )
    except CaseError as err:
        click.echo(f"Error: {err}", err=True)
        sys.exit(1)

    click.echo(f"Case initialized: {info.case_id}")
    click.echo(f"  Name:     {info.name}")
    click.echo(f"  Examiner: {info.examiner}")
    click.echo(f"  Path:     {info.case_dir}")
    if info.active:
        click.echo("  (active)")
    click.echo()
    click.echo("Next steps:")
    click.echo(f"  1. Copy evidence into: {info.case_dir}/evidence/")
    click.echo("  2. Ingest:             nighteye ingest <path>   (D4-D7)")
    click.echo("  3. Serve MCP+portal:   nighteye serve           (D13-D16)")


@case.command("list")
@click.option(
    "--cases-dir",
    default=None,
    type=click.Path(file_okay=False, path_type=Path),
    help="Cases root directory (default: $NIGHTEYE_CASES_DIR or ~/cases).",
)
def case_list(cases_dir: Path | None) -> None:
    """List all cases under the cases directory."""
    cases = list_cases(cases_dir=cases_dir)
    if not cases:
        click.echo("No cases found.")
        return
    click.echo(f"{'Case ID':<25} {'Status':<8} {'Examiner':<14} Name")
    click.echo("-" * 80)
    for c in cases:
        marker = " *" if c.active else "  "
        click.echo(
            f"{c.case_id:<25} {c.status:<8} {c.examiner:<14} {c.name}{marker}"
        )


@case.command("status")
@click.argument("case_id", required=False)
def case_status_cmd(case_id: str | None) -> None:
    """Show status of a case (default: active case)."""
    try:
        case_dir = get_case_dir(case_id)
        status = case_status(case_dir)
    except CaseError as err:
        click.echo(f"Error: {err}", err=True)
        sys.exit(1)

    meta = status["meta"]
    counts = status["counts"]
    click.echo(f"Case: {meta.get('case_id', '?')}")
    click.echo(f"  Name:        {meta.get('name', '')}")
    click.echo(f"  Status:      {meta.get('status', 'unknown')}")
    click.echo(f"  Examiner:    {meta.get('examiner', '')}")
    click.echo(f"  Created:     {meta.get('created_at', '')}")
    click.echo(f"  Path:        {status['case_dir']}")
    click.echo()
    click.echo("Counts:")
    click.echo(f"  Entities:           {counts['entities']}")
    click.echo(f"  Edges:              {counts['edges']}")
    click.echo(f"  Clusters:           {counts['clusters']}")
    click.echo(
        f"  Hypotheses:         {counts['hypotheses_total']} "
        f"(DRAFT={counts['hypotheses_draft']}, "
        f"APPROVED={counts['hypotheses_approved']}, "
        f"REJECTED={counts['hypotheses_rejected']}, "
        f"INSUFFICIENT={counts['hypotheses_insufficient']})"
    )
    click.echo(f"  Open evidence gaps: {counts['evidence_gaps_open']}")
    click.echo(f"  Audit entries:      {counts['audit_entries']}")
    click.echo(f"  Journal entries:    {counts['journal_entries']}")


@case.command("activate")
@click.argument("case_id")
@click.option(
    "--cases-dir",
    default=None,
    type=click.Path(file_okay=False, path_type=Path),
)
def case_activate_cmd(case_id: str, cases_dir: Path | None) -> None:
    """Set the active case."""
    try:
        case_dir = get_case_dir(case_id, cases_dir=cases_dir)
        set_active_case(case_dir)
    except CaseError as err:
        click.echo(f"Error: {err}", err=True)
        sys.exit(1)
    click.echo(f"Active case: {case_id}")


@case.command("close")
@click.argument("case_id", required=False)
@click.option("--summary", default="", help="Closing summary written to CASE.yaml.")
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation.")
def case_close_cmd(case_id: str | None, summary: str, yes: bool) -> None:
    """Close a case (default: active case)."""
    try:
        case_dir = get_case_dir(case_id)
    except CaseError as err:
        click.echo(f"Error: {err}", err=True)
        sys.exit(1)

    if not yes and not click.confirm(f"Close case {case_dir.name}?", default=False):
        click.echo("Cancelled.")
        return

    try:
        close_case(case_dir, summary=summary)
    except CaseError as err:
        click.echo(f"Error: {err}", err=True)
        sys.exit(1)
    click.echo(f"Case {case_dir.name} closed.")


@case.command("reopen")
@click.argument("case_id")
def case_reopen_cmd(case_id: str) -> None:
    """Reopen a closed case."""
    try:
        case_dir = get_case_dir(case_id)
        reopen_case(case_dir)
        set_active_case(case_dir)
    except CaseError as err:
        click.echo(f"Error: {err}", err=True)
        sys.exit(1)
    click.echo(f"Case {case_dir.name} reopened and set as active.")


# ============================================================
# Stub subcommands (land in later D-days)
# ============================================================


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
