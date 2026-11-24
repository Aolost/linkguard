"""Command line interface.

Exit codes: 0 no red flags, 1 suspicious, 2 dangerous, 3 refused or error.
"""

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import typer
from typer.exceptions import TyperException

from linkguard.api import inspect
from linkguard.batch import BatchError, load_entries, result_line, summary_line
from linkguard.model import DEFAULT_POLICY, Policy, Report, Verdict, escape_text
from linkguard.render import render_text

EXIT_REFUSED_OR_ERROR = 3
_VERDICT_EXIT = {Verdict.NO_RED_FLAGS: 0, Verdict.SUSPICIOUS: 1, Verdict.DANGEROUS: 2}

# Completion would edit the user's shell startup files; pretty exceptions would print
# local variables, including the URL under test, on a crash.
app = typer.Typer(
    add_completion=False,
    pretty_exceptions_enable=False,
    help=(
        "Report suspicious indicators in a URL. A clean result means no red flags "
        "were found, not that the URL is trustworthy."
    ),
)


def exit_code(report: Report) -> int:
    if report.verdict is None or report.fetch.status in {"refused", "error"}:
        return EXIT_REFUSED_OR_ERROR
    return _VERDICT_EXIT[report.verdict]


@app.callback()
def _root() -> None:
    """Inspect URLs for suspicious indicators."""


@app.command()
def check(
    url: Annotated[str, typer.Argument(help="The http or https URL to inspect.")],
    follow: Annotated[
        bool,
        typer.Option(
            "--follow",
            help=(
                "Also fetch the URL, following up to 5 redirects. Internal and "
                "local addresses are always refused."
            ),
        ),
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the report as JSON.")
    ] = False,
) -> None:
    """Inspect one URL."""
    policy = Policy(follow=True) if follow else DEFAULT_POLICY
    report = inspect(url, policy)
    typer.echo(
        json.dumps(report.to_dict(), indent=2)
        if json_output
        else render_text(report).rstrip("\n")
    )
    raise typer.Exit(exit_code(report))


@app.command()
def batch(
    file: Annotated[Path, typer.Argument(help="A file with one URL per line.")],
) -> None:
    """Inspect every URL in a file. The exit code is the highest of all entries."""
    try:
        entries = load_entries(file)
    except BatchError as error:
        print(f"Error: {error}", file=sys.stderr)
        raise typer.Exit(EXIT_REFUSED_OR_ERROR) from error
    reports = [(number, inspect(url)) for number, url in entries]
    lines = [result_line(number, report) for number, report in reports]
    all_reports = [report for _, report in reports]
    typer.echo("\n".join([*lines, summary_line(all_reports)]))
    raise typer.Exit(max(exit_code(report) for report in all_reports))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the exit code. Usage errors are 3, not click's 2."""
    try:
        result = app(args=None if argv is None else list(argv), standalone_mode=False)
    except TyperException as error:
        message = escape_text(error.format_message(), 300)
        print(f"Error: {message}", file=sys.stderr)
        return EXIT_REFUSED_OR_ERROR
    return result if isinstance(result, int) else 0


def run() -> None:
    sys.exit(main())
