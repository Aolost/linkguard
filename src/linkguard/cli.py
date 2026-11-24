"""Command line interface.

Exit codes: 0 no red flags, 1 suspicious, 2 dangerous, 3 refused or error.
"""

import contextlib
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class Result:
    """What a command wants printed and the exit code it asks for.

    Commands return this instead of printing, so that `main` owns every write. Click
    turns a write error inside a command into `sys.exit(1)`, which callers would read
    as SUSPICIOUS.
    """

    stdout: str
    code: int
    stderr: str = ""


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
) -> Result:
    """Inspect one URL."""
    policy = Policy(follow=True) if follow else DEFAULT_POLICY
    report = inspect(url, policy)
    text = (
        json.dumps(report.to_dict(), indent=2) if json_output else render_text(report)
    )
    return Result(text.rstrip("\n") + "\n", exit_code(report))


@app.command()
def batch(
    file: Annotated[Path, typer.Argument(help="A file with one URL per line.")],
) -> Result:
    """Inspect every URL in a file. The exit code is the highest of all entries."""
    try:
        entries = load_entries(file)
    except BatchError as error:
        return Result("", EXIT_REFUSED_OR_ERROR, f"Error: {error}\n")
    reports = [(number, inspect(url)) for number, url in entries]
    lines = [result_line(number, report) for number, report in reports]
    all_reports = [report for _, report in reports]
    text = "\n".join([*lines, summary_line(all_reports)]) + "\n"
    return Result(text, max(exit_code(report) for report in all_reports))


def _discard_stdout() -> None:
    """Point stdout at /dev/null after a broken pipe.

    Otherwise the flush at interpreter exit fails again and changes the exit status.
    """
    with contextlib.suppress(OSError, ValueError, AttributeError):  # not a real file
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the exit code.

    Whatever goes wrong, the status is 3. Python's own status for an uncaught exception
    is 1, which callers would read as SUSPICIOUS, and typer's usage errors are 2, which
    would read as DANGEROUS.
    """
    try:
        result = app(args=None if argv is None else list(argv), standalone_mode=False)
        if not isinstance(result, Result):  # --help, or a bare group: typer's own exit
            return result if isinstance(result, int) else 0
        sys.stderr.write(result.stderr)
        sys.stdout.write(result.stdout)
        sys.stdout.flush()
        return result.code
    except TyperException as error:
        message = escape_text(error.format_message(), 300)
        print(f"Error: {message}", file=sys.stderr)
        return EXIT_REFUSED_OR_ERROR
    except BrokenPipeError:  # the reader of our output went away
        _discard_stdout()
        return EXIT_REFUSED_OR_ERROR
    except Exception as error:  # last-resort boundary; only the type is printed
        print(f"Error: internal error ({type(error).__name__})", file=sys.stderr)
        return EXIT_REFUSED_OR_ERROR


def run() -> None:
    sys.exit(main())
