"""Reading a file of URLs and formatting one result line per URL.

The file is hostile input: its size and URL count are bounded before anything is
inspected, and a file that breaks a limit is refused whole rather than half-processed.
"""

from collections import Counter
from pathlib import Path

from linkguard.model import Report

MAX_FILE_BYTES = 1024 * 1024
MAX_URLS = 10_000

_LABELS = ("NO_RED_FLAGS", "SUSPICIOUS", "DANGEROUS", "REFUSED")


class BatchError(Exception):
    """The whole file is unusable; the message is safe to print."""


def load_entries(path: Path) -> list[tuple[int, str]]:
    """Return `(line number, URL)` pairs, skipping blank lines.

    Only `\\n` separates entries: other separators (form feed, U+2028, ...) stay inside
    the line, where the URL parser refuses them.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        raise BatchError(
            f"cannot read file: {error.strerror or 'I/O error'}"
        ) from error
    if len(data) > MAX_FILE_BYTES:
        raise BatchError("file is larger than 1 MiB")
    try:
        text = data.decode("utf-8-sig")  # Windows editors add a byte order mark
    except UnicodeDecodeError as error:
        raise BatchError("file is not valid UTF-8") from error
    stripped = (
        (number, line.strip(" \t\r")) for number, line in enumerate(text.split("\n"), 1)
    )
    entries = [(number, line) for number, line in stripped if line]
    if not entries:
        raise BatchError("no URLs found")
    if len(entries) > MAX_URLS:
        raise BatchError(f"more than {MAX_URLS} URLs")
    return entries


def _label(report: Report) -> str:
    return "REFUSED" if report.verdict is None else str(report.verdict)


def result_line(number: int, report: Report) -> str:
    if report.refusal is not None:
        detail = report.refusal.code
    else:
        detail = ",".join(dict.fromkeys(finding.rule_id for finding in report.findings))
    return f"{number:>6}  {_label(report):<13} {report.input}  {detail}".rstrip()


def summary_line(reports: list[Report]) -> str:
    counts = Counter(_label(report) for report in reports)
    parts = [f"{counts[label]} {label}" for label in _LABELS if counts[label]]
    return f"{len(reports)} URLs: " + ", ".join(parts)
