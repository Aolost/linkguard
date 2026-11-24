"""Plain-text rendering of a `Report`.

Every attacker-controlled string is already escaped to printable ASCII when the report
is built, so nothing here escapes again.
"""

from linkguard.model import Report, Verdict

_NO_RED_FLAGS_NOTE = (
    "No red flags found. This does not mean the URL is trustworthy; "
    "linkguard only reports indicators."
)


def _verdict_lines(report: Report) -> list[str]:
    if report.verdict is None:
        return ["Verdict:  none (input refused)"]
    lines = [f"Verdict:  {report.verdict}"]
    if report.verdict is Verdict.NO_RED_FLAGS:
        lines.append(f"          {_NO_RED_FLAGS_NOTE}")
    return lines


def _finding_lines(report: Report) -> list[str]:
    if not report.findings:
        return []
    lines = ["Findings:"]
    for finding in report.findings:
        lines.append(f"  [{finding.severity}] {finding.rule_id}  {finding.evidence}")
        lines.append(f"      {finding.explanation}")
    return lines


def _fetch_lines(report: Report) -> list[str]:
    fetch = report.fetch
    if fetch.status == "not_requested":
        return []
    summary = f"Fetch:    {fetch.status}"
    if fetch.reason is not None:
        summary += f" ({fetch.reason})"
    if fetch.status == "completed":
        summary += f", HTTP {fetch.http_status}, {fetch.bytes_read} bytes read" + (
            " (truncated)" if fetch.truncated else ""
        )
    lines = [summary]
    for number, hop in enumerate(fetch.hops, start=1):
        lines.append(f"  hop {number}: {hop.http_status} {hop.url} via {hop.address}")
    return lines


def render_text(report: Report) -> str:
    lines = [f"linkguard {report.tool_version} (reference data {report.data_version})"]
    lines.append(f"Input:    {report.input}")
    if report.refusal is not None:
        lines.append(f"Refused:  {report.refusal.code} - {report.refusal.message}")
    if report.normalized_url is not None:
        lines.append(f"Checked:  {report.normalized_url}")
    lines += _verdict_lines(report)
    lines += _finding_lines(report)
    lines += _fetch_lines(report)
    return "\n".join(lines) + "\n"
