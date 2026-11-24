"""Keeps README.md honest: its examples are re-run and cited tests must exist."""

import re
import shlex
from pathlib import Path

import pytest

from linkguard.cli import main

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")

EXAMPLE = re.compile(
    r"<!-- example exit=(\d): (?P<args>.+?) -->\n"
    r"```text\n\$ (?P<command>.+?)\n(?P<output>.*?)```",
    re.DOTALL,
)
FILE_BLOCK = re.compile(
    r"<!-- file: (?P<name>\S+) -->\n```text\n(?P<content>.*?)```", re.DOTALL
)
TEST_REFERENCE = re.compile(r"`(tests/[\w/]+\.py)::(\w+)`")
PERFORMANCE_WORDS = re.compile(
    r"\b(fast|faster|fastest|quick|quickly|lightweight|efficient|scalable|milliseconds?)\b",
    re.IGNORECASE,
)


def examples() -> list[tuple[int, list[str], str, str]]:
    return [
        (
            int(m.group(1)),
            shlex.split(m.group("args")),
            m.group("command"),
            m.group("output"),
        )
        for m in EXAMPLE.finditer(README)
    ]


def test_the_readme_has_examples_and_the_required_sections() -> None:
    assert len(examples()) >= 5
    for heading in (
        "## What it is and why",
        "## Install",
        "## Usage",
        "## How it works",
        "## Threat model",
        "## Limitations",
        "## What is not verified",
        "## Testing",
        "## Online reputation lookup",
    ):
        assert heading in README


@pytest.mark.parametrize("expected", examples(), ids=lambda e: e[2])
def test_every_readme_example_matches_the_real_output_and_exit_code(
    expected: tuple[int, list[str], str, str],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    code, args, command, output = expected
    files = {m.group("name"): m.group("content") for m in FILE_BLOCK.finditer(README)}
    resolved = []
    for arg in args:
        if arg in files:
            (tmp_path / arg).write_text(files[arg], encoding="utf-8")
            arg = str(tmp_path / arg)
        resolved.append(arg)
    assert main(resolved) == code
    assert capsys.readouterr().out == output
    assert command.startswith("linkguard ")


def test_every_test_the_readme_cites_exists() -> None:
    references = TEST_REFERENCE.findall(README)
    assert len(references) >= 20
    for path, name in references:
        source = (ROOT / path).read_text(encoding="utf-8")
        assert re.search(rf"^(async )?def {name}\(", source, re.MULTILINE), (path, name)


def test_the_readme_makes_no_performance_claims() -> None:
    assert PERFORMANCE_WORDS.findall(README) == []


def test_the_readme_has_no_unfilled_template_comments() -> None:
    text = re.sub(r"<!-- (example exit=\d|file):.*?-->", "", README)
    assert "<!--" not in text
