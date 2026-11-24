# linkguard

## What it is and why

<!-- One paragraph: what this does, who needs it, and the problem it solves. -->

## Install

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer.

```bash
git clone https://github.com/aolost/linkguard.git
cd linkguard
uv sync --locked
```

## Usage

```bash
uv run --locked python -c "import linkguard; print(linkguard.version())"
```

Expected output: `0.1.0`

## How it works

<!-- The mechanism in plain terms: data flow, main components, trust boundaries. -->

## Design decisions and tradeoffs

<!-- Each decision: what was chosen, what was rejected, and what it costs. -->

## Threat model

<!-- Summary of the threat model in SPEC.md: assets, attacker, what is out of scope. -->

## Limitations

<!-- What it does not handle, known weaknesses, unsupported platforms. -->

## Testing

Run everything CI runs (format check, lint, type check, tests with an 80 percent coverage gate):

```bash
make check
```

## License

MIT. See [LICENSE](LICENSE).
