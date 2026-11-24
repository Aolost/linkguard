# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project scaffold.
- SPEC.md: goals, threat model, interfaces, invariants, edge cases, dependencies. Revised: no batch JSON, DNS in a killable child process with an async total deadline, versioned reference data, reputation provider deferred to the final milestone.
- `linkguard.parse.parse_url`: strict URL splitting (scheme, userinfo, host, port, path/query); refuses control characters, whitespace, backslash, over-long input, bad ports, and malformed hosts.
- `linkguard.host.normalize_domain`: percent-decode once, IDNA 2008 (UTS #46) to ASCII, label and length limits; adds the `idna` dependency.
- `linkguard.host.normalize_host`: legacy IPv4 spellings (decimal, hex, octal, short, mixed) and bracketed IPv6 literals; zone IDs and malformed numeric hosts are refused.
- `linkguard.heuristics.find_findings` with rules LG-001 (userinfo), LG-002 (userinfo that looks like a destination), LG-003 (raw IP), LG-004 (obfuscated IP), LG-005 (non-default port), LG-014 (percent-encoded host); `linkguard.model` finding types and `escape_text` for echoed input. Userinfo passwords are never put in evidence.
- Rules LG-006 (punycode label), LG-007 (Latin mixed with Cyrillic or Greek in one label), LG-011 (long hostname); `Policy.max_hostname_length`.
- `make coverage-gate`: parser and host modules must keep at least 90 percent line and branch coverage; run as part of `make check`.

### Fixed

- `normalize_domain` refuses a lone surrogate with `ParseError` instead of raising `UnicodeEncodeError` (found by property tests).

### Changed

- Minimum Python is 3.12, pinned by `.python-version` and mypy `python_version`. Added `hypothesis` as a dev dependency.
