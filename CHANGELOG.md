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
- `linkguard.data` (versioned reference lists, `DATA_VERSION` pinned to a content digest by a test) and rules LG-008 (typosquat), LG-009 (brand in subdomain), LG-010 (subdomain depth, `Policy.max_subdomain_depth`), LG-012 (suspicious TLD), LG-013 (URL shortener); `split_host` is relative to the listed suffixes, not the Public Suffix List.
- `linkguard.inspect(url, policy)` returning a frozen `Report` with `to_dict()` (JSON schema version 1, pinned by a independently written golden file), verdicts `NO_RED_FLAGS`/`SUSPICIOUS`/`DANGEROUS`, and normalized URLs that are always printable ASCII. Refused input yields a refused report, never an exception.
- `linkguard.ssrf.blocked_reason`: explicit CIDR blocklist (IPv4 and IPv6, with mapped, NAT64 and 6to4 judged by their embedded IPv4) that fails closed.
- `linkguard.resolve`: `SubprocessResolver` (name lookup in a child process that is killed, drained and reaped on timeout; output capped at 4096 bytes and every line validated) and `resolve_hop`, which refuses a hop if any resolved address is blocked, the answer is empty, or the resolver misbehaves.
- `linkguard.hop.HopClient`: one pinned GET to a validated IP with the hostname kept for `Host`, SNI and certificate verification; 64 KB body cap, no cookies or credentials, `trust_env=False`, redirects reported not followed, stable failure reasons. Adds `httpx` (runtime) and `trustme` (dev only). Tests include real TLS on loopback and a socket guard that fails any test touching a non-loopback address.
- `linkguard.fetch.SafeFetcher`: validates every hop (ports 80 and 443 only, every resolved address checked before any connection, resolver called once per hop), follows at most 5 redirects by hand, tries at most 3 addresses, and enforces a 10 second total deadline with `asyncio.timeout` (DNS wait capped at 5 seconds). Returns a `FetchSummary`; refusals and errors are reported, never raised.
- `linkguard check URL [--follow] [--json]` (typer CLI, also `python -m linkguard`), text and JSON output, exit codes 0/1/2/3 with usage errors mapped to 3, and `Policy.follow` wired into `inspect()` (fetch runs on its own event loop in a helper thread). Server-controlled `Content-Type` is escaped to printable ASCII. Adds `typer`.
- `linkguard batch FILE`: one text line per URL plus a summary; whole-file refusal for unreadable, oversized (over 1 MiB), non-UTF-8, empty, or over-10,000-URL files; exit code is the maximum over entries. `version()` is now cached, which roughly halved the time of a 10,000 URL batch on the development machine.
- README: threat model, fetch-pipeline diagram, rule table, example output captured by running the tool, limitations, what is not verified, and a table tying each behavior claim to a test. `tests/test_readme.py` re-runs every example and checks that every cited test exists.
- `make coverage-gate`: parser, host and SSRF modules must keep at least 90 percent line and branch coverage; run as part of `make check`.

### Fixed

- Test sources no longer contain literal invisible or look-alike characters (no-break space, U+2028, the right-to-left override, full-width digits); they are built from code points in `tests/chars.py`.

- `HopClient` reports `httpx.InvalidURL` (raised by the HTTP library while it parses a hostile `Location`) as `http_error` instead of letting it escape.

- `normalize_domain` refuses a lone surrogate with `ParseError` instead of raising `UnicodeEncodeError` (found by property tests).

### Changed

- Decision recorded in SPEC.md and README: no online reputation lookup in this release. There is no `--online` option, no API-key variable, and no URL is sent to any third party.
- Minimum Python is 3.12, pinned by `.python-version` and mypy `python_version`. Added `hypothesis` as a dev dependency.
