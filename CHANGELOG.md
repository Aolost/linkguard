# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `linkguard.parse.parse_url`: strict URL splitting (scheme, userinfo, host, port, path/query); refuses control characters, whitespace, backslash, over-long input, bad ports, and malformed hosts.

- Initial project scaffold.
- SPEC.md: goals, threat model, interfaces, invariants, edge cases, dependencies. Revised: no batch JSON, DNS in a killable child process with an async total deadline, versioned reference data, reputation provider deferred to the final milestone.

### Changed

- Minimum Python is 3.12. Added `hypothesis` as a dev dependency.
