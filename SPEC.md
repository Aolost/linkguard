# SPEC: linkguard

Status: draft, awaiting approval. Update this file in the same pull request as the behavior it describes.

linkguard is a URL risk inspector for Python 3.12. Given a URL it reports suspicious
indicators without rendering or executing page content. It never claims a URL is safe.

## Goals

- Parse and normalize an untrusted URL strictly, so that the host linkguard reasons about is the
  host any other tool would connect to, including obfuscated IP encodings.
- Report heuristic findings, each with a rule ID, severity, evidence, and explanation, and reduce
  them to one of three verdicts: `NO_RED_FLAGS`, `SUSPICIOUS`, `DANGEROUS`.
- Offer an optional fetcher (`SafeFetcher`, off by default) that cannot be turned against the
  user's internal network (SSRF), the user's machine, or the user's time and memory.
- Offer an optional third-party reputation lookup (off by default) that is explicit about
  what it sends and where.
- Offer a CLI and a library with stable exit codes and a versioned JSON schema.

## Non-goals

- Declaring a URL safe. The strongest positive output is "no red flags found".
- Rendering, executing, or analyzing page content (HTML, JavaScript, downloads, malware).
- Browser exploit detection.
- Defending against an attacker who already controls the machine running linkguard.
- Following redirects or resolving DNS unless the user passes `--follow`.
- Any production option that disables, relaxes, or bypasses the SSRF checks.
- Browser-exact URL parsing. linkguard is stricter: ambiguous input is refused, not interpreted.

## Threat model

### Assets

- The user's internal network, local services (loopback), and cloud metadata endpoints
  (for example link-local `169.254.169.254`), reachable only if the fetcher is tricked.
- The user's availability: CPU, memory, wall-clock time, file descriptors.
- Trust in the report: a report must not mislead the reader (false "safe" claims, terminal
  escape injection through echoed evidence).
- The user's reputation-provider API key.

### Attacker

A remote party who wants the user to visit, or the tool to reach, an attacker-chosen
destination, or who wants a malicious URL to be reported as benign.

### Attacker capabilities

- Fully controls the input URL string, including encodings, Unicode, and length.
- Controls DNS answers for domains they own (any number, any addresses, changing between
  queries, so DNS rebinding).
- Controls HTTP responses: redirect targets (`Location`), status, headers, body, size, and timing
  (slow responses, slow-drip bodies).
- Controls the contents of a batch file if the user passes one.

### Out of scope

- Malware in downloaded content, browser exploits, page-content analysis (nothing is parsed or
  rendered; the body is read up to a cap and discarded).
- An attacker who controls the user's machine, resolver configuration, or environment variables.
- A malicious or compromised reputation provider (its answer is shown as data, never trusted to
  lower a verdict).
- Whole-script homograph confusables (for example an all-Cyrillic lookalike of a Latin brand)
  and any spoofing that needs a full Unicode confusables table. Documented as a limitation.
- Network-level interception of the fetch itself beyond normal TLS certificate verification.

## Interfaces

### CLI

```
linkguard check URL [--follow] [--online] [--json]
linkguard batch FILE [--json]
```

- `check` inspects one URL. `--follow` enables `SafeFetcher`. `--online` enables the reputation
  lookup and prints a warning to stderr, before any request, that the URL is sent to a third party.
- `batch` inspects one URL per line. Line endings and surrounding spaces are stripped, blank lines
  are skipped, there is no comment syntax. Limits: file at most 1 MiB, at most 10,000 URLs, each
  line at most 2048 characters (longer lines are reported as refused for that entry). Batch
  never fetches and never goes online.
- Text output goes to stdout, warnings and errors to stderr. All echoed attacker-controlled
  text is escaped to printable ASCII and truncated (evidence at most 200 characters).
- No flag, environment variable, or config file disables SSRF checks.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | `NO_RED_FLAGS` |
| 1 | `SUSPICIOUS` |
| 2 | `DANGEROUS` |
| 3 | Refused or error: input refused by the parser, fetch refused, fetch or reputation error, bad CLI usage, unreadable file |

When a requested step fails (fetch refused or errored, reputation errored) the report is still
printed with whatever was computed, and the exit code is 3. For `batch` the exit code is the
maximum code over all entries.

### Library

```python
@dataclass(frozen=True, slots=True)
class Policy:
    follow: bool = False
    online: bool = False
    # Thresholds below have defaults and are tuning knobs for heuristics only.
    # There is deliberately no field that affects SSRF checks.
    max_hostname_length: int = 50  # LG-011 fires above this
    max_subdomain_depth: int = 4  # LG-010 fires above this


def inspect(url: str, policy: Policy = Policy()) -> Report: ...
```

`inspect` never raises for any `str` input. Input that is refused yields a `Report` with
`outcome="refused"`. The default `Policy` performs no network access.

`Report` is a frozen dataclass with `to_dict()` matching the JSON below.

### Verdict

- Any finding with severity `high` gives `DANGEROUS`.
- Otherwise any finding with severity `low` or `medium` gives `SUSPICIOUS`.
- No findings gives `NO_RED_FLAGS`, rendered as "no red flags found" together with the note that
  this is not a guarantee. The word "safe" never appears in output.
- Reputation results can add findings but never remove or lower one.

### JSON schema (version "1")

```json
{
  "schema_version": "1",
  "tool_version": "0.1.0",
  "input": "escaped, truncated input",
  "outcome": "inspected",
  "refusal": null,
  "normalized_url": "http://xn--example-9d0b.test/path",
  "verdict": "SUSPICIOUS",
  "findings": [
    {
      "rule_id": "LG-005",
      "severity": "low",
      "evidence": "port 8080",
      "explanation": "Non-default port."
    }
  ],
  "fetch": {
    "status": "not_requested",
    "hops": [],
    "final_url": null,
    "http_status": null,
    "content_type": null,
    "bytes_read": 0,
    "truncated": false,
    "reason": null
  },
  "reputation": {
    "status": "not_requested",
    "provider": null,
    "detail": null
  }
}
```

- `outcome` is `inspected` or `refused`. When `refused`, `refusal` is `{"code": ..., "message": ...}`,
  `verdict` and `normalized_url` are null, and `findings` is empty.
- `fetch.status` is one of `not_requested`, `completed`, `refused`, `error`. Each hop is
  `{"url", "http_status", "address"}`. `reason` is a stable code, for example `blocked_address`,
  `redirect_limit`, `timeout`.
- `reputation.status` is one of `not_requested`, `completed`, `error`.
- Findings are sorted by severity (high first), then rule ID, then evidence, so output is
  deterministic.
- Compatibility: within one `schema_version`, fields are only added. A removed or retyped field
  bumps the version. A golden-file test pins the shape.
- The batch JSON document is `{"schema_version": "1", "results": [<report>, ...]}`.

### Normalization contract

Input to `inspect` is a `str`. Output `normalized_url` is `scheme://[host][:port]path[?query]`:

- Scheme lowercased; only `http` and `https` accepted. The `://` form is required.
- Input longer than 2048 characters is refused (2048 accepted, 2049 refused).
- Any control character (C0, DEL, C1), any whitespace (including Unicode whitespace), NUL, and
  backslash anywhere in the input is refused. Parsers disagree on backslash, so it fails closed.
- Fragment is split off and dropped from `normalized_url`; it is never sent anywhere.
- Userinfo is parsed for heuristics, dropped from `normalized_url`, and never sent by the fetcher.
- Host: percent-decoded once (so `%2e` becomes `.`); a `%` remaining after decoding is refused.
  Lowercased, exactly one trailing dot removed, converted to ASCII with IDNA 2008 via `idna`
  (UTS #46 mapping), each label 1 to 63 octets, whole name at most 253. Empty labels refused.
- IPv4 in any legacy form (decimal `2130706433`, hexadecimal `0x7f000001`, octal `0177.0.0.1`,
  mixed `0x7f.1`, short `127.1`) is parsed with WHATWG IPv4 rules and normalized to dotted
  decimal. A host whose last label is numeric or `0x`-prefixed that fails to parse as IPv4 is
  refused rather than treated as a name.
- IPv6 literal must be bracketed, is normalized to compressed lowercase, and zone IDs
  (`%25eth0`) are refused. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is kept as IPv6 for display and
  evaluated as its embedded IPv4 for classification.
- Port: digits only, 1 to 65535, leading zeros allowed, empty port (`host:`) refused, default
  port (80 for http, 443 for https) removed.
- Path and query are kept as given after the character checks above.

### Heuristic rules

| ID | Severity | Fires when | Near-miss that must not fire |
| -- | -------- | ---------- | ---------------------------- |
| LG-001 | medium | userinfo present | no `@` in authority |
| LG-002 | high | userinfo contains a dot-separated hostname-like string or `://` (`paypal.com@evil.test`) | `user@host` with a plain username |
| LG-003 | medium | host is a raw IP address | a name that merely contains digits |
| LG-004 | high | IP written in a non-canonical encoding (decimal, hex, octal, mixed, short) or IPv4-mapped IPv6 | canonical dotted decimal |
| LG-005 | low | explicit port after default-port removal | `:443` on https, `:80` on http |
| LG-006 | low | any `xn--` label | non-IDN host |
| LG-007 | high | one label mixes Latin with Cyrillic or Greek letters | a label of a single script; digits and hyphens are neutral |
| LG-008 | medium | registrable label within edit distance 1 (2 for labels of 8+ characters) of a reference brand label but not equal to it | the exact brand label; unrelated words |
| LG-009 | high | reference brand label appears in a subdomain label and the registrable domain is not that brand's | `www.brand.com`; brand as the registrable domain |
| LG-010 | medium | more subdomain labels than `max_subdomain_depth` | exactly at the threshold |
| LG-011 | low | hostname longer than `max_hostname_length` | exactly at the threshold |
| LG-012 | low | TLD is in the reference suspicious-TLD list | a neighboring TLD not on the list |
| LG-013 | low | registrable domain is in the reference shortener list | a lookalike that is not on the list |
| LG-014 | medium | host contained percent-encoded characters before decoding | plain host |

Reference data (brand labels with their legitimate registrable domains, suspicious TLDs,
shorteners, multi-label public suffixes) lives in one data module with a comment naming its
provenance and review date. Lists are heuristics and are incomplete by nature.

Script detection uses the first word of `unicodedata.name()`, because the standard library has
no script property. This is an approximation and is listed under limitations.

### SafeFetcher

Off by default; enabled only by `--follow` or `Policy(follow=True)`.

Pipeline for each hop (the initial URL and every redirect target):

1. Parse and normalize the URL with the same parser as above. Scheme `http` or `https`, port
   80 or 443 only (checked after default-port removal, so `:8080` is refused).
2. If the host is an IP literal, classify it directly. Otherwise resolve it with the fetcher's
   own resolver (`socket.getaddrinfo`, all address families), once.
3. Every returned address must be allowed. If any one is blocked, the hop is refused, because a
   mixed answer is a rebinding signal.
4. Connect only to a validated IP: the request URL host is the IP literal, the `Host` header is
   the normalized hostname, and the TLS SNI and certificate verification name is the hostname
   (httpx `sni_hostname` extension). The hostname is never resolved a second time.
5. Read the response with a deadline. Redirects (3xx with `Location`) are followed manually,
   `Location` goes back to step 1 with the same 2048-character limit. At most 5 redirects.
   A 6th is refused with `redirect_limit`.

Blocked address classes, implemented as an explicit CIDR table (not `ipaddress.is_global`, whose
behavior varies by Python patch release): loopback, private (RFC 1918), link-local, CGNAT
(`100.64.0.0/10`), multicast, reserved and special-purpose per the IANA registries, unspecified,
IPv6 loopback, ULA (`fc00::/7`), IPv6 link-local (`fe80::/10`), deprecated site-local
(`fec0::/10`), and IPv4-mapped, NAT64 (`64:ff9b::/96`), and 6to4 (`2002::/16`) addresses, which
are evaluated by their embedded IPv4. The table fails closed: an address not clearly global is
blocked.

Limits (constants, not user-configurable):

| Limit | Value |
| ----- | ----- |
| Connect timeout | 5 s |
| Total time (DNS, all hops, body) | 10 s |
| Body bytes read | 65,536; read stops there and `truncated` is true |
| Redirects | 5 |
| Ports | 80, 443 |
| URL length | 2048 characters |

Other properties: `GET` only; fixed `User-Agent: linkguard/<version>`; `Accept-Encoding:
identity` so no decompression bomb; no cookies, no `Authorization`, no userinfo sent; no
cookie jar carried between hops; `trust_env=False` so proxy and netrc environment cannot
redirect traffic; certificate verification always on; the body is discarded, never parsed.

Test seams: the resolver, the HTTP transport, and the clock are injectable through the
`SafeFetcher` constructor, which is how tests run offline. They sit before validation, so an
injected resolver can return anything but the allow/deny check still runs on it. No injection
point replaces the check.

### Reputation provider

Off by default; enabled only by `--online` or `Policy(online=True)`.

- The API key is read from an environment variable only (name: see open questions), never from
  a CLI argument, never logged, never included in output, exceptions, or `repr` (held in a
  wrapper whose `repr` is redacted).
- Before the request, stderr shows: the URL will be sent to the named third-party provider.
- The provider endpoint is a fixed HTTPS URL in code, not attacker-controlled; redirects are not
  followed; same timeouts and a 64 KB response cap as the fetcher.
- A missing key, a network error, or a malformed response yields `reputation.status="error"`
  and exit code 3. Local findings are still reported.
- A "not listed" answer from the provider is reported as exactly that, and does not affect the
  verdict.

## Invariants

1. `inspect(s)` returns a `Report` for every `str` `s` and never raises (property-tested with
   Hypothesis on arbitrary text, including surrogates and control characters).
2. Normalization is idempotent: normalizing a `normalized_url` returns the same value.
3. Output text and JSON never contain the word "safe" (case-insensitive, whole word).
4. Every string echoed in text or JSON output is printable ASCII (non-ASCII and control
   characters escaped) and bounded in length.
5. The fetcher only ever opens a connection to an IP literal that passed the allow check
   (asserted on every request seen by the fake transport).
6. The resolver is called exactly once per hop. A resolver whose answers change between calls
   cannot cause a connection to a different address than the one validated.
7. A hop with any blocked address in its answers is refused with no connection made.
8. Every redirect target is re-parsed and re-validated; a redirect to a blocked address,
   non-HTTP scheme, or disallowed port is refused.
9. With a fake clock: connect attempts are limited to 5 s, the whole `--follow` run to 10 s, the
   body read to 65,536 bytes, redirects to 5.
10. No request carries `Cookie`, `Authorization`, `Proxy-Authorization`, or userinfo.
11. With the default `Policy`, no resolver or transport call is made (the fakes fail if called).
12. The API key sentinel used in tests appears in no output, no exception message, and no `repr`.
13. Findings order is deterministic and exit codes follow the table above.
14. No CLI flag, `Policy` field, or environment variable affects SSRF validation (the CLI help
    and `Policy` fields are asserted).

## Edge cases

Each is a test, positive and negative where it applies:

- Empty string, whitespace only, leading or trailing whitespace, internal space, tab, newline.
- NUL, other C0 controls, DEL, C1 controls, bidi override characters, lone surrogates.
- Backslash in authority or path (`http://good.test\@evil.test/`).
- URL of exactly 2048 and of 2049 characters; 10 MB input.
- Missing scheme, `//host`, `http:/host`, `http:host`, uppercase scheme, `ftp://`, `javascript:`,
  `file://`, `data:`.
- Empty host, `http://:80`, `http://@host`, multiple `@`, `@` in userinfo percent-encoded.
- Fragment containing `@` or a second URL; fragment-only differences; `#` before `?`.
- IPv6: zone ID (`[fe80::1%25eth0]`), unbracketed, unclosed bracket, `[::ffff:127.0.0.1]`,
  `[::ffff:7f00:1]`, `[64:ff9b::7f00:1]`, `[2002:7f00:1::]`, `[::]`, `[::1]`.
- IPv4 encodings: `2130706433`, `0x7f000001`, `0177.0.0.1`, `0x7f.0.0.1`, `127.1`, `0x7f.1`,
  out-of-range octets, overflow (`4294967296`), `1.2.3.4.5`, hex with invalid digits.
- Percent-encoded dots (`127%2e0%2e0%2e1`), double encoding (`%252e`), percent-encoded host
  letters.
- Trailing dot (`example.test.`), two trailing dots, empty labels, 64-character label,
  254-character name.
- Internationalized domains: valid IDN, invalid punycode (`xn--`), mixed-script label,
  full-width digits and dots (`１２７．０．０．１`), IDNA 2003 versus 2008 differences (for example
  `ß`).
- Ports: `:0`, `:65536`, `:08080`, empty `:`, non-digit, default port spelled `:0080`.
- Fetcher: DNS answers mixing public and blocked addresses; rebinding on second query; empty
  DNS answer; resolver raising; IPv6-only answer; redirect loop; 6th redirect; redirect to
  `Location` with userinfo, relative path, scheme-relative, `file:`, over-long, non-ASCII;
  slow-drip body past the deadline; body exactly 65,536 and 65,537 bytes; connect timeout;
  `Set-Cookie` in a response (must not be replayed).
- Batch: empty file, blank lines only, binary file, a 10,001-line file, a line over 2048
  characters, a file over 1 MiB, missing file, directory instead of file.
- Concurrent use: `inspect` holds no module-level mutable state, so concurrent calls are safe
  (asserted by a threaded test).

## Acceptance criteria

- [ ] `make check` passes (format check, lint, `mypy --strict`, tests, coverage gate at 80 percent
      overall).
- [ ] Coverage of the parser and the SSRF address-classification module is at least 90 percent
      (line and branch), enforced by a separate `make` gate.
- [ ] All invariants above have at least one test; heuristics LG-001 to LG-014 each have a
      positive and a near-miss test.
- [ ] Tests are offline: fake DNS, fake transport, fake clock; a guard fixture fails any test
      that opens a real socket.
- [ ] The CLI exits with 0, 1, 2, 3 as specified, each covered by a test.
- [ ] JSON output matches the version "1" golden file; `--json` output parses and contains
      `schema_version`.
- [ ] Output never contains the word "safe".
- [ ] README contains the threat model, a fetch-pipeline diagram, real example output captured
      by running the tool, limitations, and the online-provider privacy note. Behavioral claims
      in the README link to a test; no performance claim is made without a reproducible
      benchmark (none is planned, so none is made).

## Dependencies

Runtime dependencies are added only in the slice that first imports them. Pinned through
`uv.lock`; the version column is filled with the locked version in that slice's commit.

| Name | Used for | Why not in-house | Vetting (performed in the adding slice, recorded in the commit message) |
| ---- | -------- | ---------------- | ----------------------------------------------------------------------- |
| `idna` | IDNA 2008 / UTS #46 host conversion | The standard `idna` codec implements the obsolete IDNA 2003; correct 2008 tables and mapping are large data sets that must not be hand-written. Already a transitive dependency of `httpx`. | License, maintainer, release age, `uv lock` diff, known advisories |
| `httpx` | HTTP client for `SafeFetcher` and the reputation provider | TLS with a custom SNI name distinct from the connect address, streaming reads, per-operation timeouts and a transport seam for fakes. In-house this is a TLS and HTTP/1.1 client, which is risky security code. | Same, plus review of `sni_hostname` and `trust_env` behavior in the locked version |
| `typer` | CLI | Argument parsing, help, exit-code plumbing. This one is a convenience: `argparse` could do it in the standard library. Recorded here because the brief names `typer`; the cost is `click` as a transitive dependency. | Same |

Development tools: `pytest` (test runner), `pytest-cov` (coverage gate, already present),
`hypothesis` 6.170.17 (property tests on arbitrary text; the standard library has no generator; dev only, never imported by shipped code),
`ruff` (lint and format), `mypy` (strict typing). All except `hypothesis` are already in
`pyproject.toml`.

No cryptography is written. TLS and certificate verification are the standard library `ssl`
module through `httpx`, with the system trust store and default hostname checking; hostname
checking uses the original hostname, not the IP.

## Decisions

- Registrable domain: no Public Suffix List dependency. The data module embeds a small table of
  common multi-label public suffixes. Limitation: unlisted suffixes give wrong answers for
  LG-008, LG-009, LG-010, and LG-013.
- `batch` accepts `--json` and emits the batch document shown under Interfaces.
- Reference lists (brands, suspicious TLDs, shorteners) are proposed small and reviewed in the
  diff of the slice that adds them.

## Open questions

1. **Reputation provider and environment variable name.** The brief does not name a provider.
   The reputation slice needs the provider, its API terms, and the variable name. Nothing before
   that slice depends on it.
