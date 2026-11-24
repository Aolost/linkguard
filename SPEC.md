# SPEC: linkguard

Status: revised draft. Update this file in the same pull request as the behavior it describes.

linkguard is a URL risk inspector for Python 3.12. Given a URL it reports suspicious
indicators without rendering or executing page content. It never claims a URL is safe.

## Goals

- Parse and normalize an untrusted URL strictly, so that the host linkguard reasons about is the
  host any other tool would connect to, including obfuscated IP encodings.
- Report heuristic findings, each with a rule ID, severity, evidence, and explanation, and reduce
  them to one of three verdicts: `NO_RED_FLAGS`, `SUSPICIOUS`, `DANGEROUS`.
- Offer an optional fetcher (`SafeFetcher`, off by default) that cannot be turned against the
  user's internal network (SSRF), the user's machine, or the user's time and memory.
- Offer a CLI and a library with stable exit codes and a versioned JSON schema.

## Non-goals

- Declaring a URL safe. The strongest positive output is "no red flags found".
- Rendering, executing, or analyzing page content (HTML, JavaScript, downloads, malware).
- Browser exploit detection.
- Defending against an attacker who already controls the machine running linkguard.
- Following redirects or resolving DNS unless the user passes `--follow`.
- Any production option that disables, relaxes, or bypasses the SSRF checks.
- Browser-exact URL parsing. linkguard is stricter: ambiguous input is refused, not interpreted.
- Generic registrable-domain accuracy. See "Reference data".
- JSON output for `batch`.
- Any online reputation lookup: no third-party service, no `--online` flag, no `Policy.online` field,
  and no API-key environment variable. No URL is sent to any third party. The only network access is
  the user-requested `--follow`, which contacts the URL's own server.

## Threat model

### Assets

- The user's internal network, local services (loopback), and cloud metadata endpoints
  (for example link-local `169.254.169.254`), reachable only if the fetcher is tricked.
- The user's availability: CPU, memory, wall-clock time, file descriptors.
- Trust in the report: a report must not mislead the reader (false "safe" claims, terminal
  escape injection through echoed evidence).

### Attacker

A remote party who wants the user to visit, or the tool to reach, an attacker-chosen
destination, or who wants a malicious URL to be reported as benign.

### Attacker capabilities

- Fully controls the input URL string, including encodings, Unicode, and length.
- Controls DNS answers for domains they own (any number, any addresses, changing between
  queries, so DNS rebinding).
- Controls HTTP responses: redirect targets (`Location`), status, headers, body, size, and timing
  (slow responses, slow-drip bodies, trickled TLS handshakes).
- Controls the contents of a batch file if the user passes one.

### Out of scope

- Malware in downloaded content, browser exploits, page-content analysis (nothing is parsed or
  rendered; the body is read up to a cap and discarded).
- An attacker who controls the user's machine, resolver configuration, or environment variables.
- Whole-script homograph confusables (for example an all-Cyrillic lookalike of a Latin brand)
  and any spoofing that needs a full Unicode confusables table. Documented as a limitation.
- Network-level interception of the fetch itself beyond normal TLS certificate verification.
- Work done by system resolver daemons after linkguard stops waiting for them.

## Supported Python

Python 3.12. This is enforced, not assumed: `.python-version` is `3.12`, `requires-python` is
`>=3.12`, mypy's `python_version` is `3.12`, and CI runs under the pin. Newer interpreters are not
tested.

## Interfaces

### CLI

```
linkguard check URL [--follow] [--json]
linkguard batch FILE
```

- `check` inspects one URL. `--follow` enables `SafeFetcher`. Text output lists the input, the
  normalized URL, the verdict, each finding (`[severity] rule-id  evidence` and its explanation), and,
  with `--follow`, the fetch result and each hop. A clean result prints "No red flags found. This does
  not mean the URL is trustworthy". `--json` prints the report dictionary and nothing else.
- Typer's own usage errors exit 2, which would collide with `DANGEROUS`, so `main()` catches them,
  prints `Error: <escaped message>` to stderr, and exits 3. Shell completion is disabled because it
  edits the user's shell startup files, and pretty exceptions are disabled because they print local
  variables, including the URL under test.
- `batch` inspects one URL per line and prints one text line per URL: the file line number, the
  verdict (or `REFUSED`), the escaped input, and the rule IDs (or the refusal code), followed by a
  summary line such as `4 URLs: 1 NO_RED_FLAGS, 1 SUSPICIOUS, 1 DANGEROUS, 1 REFUSED`. Only `\n`
  separates entries; a trailing `\r` and surrounding spaces and tabs are stripped, and blank lines
  are skipped (but still counted in line numbers). There is no comment syntax, so `# note` is a
  refused entry. Other separators (form feed, U+2028) stay inside the line, where the URL parser
  refuses them. A line longer than 2048 characters is refused as its own entry.
- `batch` refuses the whole file, with exit code 3, a message on stderr, and nothing on stdout, if
  it is unreadable (missing, a directory), larger than 1 MiB, not valid UTF-8, holds no URLs, or
  holds more than 10,000 URLs. At most 1 MiB + 1 byte is ever read. Otherwise the exit code is the
  maximum over all entries. Batch never fetches and has no `--json`, `--follow`, or `--online`.
- Text output goes to stdout, warnings and errors to stderr. All echoed attacker-controlled
  text is escaped to printable ASCII and truncated (evidence at most 200 characters).
- No flag, environment variable, or config file disables SSRF checks.
- `--online` does not exist (asserted by tests of the `check` and `batch` help).

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | `NO_RED_FLAGS` |
| 1 | `SUSPICIOUS` |
| 2 | `DANGEROUS` |
| 3 | Refused or error: input refused by the parser, fetch refused or failed, bad CLI usage, unreadable file |

When a requested step fails (fetch refused or errored) the report is still printed with whatever
was computed, and the exit code is 3. For `batch` the exit code is the maximum code over all
entries.

### Library

```python
@dataclass(frozen=True, slots=True)
class Policy:
    follow: bool = False
    # Thresholds below have defaults and are tuning knobs for heuristics only.
    # There is deliberately no field that affects SSRF checks.
    max_hostname_length: int = 50  # LG-011 fires above this
    max_subdomain_depth: int = 4  # LG-010 fires above this


def inspect(url: str, policy: Policy = Policy()) -> Report: ...
```

`inspect` never raises for any `str` input. Input that is refused yields a `Report` with
`outcome="refused"`. The default `Policy` performs no network access. With `follow=True`,
`inspect` runs the fetch on a private event loop in a helper thread, so it works whether or not
the caller is inside an event loop.

`Report` is a frozen dataclass with `to_dict()` matching the JSON below.

### Verdict

- Any finding with severity `high` gives `DANGEROUS`.
- Otherwise any finding with severity `low` or `medium` gives `SUSPICIOUS`.
- No findings gives `NO_RED_FLAGS`, rendered as "no red flags found" together with the note that
  this is not a guarantee. The word "safe" never appears in output.

### JSON schema (version "1")

Version "1" is the schema of the first release.

```json
{
  "schema_version": "1",
  "tool_version": "0.1.0",
  "data_version": "1",
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
  }
}
```

- `outcome` is `inspected` or `refused`. When `refused`, `refusal` is `{"code": ..., "message": ...}`,
  `verdict` and `normalized_url` are null, and `findings` is empty.
- `data_version` is the version of the reference data (see "Reference data") used for the report.
- `fetch.status` is one of `not_requested`, `completed`, `refused`, `error`. Each hop is
  `{"url", "http_status", "address"}`. `reason` is one of the stable codes listed under SafeFetcher.
- There is no `reputation` object: no online lookup exists.
- Findings are sorted by severity (high first), then rule ID, then evidence, so output is
  deterministic.
- Compatibility, once frozen: within one `schema_version`, fields are only added. A removed or
  retyped field bumps the version. A golden-file test pins the shape.

### Normalization contract

Input to `inspect` is a `str`. Output `normalized_url` is `scheme://[host][:port]path[?query]`:

- Scheme lowercased; only `http` and `https` accepted. The `://` form is required.
- Input longer than 2048 characters is refused (2048 accepted, 2049 refused).
- Any control character (C0, DEL, C1), any whitespace (including Unicode whitespace), NUL, lone
  surrogate, and backslash anywhere in the input is refused. Parsers disagree on backslash, so
  it fails closed.
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
- Path and query are kept as given after the character checks above, except that non-ASCII
  characters are percent-encoded as UTF-8 so `normalized_url` is always printable ASCII. Existing
  `%XX` sequences are left alone, which keeps normalization idempotent.
- Mapped IPv6 addresses are always written as `::ffff:HHHH:HHHH` because Python's own `str()` of
  them differs between versions.

### Reference data

All heuristic data lives in one module, `linkguard.data`, under one `DATA_VERSION` string that
appears in every report as `data_version`. The module holds four lists. Its header states the provenance honestly: the lists were
compiled on 2026-11-25 from general knowledge, not derived from
the Public Suffix List or any threat-intelligence feed, and have not been audited for completeness
or false positives. The lists are:

1. Multi-label suffixes (for example `co.uk`), used only to split a host into subdomain labels,
   one registrable label, and a suffix.
2. Brands: a label of at least 5 characters (`paypal`) and the exact domains that legitimately own
   it (`paypal.com`). Shorter labels are excluded because they sit within one edit of too many
   ordinary words, so brands such as `ebay` are not covered.
3. Suspicious TLDs.
4. URL shortener domains.

Any change to a list changes `DATA_VERSION`, and a test pins the version to the list contents so
they cannot drift apart.

**The suffix data is not the Public Suffix List and linkguard does not claim registrable-domain
accuracy.** The split is defined only relative to list 1 at the stated `DATA_VERSION`:

- A host that ends in a listed multi-label suffix uses the longest such suffix. Every other host
  uses its last label as the suffix.
- Known wrong answers: hosts under an unlisted multi-label suffix (for example an unlisted
  `.co.xx`) get one extra label counted as the registrable label, which can raise a false LG-010
  and cause LG-008 and LG-009 to miss; private-suffix hosting domains (for example user-content
  platforms) are treated as ordinary domains.
- Only LG-008, LG-009, and LG-010 depend on the split. LG-012 uses the last label. LG-013 and the
  legitimate-domain check in LG-009 match host-suffix against list 4 and list 2 and do not use
  the split.
- The README limitations section repeats this, with the `DATA_VERSION` it describes.

Script detection (LG-007) uses the first word of `unicodedata.name()`, because the standard
library has no script property. This is an approximation and is listed under limitations.

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
| LG-008 | medium | registrable label (per list 1) within edit distance 1 (2 for labels of 8+ characters) of a brand label but not equal to it | the exact brand label; unrelated words |
| LG-009 | high | a brand label equals a hyphen-separated token of a subdomain label (per list 1) and the host is not equal to or under a domain that legitimately owns it (list 2) | `www.brand.com`; brand as the registrable label of its own domain; `pineapple` for brand `apple` |
| LG-010 | medium | more subdomain labels (per list 1) than `max_subdomain_depth` | exactly at the threshold |
| LG-011 | low | hostname longer than `max_hostname_length` | exactly at the threshold |
| LG-012 | low | last label is in list 3 | a neighboring TLD not on the list |
| LG-013 | low | host equals or is under a domain in list 4 | a lookalike that is not on the list |
| LG-014 | medium | host contained percent-encoded characters before decoding | plain host |

### SafeFetcher

Off by default; enabled only by `--follow` or `Policy(follow=True)`.

Structure. `SafeFetcher` owns validation, redirect handling, and the deadline. For each hop it
hands a validated IP literal to a private `HopClient`, which owns connecting, TLS, and reading.
The validation function is called by `SafeFetcher` unconditionally and is not a parameter of
anything. `HopClient` is not exported, is not reachable from the CLI or `Policy`, and rejects any
`ssl.SSLContext` that does not have `CERT_REQUIRED` and `check_hostname` set. The fetcher is async;
`inspect` drives it as described under "Library".

Pipeline for each hop (the initial URL and every redirect target):

1. Parse and normalize the URL with the same parser as above. Scheme `http` or `https`, port
   80 or 443 only (checked after default-port removal, so `:8080` is refused).
2. If the host is an IP literal, classify it directly. Otherwise resolve it once with the
   resolver (see "DNS" below).
3. Every returned address must be allowed. If any one is blocked, or the answer is empty, the hop
   is refused with no connection made, because a mixed answer is a rebinding signal.
4. Connect only to a validated IP: the request URL host is the IP literal, the `Host` header is
   the normalized hostname, and the TLS SNI and certificate verification name is the hostname
   (httpx `sni_hostname` extension). The hostname is never resolved a second time. Addresses are
   tried in resolver order, at most 3, all validated before the first connection.
5. Read the response. Redirects (301, 302, 303, 307, 308 with a `Location`) are followed manually.
   `Location` is hostile text: over 2048 characters is refused. A value that carries its own scheme
   goes to the strict parser untouched (so `http://` is refused, not "repaired" by borrowing the
   current host); only scheme-less references are joined to the current URL. The result goes back
   to step 1. At most 5 redirects are followed, so at most 6 hops are fetched, and a 6th redirect
   is refused with `redirect_limit`.
6. If a connection to one validated address is refused, the next validated address is tried, at
   most 3 in all. Every other failure (timeout, TLS error, HTTP error) stops the fetch.

`fetch.status` is `refused` for policy decisions (`blocked_address`, `no_addresses`,
`port_not_allowed`, `redirect_limit`, `invalid_url`, `invalid_redirect`) and `error` for
operational failures (`dns_failed`, `dns_timeout`, `timeout`, `tls_error`, `connect_failed`,
`http_error`). A malformed `Location` that the HTTP library itself rejects while building its own
redirect request (for example `javascript:alert(1)`) is reported as `http_error`.

Blocked address classes, implemented as an explicit CIDR table in `linkguard.ssrf` (not
`ipaddress.is_global`, whose behavior varies by Python patch release):

- IPv4: `0.0.0.0/8` (unspecified), `10/8`, `172.16/12`, `192.168/16` (private), `100.64/10`
  (CGNAT), `127/8` (loopback), `169.254/16` (link-local), `192.0.0.0/24` and `192.88.99.0/24`
  and `240/4` including the broadcast address (reserved), `192.0.2/24`, `198.51.100/24`,
  `203.0.113/24` (documentation), `198.18/15` (benchmarking), `224/4` (multicast).
- IPv6: only global unicast `2000::/3` can be allowed. Everything outside it is blocked
  (unspecified `::`, loopback `::1`, ULA `fc00::/7`, link-local `fe80::/10`, deprecated
  site-local `fec0::/10`, multicast `ff00::/8`, and all other space as `non_global`). Inside
  `2000::/3` these are also blocked: `2001::/23` (IETF protocol assignments, including Teredo),
  `2001:db8::/32` and `3fff::/20` (documentation).
- IPv4-mapped (`::ffff:0:0/96`), NAT64 (`64:ff9b::/96`), and 6to4 (`2002::/16`) addresses are
  evaluated by the IPv4 address they embed, so `::ffff:127.0.0.1` is blocked as loopback and
  `::ffff:8.8.8.8` is allowed. Other NAT64 prefixes such as `64:ff9b:1::/48` are blocked.

The table fails closed: an address not clearly global is blocked. A test asserts that every address
Python 3.12 reports as non-global is also blocked here. That is a floor, not a proof of
completeness, and it depends on the interpreter's own tables.

#### DNS

`socket.getaddrinfo` cannot be cancelled, and a worker thread running it keeps running after a
timeout, so a thread is not used. The default resolver runs `getaddrinfo` in a short-lived child
process (`sys.executable -I -c <fixed source>`; the hostname is sent on stdin, never in argv) and
kills the child on timeout. Output is read up to 4096 bytes and every line must parse as an IP
address (a scoped address such as `fe80::1%eth0` is refused), otherwise the lookup fails closed
(`dns_failed`). After any outcome the child is killed, its stdout is drained so the exit is
observed, and it is reaped. The DNS wait is capped at 5 s and by
the time remaining in the total deadline. Any failure to start the child also fails closed.

What this does and does not guarantee: linkguard stops waiting at the deadline and the child is
killed. It does not control work that a system resolver daemon (for example systemd-resolved)
already started on the child's behalf. A lookup of the same name by a daemon is not attributable
to a linkguard process after the kill.

The resolver is an injectable `async` callable for tests. It sits before validation, so an
injected resolver can return anything and the allow/deny check still runs on its output.

#### Limits and how each is enforced

Constants, not user-configurable. Tests may pass lower values through a private constructor
argument; the fetcher clamps them with `min()`, so a value can lower a limit and never raise it.

| Limit | Value | Enforcement | Guarantee |
| ----- | ----- | ----------- | --------- |
| DNS wait | 5 s | child process killed | Hard for linkguard's own wait. Does not bound resolver daemons. |
| Connect timeout | 5 s | httpx connect timeout, per connection attempt | Per attempt. A trickled TLS handshake is bounded by the total deadline, not by this value. |
| Total time (DNS, every hop, TLS, headers, body) | 10 s | one `asyncio.timeout` around the whole fetch | Enforced at every await point by cancellation. Not a real-time guarantee: overshoot is scheduler latency, and a suspended or CPU-starved process can exceed it. No blocking call runs inside the event loop. |
| Body bytes read | 65,536 | counted on the raw stream; `Accept-Encoding: identity` | Hard. Reading stops at the cap and `truncated` is true. |
| Response header size | httpx/h11 default | the HTTP library's own limit | Tested against the locked h11 0.16.0: a 300,000-byte header value is rejected with `http_error`. The exact threshold is the library default and was not measured. |
| Redirects | 5 | counter | Hard. |
| Ports | 80, 443 | validation | Hard. |
| URL length | 2048 characters | parser | Hard. |

Other properties: `GET` only; fixed `User-Agent: linkguard/<version>`; no cookies, no
`Authorization`, no userinfo sent; no cookie jar carried between hops; `trust_env=False` so proxy
and netrc environment cannot redirect traffic; certificate verification always on; the body is
discarded, never parsed.

#### What the offline tests can and cannot verify

All tests run without Internet access. The socket guard fixture refuses every connection except
to loopback, and only tests marked `loopback` may use that.

- `SafeFetcher` validation, redirect, cookie, and limit logic is tested with a fake resolver and
  `httpx.MockTransport`. A recording transport asserts every request's host is a validated IP
  literal, the `Host` header, and the `sni_hostname` extension.
- `HopClient` is tested against a local TLS server on `127.0.0.1` using a throwaway in-memory
  certificate authority (see Dependencies). The server records the SNI it received and the
  `Host` header. Tests assert: SNI and `Host` are the hostname and not the IP; a certificate
  valid for the hostname is accepted; a certificate valid for a different name is rejected; a
  context with verification disabled is refused; the body cap and the total deadline stop a
  slow-drip server; no cookie is sent.
- The default DNS child is tested on numeric hosts (`127.0.0.1`, `::1`), which `getaddrinfo`
  answers without any network lookup. Hung, noisy, oversized, and failing children are tested
  with an injected child command. Name resolution against real DNS is not tested.
- Not verified by any test: connecting to hosts on the public Internet, behavior against real
  DNS servers, behavior behind real CDNs and proxies, and platforms other than Linux. The README
  says so.

### Reputation provider

Not implemented, by decision. The maintainer chose on 2026-11-25 to skip it for this release.

- No provider is chosen, no API-key environment variable is defined, and `--online`,
  `Policy.online`, and a `reputation` JSON object do not exist.
- linkguard sends no URL to any third party. The only network access it can make is `--follow`,
  which contacts the URL's own server and nothing else.
- Adding one later needs a new maintainer decision (provider, its terms, the variable name, and
  explicit approval to send URLs to it) and a change to this SPEC first.

## Invariants

1. `inspect(s)` returns a `Report` for every `str` `s` and never raises (property-tested with
   Hypothesis on arbitrary text, including surrogates and control characters).
2. Normalization is idempotent: normalizing a `normalized_url` returns the same value.
3. Output text and JSON never contain the word "safe" (case-insensitive, whole word).
4. Every string echoed in text or JSON output is printable ASCII (non-ASCII and control
   characters escaped) and bounded in length.
5. `SafeFetcher` only ever hands `HopClient` an IP literal that passed the allow check, and every
   request seen by the recording transport targets such a literal.
6. The resolver is called exactly once per hop. A resolver whose answers change between calls
   cannot cause a connection to a different address than the one validated.
7. A hop with any blocked address in its answers, or an empty answer, is refused with no
   connection made.
8. Every redirect target is re-parsed and re-validated; a redirect to a blocked address,
   non-HTTP scheme, or disallowed port is refused.
9. With lowered limits and a real clock: a hung DNS child, a hung connect, a trickled TLS
   handshake, and a slow-drip body each end the fetch with `timeout` or `dns_timeout` within the
   lowered limit plus a small fixed slack; the body read never exceeds 65,536 bytes; redirects
   never exceed 5.
10. A DNS child that exceeds its wait is killed and reaped before the lookup returns.
11. No request carries `Cookie`, `Authorization`, `Proxy-Authorization`, or userinfo.
12. With the default `Policy`, no resolver or transport call is made (the fakes fail if called).
13. `HopClient` refuses an `ssl.SSLContext` without `CERT_REQUIRED` and `check_hostname`.
14. Findings order is deterministic and exit codes follow the table above.
15. No CLI flag, `Policy` field, or environment variable affects SSRF validation, and no
    `--online` option exists (CLI help and `Policy` fields asserted).
16. Every report carries `data_version`, and `DATA_VERSION` changes with the list contents.

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
- Suffix data: a host under a listed multi-label suffix, the same shape under an unlisted one
  (the documented wrong answer is asserted, not hidden), a host that is exactly a suffix.
- DNS: answers mixing public and blocked addresses, rebinding on second query, empty answer,
  resolver raising, IPv6-only answer, IPv6 scope IDs in answers; child that hangs, exits nonzero,
  prints garbage, prints non-IP lines, prints more than 4096 bytes, cannot start.
- Fetcher: redirect loop, 6th redirect, redirect to `Location` with userinfo, relative path,
  scheme-relative, `file:`, over-long, non-ASCII; slow-drip body past the deadline; trickled TLS
  handshake; body exactly 65,536 and 65,537 bytes; connect timeout; oversized header block;
  `Set-Cookie` in a response (must not be replayed); certificate for the wrong name.
- Batch: empty file, blank lines only, binary file, a 10,001-line file, a line over 2048
  characters, a file over 1 MiB, missing file, directory instead of file.
- Concurrent use: `inspect` holds no module-level mutable state, so concurrent calls are safe
  (asserted by a threaded test).

## Acceptance criteria

- [ ] `make check` passes (format check, lint, `mypy --strict`, tests, coverage gate at 80 percent
      overall) under Python 3.12.
- [ ] Coverage of the parser and the SSRF address-classification module is at least 90 percent
      (line and branch), enforced by a separate `make` gate.
- [ ] All invariants above have at least one test; heuristics LG-001 to LG-014 each have a
      positive and a near-miss test.
- [ ] Tests are offline: fake DNS, fake transport, a loopback-only socket guard. The only real
      sockets are loopback fixtures in tests marked `loopback`.
- [ ] The CLI exits with 0, 1, 2, 3 as specified, each covered by a test.
- [ ] `check --json` output matches the version "1" golden file and contains `schema_version`.
- [ ] Output never contains the word "safe".
- [ ] README contains the threat model, a fetch-pipeline diagram, real example output captured
      by running the tool, limitations (including the suffix-data limitation and the list of
      what is not verified), and a plain statement that online lookup is not implemented.
      Behavioral claims in the README link to a test; no performance claim is made without a
      reproducible benchmark (none is planned, so none is made).

## Dependencies

Runtime dependencies are added only in the slice that first imports them. Pinned through
`uv.lock`; the version column is filled with the locked version in that slice's commit.

| Name | Used for | Why not in-house | Vetting (performed in the adding slice, recorded in the commit message) |
| ---- | -------- | ---------------- | ----------------------------------------------------------------------- |
| `idna` | IDNA 2008 / UTS #46 host conversion | The standard `idna` codec implements the obsolete IDNA 2003; correct 2008 tables and mapping are large data sets that must not be hand-written. Already a transitive dependency of `httpx`. | Locked 3.20 (uploaded 2026-09-17 per `uv.lock`), license BSD-3-Clause from package metadata. Checked: version, license, upload date. Not checked: advisories (no scanner was run). |
| `httpx` | Async HTTP client for `SafeFetcher` | TLS with a custom SNI name distinct from the connect address, streaming reads, per-operation timeouts and a transport seam for fakes. In-house this is a TLS and HTTP/1.1 client, which is risky security code. | Locked 0.28.1, BSD-3-Clause. Pulls `httpcore` 1.0.9 (BSD-3-Clause), `h11` 0.16.0 (MIT), `anyio` 4.16.0 (MIT), `certifi` 2026.11.20 (MPL-2.0) and `idna`. Behavior of `sni_hostname` (SNI and certificate name) and `trust_env` checked by tests against this version. Not checked: advisories (no scanner was run). linkguard passes its own `ssl.SSLContext` using the system trust store, so `certifi`'s bundle is not used for verification. |
| `typer` | CLI | Argument parsing, help, exit-code plumbing. This one is a convenience: `argparse` could do it in the standard library with no dependencies. Kept because the brief names `typer`. **Actual cost, corrected from an earlier wrong note that said only `click`:** typer 0.29.2 vendors its own click code and pulls 10 more packages: `rich` 15.0.0, `shellingham` 1.5.4, `pydantic` 2.14.4 and the compiled `pydantic-core` 2.50.5, `annotated-types`, `annotated-doc`, `typing-inspection`, `markdown-it-py`, `mdurl` (and `pygments`, already present). Swapping to `argparse` would be a small change if this footprint is unwanted. | typer MIT, rich MIT, shellingham ISC, per package metadata. Not checked: advisories (no scanner was run). |

Development tools: `pytest` (test runner), `pytest-cov` (coverage gate), `hypothesis` 6.170.17
(property tests on arbitrary text; the standard library has no generator), `ruff` (lint and
format), `mypy` (strict typing). All are already in `pyproject.toml`.

Added development dependency, approved by the maintainer in chat: `trustme` 1.2.1 (MIT OR Apache-2.0),
which creates a throwaway certificate authority and server certificates in memory for the loopback TLS
tests. It brings `cryptography` 50.0.2, `cffi` 2.1.1, and `pycparser` 3.12, all dev-only and never
imported by shipped code. The standard library can verify certificates but cannot create them, and
committing a private key as a fixture is rejected (rule 11, and the secret scanner). Advisories were
not checked.

No cryptography is written. TLS and certificate verification are the standard library `ssl`
module through `httpx`, with the system trust store and default hostname checking; hostname
checking uses the original hostname, not the IP.

## Decisions

- Python is pinned to 3.12 as described under "Supported Python".
- The fetcher is async. Wall-clock limits use one `asyncio.timeout`; DNS runs in a killable child
  process; no thread is used for DNS because it could not be stopped.
- Domain splitting uses versioned reference data, not the Public Suffix List, and claims nothing
  beyond that data (see "Reference data").
- `batch` has no JSON output.
- Reference lists (brands, suspicious TLDs, shorteners, suffixes) are proposed small and reviewed
  in the diff of the slice that adds them.
- The online reputation lookup is not part of this release: no provider, no `--online`, no API key.

## Open questions

None at this time.
