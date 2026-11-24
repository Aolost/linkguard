# linkguard

## What it is and why

linkguard inspects a URL and reports suspicious indicators without rendering or executing
page content: tricks in the userinfo, raw or obfuscated IP addresses, unusual ports, look-alike
and punycode hosts, typosquats, brand names used as subdomains, long or deep hostnames,
suspicious top-level domains, and URL shorteners. Each finding has a rule ID, a severity,
evidence, and an explanation, and the findings reduce to one of three verdicts:
`NO_RED_FLAGS`, `SUSPICIOUS`, or `DANGEROUS`.

It never says a URL is safe. The best it can say is "no red flags found", which only means
none of its heuristics fired. It is for people and scripts that triage links and want a
second opinion that does not touch the page.

An optional fetcher (`--follow`) can also follow redirects. It is built so that a hostile URL
or hostile DNS cannot turn it against your internal network (SSRF). It is off by default.

Status: pre-release 0.1.0. The reference lists behind the heuristics are small, unaudited
samples (see [Limitations](#limitations)), and nobody has measured how often the rules are
right or wrong on real URLs.

## Install

Requires [uv](https://docs.astral.sh/uv/). The project is pinned to and tested on Python 3.12.

```bash
git clone https://github.com/aolost/linkguard.git
cd linkguard
uv sync --locked
```

## Usage

```text
linkguard check URL [--follow] [--json]
linkguard batch FILE
```

Exit codes: `0` no red flags, `1` suspicious, `2` dangerous, `3` input refused, fetch refused
or failed, or a usage error. Run them through `uv run --locked linkguard ...`, or
`python -m linkguard ...`.

A clean URL:

<!-- example exit=0: check http://example.test/ -->
```text
$ linkguard check http://example.test/
linkguard 0.1.0 (reference data 1)
Input:    http://example.test/
Checked:  http://example.test/
Verdict:  NO_RED_FLAGS
          No red flags found. This does not mean the URL is trustworthy; linkguard only reports indicators.
```

Several findings at once. The userinfo imitates a destination, the host is a decimal-encoded
IP address (it is `127.0.0.1`), and the port is unusual:

<!-- example exit=2: check 'http://paypal.com@2130706433:8080/login' -->
```text
$ linkguard check 'http://paypal.com@2130706433:8080/login'
linkguard 0.1.0 (reference data 1)
Input:    http://paypal.com@2130706433:8080/login
Checked:  http://127.0.0.1:8080/login
Verdict:  DANGEROUS
Findings:
  [high] LG-002  paypal.com
      The text before the @ looks like a destination.
  [high] LG-004  2130706433
      The IP address is written in a non-standard encoding.
  [medium] LG-001  paypal.com
      Credentials in a URL can disguise the real host.
  [medium] LG-003  127.0.0.1
      The host is a raw IP address instead of a name.
  [low] LG-005  port 8080
      The URL uses a non-default port.
```

A brand used as a subdomain of a domain that does not own it, under a suspicious TLD:

<!-- example exit=2: check http://login.paypal.evil.tk/ -->
```text
$ linkguard check http://login.paypal.evil.tk/
linkguard 0.1.0 (reference data 1)
Input:    http://login.paypal.evil.tk/
Checked:  http://login.paypal.evil.tk/
Verdict:  DANGEROUS
Findings:
  [high] LG-009  paypal (brand paypal)
      A brand name is used as a subdomain of a domain that does not own it.
  [low] LG-012  tk
      The top-level domain is over-represented in abuse.
```

Input the strict parser refuses is reported as refused and exits `3`:

<!-- example exit=3: check ftp://example.test/ -->
```text
$ linkguard check ftp://example.test/
linkguard 0.1.0 (reference data 1)
Input:    ftp://example.test/
Refused:  bad_scheme - only http and https are accepted
Verdict:  none (input refused)
```

`--follow` fetches the URL. A redirect or a resolved address that points at an internal or
local address is refused, and no connection is made. This example uses a cloud metadata
address, which needs no network to refuse:

<!-- example exit=3: check http://169.254.169.254/latest/meta-data/ --follow -->
```text
$ linkguard check http://169.254.169.254/latest/meta-data/ --follow
linkguard 0.1.0 (reference data 1)
Input:    http://169.254.169.254/latest/meta-data/
Checked:  http://169.254.169.254/latest/meta-data/
Verdict:  SUSPICIOUS
Findings:
  [medium] LG-003  169.254.169.254
      The host is a raw IP address instead of a name.
Fetch:    refused (blocked_address)
```

`--json` prints the report as JSON (schema version `1`, pinned by
[`tests/golden/report_v1.json`](tests/golden/report_v1.json)).

`batch` reads one URL per line, never fetches, and exits with the highest code of any entry.
Blank lines are skipped, and there is no comment syntax. With this file:

<!-- file: urls.txt -->
```text
http://example.test/
http://example.test:8080/

http://login.paypal.evil.tk/
ftp://example.test/
```

<!-- example exit=3: batch urls.txt -->
```text
$ linkguard batch urls.txt
     1  NO_RED_FLAGS  http://example.test/
     2  SUSPICIOUS    http://example.test:8080/  LG-005
     4  DANGEROUS     http://login.paypal.evil.tk/  LG-009,LG-012
     5  REFUSED       ftp://example.test/  bad_scheme
4 URLs: 1 NO_RED_FLAGS, 1 SUSPICIOUS, 1 DANGEROUS, 1 REFUSED
```

From Python:

```python
from linkguard import inspect
from linkguard.model import Policy

report = inspect("http://paypal.com@evil.test/")  # no network access
report.verdict, [f.rule_id for f in report.findings]
followed = inspect(
    "http://example.test/", Policy(follow=True)
)  # fetches; see Limitations
```

## How it works

```text
URL string (hostile)
  |
  v
parse_url ......... refuses: control characters, whitespace, backslash, over 2048
  |                characters, schemes other than http/https, empty or invalid port
  v
normalize_host .... percent-decode once, IDNA 2008, legacy IPv4 spellings, IPv6 literals;
  |                refuses what it cannot read unambiguously
  v
heuristics ........ rules LG-001 to LG-014 -> findings -> verdict -> Report
  |                (always produced; no network access up to here)
  |
  |  only with --follow
  v
SafeFetcher, for every hop (first URL and each redirect; at most 6 hops, 10 s in total)
  |
  +-- parse and normalize the URL again (a redirect target is hostile input too)
  +-- port must be 80 or 443
  +-- resolve the name ONCE, in a child process that is killed on timeout
  +-- check EVERY returned address against the blocklist
  |     any blocked or no address -> refuse the hop, no connection is made
  +-- connect to the validated IP only; Host header, TLS SNI and certificate
  |     name are the hostname; certificate verification cannot be turned off
  +-- GET, no cookies or credentials, read at most 64 KB, discard the body
  +-- 3xx with Location -> back to "parse and normalize again" (at most 5 times)
```

Trust boundaries: everything left of the blocklist check (the URL, DNS answers, redirects,
response headers and timing) is attacker-controlled. Text from those sources is escaped to
printable ASCII before it reaches the terminal or JSON.

| Rule | Severity | Looks for |
| ---- | -------- | --------- |
| LG-001 | medium | userinfo (`user@`) present |
| LG-002 | high | userinfo that looks like a destination (`paypal.com@evil.test`) |
| LG-003 | medium | raw IP address as the host |
| LG-004 | high | IP written in a non-standard encoding (decimal, hex, octal, short, mapped IPv6) |
| LG-005 | low | non-default port |
| LG-006 | low | punycode (`xn--`) label |
| LG-007 | high | one label mixing Latin with Cyrillic or Greek letters |
| LG-008 | medium | label one or two edits away from a known brand |
| LG-009 | high | a brand used as a subdomain of a domain that does not own it |
| LG-010 | medium | more than 4 subdomain labels |
| LG-011 | low | hostname longer than 50 characters |
| LG-012 | low | top-level domain on a short abuse-prone list |
| LG-013 | low | URL shortener |
| LG-014 | medium | percent-encoded characters in the host |

Any low or medium finding gives `SUSPICIOUS`; any high finding gives `DANGEROUS`. The full
specification, including edge cases, is in [SPEC.md](SPEC.md).

## Design decisions and tradeoffs

- **Strict parser: refuse instead of interpret.** Parsers disagree about backslashes,
  whitespace, empty ports and odd hosts, and those disagreements are how URL tricks work.
  linkguard refuses them. Cost: some unusual but valid URLs (a host with an underscore, an
  empty port) are refused rather than inspected.
- **Explicit address blocklist, not `ipaddress.is_global`.** The standard library's answers
  differ between Python patch releases. Cost: the table must be maintained by hand.
- **Name resolution in a killable child process.** `socket.getaddrinfo` cannot be cancelled and
  a thread running it keeps going after a timeout. A child process can be killed. Cost: a
  process start per lookup.
- **One `asyncio` deadline for the whole fetch.** It cancels at every await point. It is not
  a real-time guarantee (see Limitations).
- **Versioned reference data.** The brand, TLD, shortener and suffix lists carry a
  `DATA_VERSION` that appears in every report, and a test ties the version to the contents.
- **`typer` for the CLI.** The project brief names it. It brings ten more packages,
  including `pydantic`; the standard library's `argparse` would need none. Swapping is a
  small change.
- **No online reputation lookup, on purpose.** It is not implemented in this release, and no URL
  is sent to any third party. See below.

## Threat model

Summary; the full version is in [SPEC.md](SPEC.md).

- **Protected:** your internal network, local services, and cloud metadata endpoints (from the
  fetcher); your time, memory and processes; and the truthfulness of the report.
- **Attacker:** controls the input URL, DNS answers (including answers that change between
  queries), redirects, and response headers, body size and timing. Wants the tool to reach
  a private address, to hang or exhaust resources, or to report a bad URL as clean.
- **Out of scope:** malware in downloaded content, browser exploits, page-content analysis, an
  attacker who already controls your machine or its environment, whole-script look-alike
  domains, and work a system resolver daemon has already started.

## Testing

```bash
make check    # format check, lint, mypy --strict, tests with coverage, 90% gate on
              # the parser, host and address-blocklist modules
```

The tests are written to run offline. A fixture makes any `socket.connect` to a non-loopback
address fail the test, and tests marked `loopback` may connect to `127.0.0.0/8` and `::1`
only. The guard covers connections made from the test process. It does not cover other
processes (the resolver child is only ever run on numeric hosts in tests) or UDP sends that
never call `connect`. The fetcher is tested with a fake resolver and a fake network, and the
HTTP/TLS layer against local servers with a throwaway certificate authority.

Each behavior claimed in this README, and the test that checks it:

| Claim | Test |
| ----- | ---- |
| Input over 2048 characters is refused, at the exact boundary | `tests/test_parse.py::test_length_limit_boundary` |
| Control characters, whitespace and backslashes are refused | `tests/test_parse.py::test_control_whitespace_surrogate_and_backslash_are_refused` |
| Legacy IPv4 spellings normalize to the real address | `tests/test_ip_hosts.py::test_legacy_ipv4_encodings_resolve_to_loopback_and_are_not_canonical` |
| Percent-encoding is decoded once; double encoding is refused | `tests/test_host.py::test_remaining_percent_after_decoding_is_refused` |
| `inspect` never raises, for any text | `tests/test_api.py::test_inspect_never_raises_for_any_text` |
| Normalizing a normalized URL changes nothing | `tests/test_api.py::test_normalized_url_is_idempotent` |
| Mixed-script labels are flagged | `tests/test_heuristics_names.py::test_lg007_mixed_script_label_is_high` |
| Brand-as-subdomain is flagged, and the brand's own domain is not | `tests/test_reference_rules.py::test_lg009_near_misses` |
| A userinfo password never appears in a finding | `tests/test_heuristics.py::test_userinfo_password_never_appears_in_evidence` |
| Reference-data version is tied to the list contents | `tests/test_data.py::test_data_version_is_pinned_to_list_contents` |
| JSON output matches the independently written golden file | `tests/test_api.py::test_report_matches_the_golden_file_for_an_inspected_url` |
| Output never says "safe" | `tests/test_cli.py::test_output_never_uses_the_word_safe` |
| Output is printable ASCII even for hostile input | `tests/test_cli.py::test_output_is_printable_ascii_even_for_hostile_input` |
| A server-controlled `Content-Type` is escaped | `tests/test_cli.py::test_server_controlled_content_type_is_escaped` |
| Exit codes 0, 1, 2 and 3 | `tests/test_cli.py::test_exit_codes_follow_the_verdict` |
| Usage errors exit 3, not 2 | `tests/test_cli.py::test_usage_errors_exit_three_with_a_message_on_stderr` |
| Blocked address classes and their boundaries | `tests/test_ssrf.py::test_blocked_addresses_and_their_reasons` |
| Public addresses next to blocked ranges are allowed | `tests/test_ssrf.py::test_public_addresses_are_allowed` |
| One blocked address among public ones refuses the hop with no connection | `tests/test_fetch.py::test_one_blocked_answer_among_public_ones_means_no_connection_at_all` |
| The resolver is not consulted a second time | `tests/test_resolve.py::test_rebinding_second_answer_is_never_consulted` |
| Every hop is re-resolved and re-validated | `tests/test_fetch.py::test_rebinding_between_hops_is_caught_because_every_hop_is_revalidated` |
| A redirect to a blocked IP literal is refused without connecting | `tests/test_fetch.py::test_redirect_to_a_blocked_ip_literal_is_refused_without_connecting` |
| A redirect to a name that resolves to a blocked address is refused | `tests/test_fetch.py::test_redirect_to_a_name_that_resolves_to_a_blocked_address_is_refused` |
| At most 5 redirects are followed | `tests/test_fetch.py::test_up_to_five_redirects_are_followed_and_the_sixth_is_refused` |
| Only ports 80 and 443 are fetched | `tests/test_fetch.py::test_only_ports_80_and_443_are_allowed` |
| No cookies or credentials are sent | `tests/test_fetch.py::test_set_cookie_is_never_replayed_and_no_credentials_are_sent` |
| Proxy environment variables are ignored | `tests/test_hop.py::test_environment_proxies_are_ignored` |
| The body read is capped at 64 KB | `tests/test_hop.py::test_body_is_capped_at_the_limit` |
| SNI and `Host` are the hostname, not the IP | `tests/test_hop_tls.py::test_sni_and_host_header_are_the_hostname_not_the_ip` |
| A certificate for another name is rejected | `tests/test_hop_tls.py::test_certificate_for_another_name_is_rejected` |
| TLS verification cannot be weakened | `tests/test_hop.py::test_weakened_tls_contexts_are_refused` |
| A hung connection or resolver hits the total deadline | `tests/test_fetch.py::test_a_hung_connection_hits_the_total_deadline` |
| A slow-drip body is stopped by the deadline | `tests/test_hop_tls.py::test_a_slow_drip_body_is_stopped_by_the_callers_deadline` |
| The deadline can be lowered but never raised | `tests/test_fetch.py::test_the_total_limit_can_be_lowered_but_never_raised` |
| A hung resolver child is killed and reaped | `tests/test_resolve.py::test_hung_child_times_out_and_is_killed_and_reaped` |
| A misbehaving resolver child fails closed | `tests/test_resolve.py::test_misbehaving_child_fails_closed` |
| Nothing is fetched unless `--follow` is given | `tests/test_cli.py::test_without_follow_no_fetcher_is_ever_built` |
| `batch` never fetches | `tests/test_batch.py::test_batch_never_fetches` |
| No `Policy` field can relax the address checks | `tests/test_model.py::test_policy_has_no_field_that_could_relax_the_ssrf_checks` |
| The help offers no option that relaxes the checks | `tests/test_cli.py::test_help_succeeds_and_offers_only_the_documented_options` |
| `batch` file limits hold at their boundaries | `tests/test_batch.py::test_file_size_limit_boundary` |
| Tests cannot leave loopback | `tests/test_socket_guard.py::test_loopback_marked_tests_still_cannot_leave_loopback` |
| README examples are real output | `tests/test_readme.py::test_every_readme_example_matches_the_real_output_and_exit_code` |

Passing tests do not establish that a security tool is secure. They show that the behaviors
above hold for the inputs the tests try, and the property tests (Hypothesis) widen that to
many generated inputs. They say nothing about inputs nobody thought of.

## Limitations

- **The reference lists are small, unaudited samples.** The brand, suspicious-TLD, shortener and
  multi-label-suffix lists were compiled on 2026-11-25 from
  general knowledge. They are not derived from the Public Suffix List or any threat feed, and
  nobody has audited them or measured false positives and false negatives. They carry
  `DATA_VERSION = "1"`.
- **No Public Suffix List.** Splitting a host into subdomains and registrable name uses only
  the 18 multi-label suffixes in the data, so it is correct relative to that list and nothing
  more. For a host under an unlisted suffix (for example an unlisted `.co.xx`), one extra
  label is counted as the registrable name: LG-010 can fire wrongly and LG-008 and LG-009 can
  miss. Hosting platforms that give each customer a subdomain are treated as ordinary
  domains. linkguard makes no claim of general registrable-domain accuracy.
- **Look-alike detection is partial.** Script detection uses the first word of each character's
  Unicode name, because the standard library has no script property. A label written
  entirely in Cyrillic or Greek letters that imitate a Latin brand is not detected.
  Typosquat and brand checks cover only brands of at least five characters, and LG-009
  matches a brand only as a whole hyphen-separated word (`paypal-login` yes, `paypalsecure` no).
- **A clean result is not a safety verdict.** Page content is never analyzed, and the body
  fetched with `--follow` is discarded unread.
- **`--follow` contacts the URL's server**, which sees your IP address and the request. It sends
  plain `GET`s and follows `http` to `https` and back. Use it only for URLs you are willing to contact.
- **The time limits are best effort, not real-time.** The total of 10 seconds is enforced by
  cancelling at await points; a suspended or starved process can overrun it. The DNS child
  process is killed on timeout, which bounds linkguard's own wait but not work a system
  resolver daemon already started.
- **The strict parser refuses some valid URLs**, for example hosts with underscores, empty
  ports, and anything containing a backslash or whitespace.
- **Dependencies are not audited.** `typer` brings `pydantic` and `rich`; `httpx` brings
  `httpcore`, `h11`, `anyio` and `certifi`. No advisory scanner has been run on any of them.
- **No performance claims are made.** No benchmark exists.

## What is not verified

- Behavior against the public Internet, real DNS servers (the resolver child is tested only on
  numeric hosts such as `127.0.0.1` and `::1`), CDNs, proxies, and real-world redirect chains.
  The tests deliberately never touch the Internet.
- Anything on macOS or Windows. Development and all test runs were on Linux with Python 3.12.16.
  CI also targets macOS, and it has not been run.
- How often the heuristics are right or wrong on real URLs.
- The response-header size limit is the HTTP library's default. A test confirms that a
  300,000-byte header is rejected with h11 0.16.0; the exact threshold was not measured.
- The `javascript:` and similar malformed `Location` cases are rejected by `httpx` before
  linkguard sees them; a test pins this to the locked `httpx` 0.28.1.

## Online reputation lookup

Not implemented in this release, by decision. linkguard has no `--online` option and no
API-key setting, and it sends no URL to any third party. The only network access it can make
is `--follow`, which contacts the URL's own server, as described under Limitations.

## License

MIT. See [LICENSE](LICENSE).
