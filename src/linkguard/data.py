"""Reference data for heuristics.

Provenance: compiled on 2026-11-25 from general
knowledge. It is NOT derived from the Public Suffix List, a threat-intelligence feed,
or any other authoritative source, and nobody has audited it for completeness or for
false positives. Treat every list as a small heuristic sample.

Any change to a list must change DATA_VERSION; tests/test_data.py pins the two together.
"""

DATA_VERSION = "1"

# Multi-label public suffixes, used only by `split_host`. This is not the Public
# Suffix List: a host under an unlisted multi-label suffix is split wrongly.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "ac.uk",
        "co.in",
        "co.jp",
        "co.nz",
        "co.uk",
        "co.za",
        "com.au",
        "com.br",
        "com.cn",
        "com.mx",
        "com.sg",
        "com.tr",
        "gov.uk",
        "ne.jp",
        "net.au",
        "or.jp",
        "org.au",
        "org.uk",
    }
)

# Brand label -> domains that legitimately own it. Labels shorter than 5 characters
# are excluded because they sit within one edit of too many ordinary words.
BRANDS: dict[str, tuple[str, ...]] = {
    "adobe": ("adobe.com",),
    "amazon": ("amazon.com",),
    "apple": ("apple.com", "icloud.com"),
    "bankofamerica": ("bankofamerica.com",),
    "chase": ("chase.com",),
    "docusign": ("docusign.com",),
    "dropbox": ("dropbox.com",),
    "facebook": ("facebook.com",),
    "github": ("github.com",),
    "google": ("google.com",),
    "instagram": ("instagram.com",),
    "linkedin": ("linkedin.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "netflix": ("netflix.com",),
    "paypal": ("paypal.com",),
    "wellsfargo": ("wellsfargo.com",),
    "whatsapp": ("whatsapp.com",),
}

# Top-level domains that are cheap or free to register and so are over-represented in
# abuse. A TLD being listed says nothing about any individual site.
SUSPICIOUS_TLDS = frozenset(
    {
        "buzz",
        "cf",
        "click",
        "cyou",
        "ga",
        "gq",
        "icu",
        "ml",
        "mov",
        "rest",
        "tk",
        "top",
        "work",
        "xyz",
        "zip",
    }
)

# Domains of public URL shorteners.
SHORTENERS = frozenset(
    {
        "bit.ly",
        "buff.ly",
        "cutt.ly",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "rb.gy",
        "rebrand.ly",
        "shorturl.at",
        "t.co",
        "tiny.cc",
        "tinyurl.com",
    }
)
