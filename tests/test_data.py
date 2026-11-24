import hashlib
import json

from linkguard import data

# Bump DATA_VERSION and this digest together whenever a list changes.
EXPECTED_DIGEST = "49c6353c6a1fdb28dae60ed085af82f5964ab02708ed3d1d3630e993b994cfa2"


def digest() -> str:
    canonical = json.dumps(
        {
            "suffixes": sorted(data.MULTI_LABEL_SUFFIXES),
            "brands": {k: sorted(v) for k, v in sorted(data.BRANDS.items())},
            "tlds": sorted(data.SUSPICIOUS_TLDS),
            "shorteners": sorted(data.SHORTENERS),
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def test_data_version_is_pinned_to_list_contents() -> None:
    assert (data.DATA_VERSION, digest()) == ("1", EXPECTED_DIGEST)


def test_entries_are_lowercase_ascii() -> None:
    entries = [
        *data.MULTI_LABEL_SUFFIXES,
        *data.SUSPICIOUS_TLDS,
        *data.SHORTENERS,
        *data.BRANDS,
        *(domain for domains in data.BRANDS.values() for domain in domains),
    ]
    assert all(entry.isascii() and entry == entry.lower() for entry in entries)


def test_suffixes_have_several_labels_and_tlds_have_one() -> None:
    assert all("." in suffix for suffix in data.MULTI_LABEL_SUFFIXES)
    assert all("." not in tld for tld in data.SUSPICIOUS_TLDS)


def test_brands_are_long_enough_and_own_a_domain_named_after_them() -> None:
    for label, domains in data.BRANDS.items():
        assert len(label) >= 5
        assert any(domain.split(".")[0] == label for domain in domains)
