import re

from linkguard import version


def test_version_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", version())


def test_version_is_read_from_package_metadata_only_once() -> None:
    # inspect() calls version() for every report; a batch makes up to 10,000 of them.
    version.cache_clear()
    first = version()
    assert version() == first
    assert version.cache_info().hits >= 1
