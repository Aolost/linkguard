import re

from linkguard import version


def test_version_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", version())
