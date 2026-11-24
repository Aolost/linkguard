"""linkguard."""

from importlib.metadata import version as _distribution_version


def version() -> str:
    """Return the installed package version."""
    return _distribution_version("linkguard")
