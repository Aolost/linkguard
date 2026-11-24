"""Installed package version, kept apart so any module can import it without cycles."""

from importlib.metadata import version as _distribution_version


def version() -> str:
    """Return the installed package version."""
    return _distribution_version("linkguard")
