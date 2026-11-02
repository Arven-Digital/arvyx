from __future__ import annotations

import re


# One spelling per version, enforced in one place.
#
# The release workflow used to bind the tag to `f"v{version}"` while a later step
# required `^v\d+\.\d+\.\d+$`, so no tag could carry a PEP 440 prerelease version
# (`0.1.0a0`) through the workflow. Both steps now call this module, and the
# contract test asserts that they do.
_PEP440_VERSION = re.compile(
    r"^(?P<release>\d+\.\d+\.\d+)(?:(?P<label>a|b|rc)(?P<number>\d+))?$"
)
_PRE_LABELS = {"a": "alpha", "b": "beta", "rc": "rc"}
_RELEASE_TAG = re.compile(
    r"^v(?P<release>\d+\.\d+\.\d+)(?:-(?P<label>alpha|beta|rc)\.(?P<number>\d+))?$"
)


class ReleaseTagError(ValueError):
    """A version or tag that does not follow the canonical release mapping."""


def canonical_release_tag(version: str) -> str:
    """Return the one canonical tag for a package version.

    ``0.1.0``    -> ``v0.1.0``
    ``0.1.0a0``  -> ``v0.1.0-alpha.0``
    ``1.2.3rc2`` -> ``v1.2.3-rc.2``
    """
    match = _PEP440_VERSION.fullmatch(version.strip())
    if match is None:
        raise ReleaseTagError(
            f"package version must be PEP 440 release or prerelease form, not {version!r}"
        )
    release = match.group("release")
    label = match.group("label")
    if label is None:
        return f"v{release}"
    return f"v{release}-{_PRE_LABELS[label]}.{match.group('number')}"


def is_release_tag(tag: str) -> bool:
    """True for a canonical release or prerelease tag."""
    return _RELEASE_TAG.fullmatch(tag.strip()) is not None


def release_order(tag: str) -> tuple[int, int, int] | None:
    """The ordering triple of a canonical tag, ignoring its prerelease label.

    Returns ``None`` for anything that is not a canonical tag, so a caller can
    fail closed instead of comparing a malformed tag.
    """
    match = _RELEASE_TAG.fullmatch(tag.strip())
    if match is None:
        return None
    major, minor, patch = match.group("release").split(".")
    return (int(major), int(minor), int(patch))


def is_prerelease_tag(tag: str) -> bool:
    match = _RELEASE_TAG.fullmatch(tag.strip())
    if match is None:
        raise ReleaseTagError(f"not a canonical release tag: {tag!r}")
    return match.group("label") is not None
