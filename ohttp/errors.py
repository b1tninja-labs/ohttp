"""The exceptions ohttp raises for hostile or malformed input.

Every one derives from ``ValueError`` so a caller that only wants "this was not acceptable" can
catch one type, and none of them is ever a bare ``IndexError`` leaking out of a slice.
"""

from __future__ import annotations

__all__ = [
    "BhttpError",
    "KeyConfigError",
    "MessageError",
    "OhttpError",
    "UnknownKeyError",
]


class OhttpError(ValueError):
    """Base class of every error this package raises on input it refuses."""


class KeyConfigError(OhttpError):
    """A key configuration or a collection of them is incorrectly encoded (RFC 9458 sec. 3)."""


class BhttpError(OhttpError):
    """A binary HTTP message is invalid and must not be processed further (RFC 9292 sec. 4)."""


class MessageError(OhttpError):
    """An encapsulated request or response could not be built or opened (RFC 9458 sec. 4)."""


class UnknownKeyError(MessageError):
    """No key matches the request's key identifier (RFC 9458 sec. 6.4: unknown or replaced)."""
