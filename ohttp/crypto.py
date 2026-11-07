"""the HPKE seam, swappable and pinned to tested suites (RFC 9180).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "supported_suites",
]


def supported_suites() -> tuple:
    """Pending behaviour defined by RFC 9180 sec. 7.

    Not implemented yet. See the ``crypto.supported_suites()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("supported_suites() is not implemented: RFC 9180 sec. 7")
