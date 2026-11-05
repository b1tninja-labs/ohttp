"""the relay: forward without reading, and what that forbids (RFC 9458).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Encapsulated = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "relay",
]


async def relay(body: Encapsulated, responder: str) -> Encapsulated:
    """Pending behaviour defined by RFC 9458.

    Not implemented yet. See the ``gateway.relay()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("relay() is not implemented: RFC 9458")
