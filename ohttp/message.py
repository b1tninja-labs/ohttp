"""encapsulated request and response formats (RFC 9458).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Decapsulated = Any  # placeholder: give it a real type in the milestone that needs it
    Encapsulated = Any  # placeholder: give it a real type in the milestone that needs it
    KeyConfig = Any  # placeholder: give it a real type in the milestone that needs it
    ResponderKeys = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decapsulate",
    "encapsulate",
]


def encapsulate(request: bytes, config: KeyConfig, aad: bytes) -> Encapsulated:
    """Pending behaviour defined by RFC 9458 sec. 4.

    Not implemented yet. See the ``message.encapsulate()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encapsulate() is not implemented: RFC 9458 sec. 4")


def decapsulate(body: Encapsulated, keys: ResponderKeys) -> Decapsulated:
    """Pending behaviour defined by RFC 9458 sec. 4.

    Not implemented yet. See the ``message.decapsulate()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decapsulate() is not implemented: RFC 9458 sec. 4")
