"""key configurations, identifier, generation and rotation (RFC 9458).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    KeyConfig = Any  # placeholder: give it a real type in the milestone that needs it
    KeyPair = Any  # placeholder: give it a real type in the milestone that needs it
    Suite = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "generate_config",
    "parse_config",
]


def generate_config(suite: Suite, key_id: int) -> KeyPair:
    """Pending behaviour defined by RFC 9458 sec. 3.

    Not implemented yet. See the ``keys.generate_config()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("generate_config() is not implemented: RFC 9458 sec. 3")


def parse_config(raw: bytes) -> KeyConfig:
    """Pending behaviour defined by RFC 9458 sec. 3.1.

    Not implemented yet. See the ``keys.parse_config()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("parse_config() is not implemented: RFC 9458 sec. 3.1")
