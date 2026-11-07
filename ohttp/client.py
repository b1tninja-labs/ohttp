"""encapsulate, send, de-encapsulate (RFC 9458).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Gateway = Any  # placeholder: give it a real type in the milestone that needs it
    HttpRequest = Any  # placeholder: give it a real type in the milestone that needs it
    HttpResponse = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "request",
]


async def request(gateway: Gateway, request: HttpRequest) -> HttpResponse:
    """Pending behaviour defined by RFC 9458 sec. 5.

    Not implemented yet. See the ``client.request()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("request() is not implemented: RFC 9458 sec. 5")
