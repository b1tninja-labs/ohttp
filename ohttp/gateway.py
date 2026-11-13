"""The Oblivious Gateway Resource as pure functions, and the relay stub (RFC 9458 sec. 5, sec. 6).

:func:`process_request` takes the HTTP request a relay forwarded (its content type and body),
the gateway's :class:`~ohttp.keys.KeyRing` and a ``forward`` callable that stands in for the
Target Resource, and returns the HTTP response the gateway sends back. No sockets are opened.

Where an error is sent, and how, follows RFC 9458 sec. 5.2, each point pinned by a test in
``tests/test_gateway.py``:

* Errors found before protection is removed are sent unprotected with a 4xx status: a content
  type other than ``message/ohttp-req`` is 415, and anything that cannot be decapsulated (an
  unknown or replaced key identifier, a KEM or suite the key does not offer, a ciphertext that
  does not authenticate) is 422 (sec. 6.4). An unknown key identifier also carries the
  ``ohttp-key`` problem type of sec. 5.3, which the RFC says a gateway MAY send; the body is
  ``application/problem+json``.
* Errors found after protection is removed are encapsulated and sent in a 200 response of
  media type ``message/ohttp-res``: binary HTTP that does not decode (400), a replayed request
  (400), a ``Date`` outside the window (400 with the ``date`` problem type, sec. 6.5.2, and a
  ``Date`` header so the client can correct its clock), an ``Expect: 100-continue`` (400, sec.
  5.1), a Target that times out (504, sec. 5) or fails (500). RFC 9458 gives 400 and 504 as its
  examples; 500 for any other failure of the Target is this module's choice.
* A success is a 200 with ``message/ohttp-res`` and nothing else but ``Content-Type``.

Replay (sec. 6.5.1): :class:`ReplayCache` remembers ``enc`` for a window and refuses a repeat.
The window is not secret and is not randomised here (sec. 6.5.1 para 5 forbids treating it as
secret). ``process_request`` consults it only when given one.

Not here: the relay (``relay`` stays a loud stub; the relay never decrypts, sec. 6.2), TLS, and
any allowlist of Target Resources, which sec. 6.3 asks of a deployment and this library cannot
know.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import format_datetime, parsedate_to_datetime
from typing import TYPE_CHECKING

from .bhttp import Request, Response, decode_request, encode_response
from .errors import BhttpError, MessageError, UnknownKeyError
from .keys import KeyPair
from .message import GatewayContext, decapsulate, encapsulate_response

if TYPE_CHECKING:
    from typing import Any

    Encapsulated = Any  # placeholder for the relay stub

__all__ = [
    "KEYS_MEDIA_TYPE",
    "PROBLEM_DATE",
    "PROBLEM_OHTTP_KEY",
    "REQUEST_MEDIA_TYPE",
    "RESPONSE_MEDIA_TYPE",
    "GatewayResponse",
    "ReplayCache",
    "process_request",
    "relay",
]

KEYS_MEDIA_TYPE = "application/ohttp-keys"  # RFC 9458 sec. 9.1
REQUEST_MEDIA_TYPE = "message/ohttp-req"  # sec. 9.2
RESPONSE_MEDIA_TYPE = "message/ohttp-res"  # sec. 9.3
PROBLEM_OHTTP_KEY = "https://iana.org/assignments/http-problem-types#ohttp-key"  # sec. 5.3
PROBLEM_DATE = "https://iana.org/assignments/http-problem-types#date"  # sec. 6.5.2
_PROBLEM_JSON = "application/problem+json"


@dataclass(frozen=True)
class GatewayResponse:
    """The HTTP response the gateway sends to the relay."""

    status: int
    content_type: str
    body: bytes
    headers: tuple[tuple[str, str], ...] = ()


class ReplayCache:
    """Remembers the ``enc`` of requests already answered for ``window`` seconds (sec. 6.5.1)."""

    def __init__(self, window: float = 300.0) -> None:
        if window <= 0:
            raise ValueError("the window must be positive")
        self.window = window
        self._seen: dict[bytes, float] = {}

    def check_and_record(self, enc: bytes, now: float) -> bool:
        """True when ``enc`` is new (and now recorded); False for a replay inside the window."""
        self._seen = {e: t for e, t in self._seen.items() if now - t < self.window}
        if enc in self._seen:
            return False
        self._seen[enc] = now
        return True


def _matches_media_type(value: str | None, expected: str) -> bool:
    # sec. 9.2 and sec. 9.3 define no parameters, so the type must be exactly this one,
    # compared without case (RFC 9110 sec. 8.3.1).
    return value is not None and value.strip().lower() == expected


def _problem(problem_type: str, title: str) -> bytes:
    return json.dumps({"type": problem_type, "title": title}).encode("utf-8")


def _unprotected(status: int, title: str, problem_type: str | None = None) -> GatewayResponse:
    if problem_type is None:
        return GatewayResponse(status, "text/plain", title.encode("utf-8"))
    return GatewayResponse(status, _PROBLEM_JSON, _problem(problem_type, title))


def _protected(context: GatewayContext, response: Response) -> GatewayResponse:
    body = encapsulate_response(context, encode_response(response))
    return GatewayResponse(200, RESPONSE_MEDIA_TYPE, body)


def _header(request: Request, name: bytes) -> bytes | None:
    for key, value in request.headers:
        if key == name:
            return value
    return None


def _date_outside(request: Request, now: float, window: float) -> bool:
    raw = _header(request, b"date")
    if raw is None:
        return (
            False  # a request without Date is not refused here: sec. 6.5.1 only says SHOULD include
        )
    try:
        stamp = parsedate_to_datetime(raw.decode("ascii"))
    except (ValueError, TypeError, UnicodeDecodeError):
        return True
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return abs(stamp.timestamp() - now) > window


def process_request(
    content_type: str | None,
    body: bytes,
    keys: Sequence[KeyPair],
    forward: Callable[[Request], Response],
    *,
    now: float,
    replay: ReplayCache | None = None,
    date_window: float | None = None,
) -> GatewayResponse:
    """Handle one forwarded Encapsulated Request (RFC 9458 sec. 4.3, sec. 4.4, sec. 5, sec. 6)."""
    if not _matches_media_type(content_type, REQUEST_MEDIA_TYPE):
        return _unprotected(415, f"content type must be {REQUEST_MEDIA_TYPE}")
    try:
        opened = decapsulate(body, keys)
    except MessageError as error:
        unknown = isinstance(error, UnknownKeyError)
        return _unprotected(
            422,
            "key identifier unknown" if unknown else "request could not be decapsulated",
            PROBLEM_OHTTP_KEY if unknown else None,
        )
    context = opened.context
    if replay is not None and not replay.check_and_record(context.enc, now):
        return _protected(context, Response(400, ((b"content-type", b"text/plain"),), b"replay"))
    try:
        request = decode_request(opened.request)
    except BhttpError:
        return _protected(context, Response(400))
    if date_window is not None and _date_outside(request, now, date_window):
        stamp = format_datetime(datetime.fromtimestamp(now, UTC), usegmt=True).encode("ascii")
        problem = _problem(PROBLEM_DATE, "date field in request outside of acceptable range")
        headers = ((b"date", stamp), (b"content-type", _PROBLEM_JSON.encode("ascii")))
        return _protected(context, Response(400, headers, problem))
    expect = _header(request, b"expect")
    if expect is not None and expect.strip().lower() == b"100-continue":
        return _protected(context, Response(400))  # sec. 5.1: MUST generate an error
    try:
        response = forward(request)
    except TimeoutError:
        return _protected(context, Response(504))
    except Exception:  # the Target failed; the gateway still owes the client an encapsulated answer
        return _protected(context, Response(500))
    return _protected(context, response)


async def relay(body: Encapsulated, responder: str) -> Encapsulated:
    """Pending behaviour defined by RFC 9458.

    Not implemented yet. See the ``gateway.relay()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("relay() is not implemented: RFC 9458")
