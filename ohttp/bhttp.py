"""Binary HTTP, the known-length form (RFC 9292), which is the payload RFC 9458 encapsulates.

Indeterminate-length messages (framing indicators 2 and 3, RFC 9292 sec. 3.2) are recognised and
refused with ``NotImplementedError``; every other malformed input raises ``BhttpError``.
Decoding honours truncation and zero padding (RFC 9292 sec. 3.8) and applies the field validity
rules RFC 9292 sec. 3.6 takes from RFC 9113 sec. 8.2.1, including the lowercase name rule that
erratum 8559 (held for document update) says the text intends.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._varint import decode_varint, encode_varint
from .errors import BhttpError

__all__ = [
    "Request",
    "Response",
    "decode_request",
    "decode_response",
    "encode_request",
    "encode_response",
]

Fields = tuple[tuple[bytes, bytes], ...]

_FRAMING_REQUEST = 0
_FRAMING_RESPONSE = 1
_FORBIDDEN_PSEUDO = frozenset({b":method", b":scheme", b":authority", b":path", b":status"})


@dataclass(frozen=True)
class Request:
    """A binary HTTP request: control data, headers, content, trailers (RFC 9292 sec. 3.4)."""

    method: bytes
    scheme: bytes
    authority: bytes
    path: bytes
    headers: Fields = ()
    content: bytes = b""
    trailers: Fields = ()


@dataclass(frozen=True)
class Response:
    """A binary HTTP response; ``informational`` holds (status, headers) pairs (sec. 3.5.1)."""

    status: int
    headers: Fields = ()
    content: bytes = b""
    trailers: Fields = ()
    informational: tuple[tuple[int, Fields], ...] = ()


def _lv(data: bytes) -> bytes:
    return encode_varint(len(data)) + data


def _encode_fields(fields: Fields) -> bytes:
    body = b"".join(_lv(name) + _lv(value) for name, value in fields)
    return encode_varint(len(body)) + body


def _tail(headers: Fields, content: bytes, trailers: Fields, pad: int, truncate: bool) -> bytes:
    """Header section, content, trailer section and zero padding (RFC 9292 sec. 3.8)."""
    parts = [(bool(headers), _encode_fields(headers))]
    parts += [(bool(content), _lv(content)), (bool(trailers), _encode_fields(trailers))]
    if truncate:
        # Every empty part at the end may go, back to the first part with something in it.
        while parts and not parts[-1][0]:
            parts.pop()
    out = b"".join(encoded for _, encoded in parts)
    return out + bytes(max(0, pad - len(out)))


def encode_request(request: Request, *, pad_to: int = 0, truncate: bool = False) -> bytes:
    """Encode ``request`` as a known-length message (RFC 9292 sec. 3.1, sec. 3.4).

    ``truncate`` omits every empty part at the end: trailers, then content, then headers
    (sec. 3.8; RFC 9458 Appendix A omits all three). ``pad_to``
    appends zero bytes until the whole message is at least that long.
    """
    head = (
        encode_varint(_FRAMING_REQUEST)
        + _lv(request.method)
        + _lv(request.scheme)
        + _lv(request.authority)
        + _lv(request.path)
    )
    body = _tail(request.headers, request.content, request.trailers, pad_to - len(head), truncate)
    return head + body


def encode_response(response: Response, *, pad_to: int = 0, truncate: bool = False) -> bytes:
    """Encode ``response`` as a known-length message (RFC 9292 sec. 3.1, sec. 3.5)."""
    if not 200 <= response.status <= 599:
        raise BhttpError("final status code must be 200..599 (RFC 9292 sec. 3.5)")
    head = encode_varint(_FRAMING_RESPONSE)
    for status, headers in response.informational:
        if not 100 <= status <= 199:
            raise BhttpError("informational status code must be 100..199 (RFC 9292 sec. 3.5.1)")
        head += encode_varint(status) + _encode_fields(headers)
    head += encode_varint(response.status)
    body = _tail(
        response.headers, response.content, response.trailers, pad_to - len(head), truncate
    )
    return head + body


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = bytes(data)
        self.at = 0

    def done(self) -> bool:
        return self.at >= len(self.data)

    def varint(self) -> int:
        try:
            value, self.at = decode_varint(self.data, self.at)
        except ValueError as error:
            raise BhttpError(str(error)) from None
        return value

    def take(self, length: int) -> bytes:
        # Compare against what is left before slicing: a declared 2**62 length must fail here
        # rather than allocate or silently clip.
        if length > len(self.data) - self.at:
            raise BhttpError("length exceeds the message")
        chunk = self.data[self.at : self.at + length]
        self.at += length
        return chunk

    def lv(self) -> bytes:
        return self.take(self.varint())


def _valid_name(name: bytes) -> bool:
    body = name[1:] if name[:1] == b":" else name
    # RFC 9113 sec. 8.2.1: no 0x00-0x20, 0x41-0x5a, 0x7f-0xff, and no colon inside the name.
    return bool(body) and not any(
        b <= 0x20 or 0x41 <= b <= 0x5A or b >= 0x7F or b == 0x3A for b in body
    )


def _valid_value(value: bytes) -> bool:
    if any(b in (0x00, 0x0A, 0x0D) for b in value):
        return False
    return not (value and (value[0] in (0x20, 0x09) or value[-1] in (0x20, 0x09)))


def _read_fields(reader: _Reader, *, trailer: bool) -> Fields:
    if reader.done():
        return ()  # truncated: equivalent to a zero length (RFC 9292 sec. 3.8)
    section = _Reader(reader.take(reader.varint()))
    fields: list[tuple[bytes, bytes]] = []
    seen_regular = False
    while not section.done():
        name, value = section.lv(), section.lv()
        if not _valid_name(name) or not _valid_value(value):
            raise BhttpError("field line is invalid (RFC 9292 sec. 3.6)")
        if name[:1] == b":":
            if trailer or name in _FORBIDDEN_PSEUDO or seen_regular:
                raise BhttpError("pseudo-field not permitted here (RFC 9292 sec. 3.6)")
        else:
            seen_regular = True
        fields.append((name, value))
    return tuple(fields)


def _read_rest(reader: _Reader) -> tuple[Fields, bytes, Fields]:
    headers = _read_fields(reader, trailer=False)
    content = b"" if reader.done() else reader.lv()
    trailers = _read_fields(reader, trailer=True)
    if any(reader.data[reader.at :]):
        raise BhttpError("non-zero padding (RFC 9292 sec. 3.8)")
    return headers, content, trailers


def _framing(reader: _Reader, expected: int) -> None:
    indicator = reader.varint()
    if indicator in (2, 3):
        raise NotImplementedError("indeterminate-length Binary HTTP: RFC 9292 sec. 3.2")
    if indicator != expected:
        raise BhttpError(f"framing indicator {indicator} is not {expected} (RFC 9292 sec. 3.3)")


def decode_request(data: bytes) -> Request:
    """Decode a known-length request (RFC 9292 sec. 3.1), raising ``BhttpError`` if invalid."""
    reader = _Reader(data)
    _framing(reader, _FRAMING_REQUEST)
    method, scheme, authority, path = reader.lv(), reader.lv(), reader.lv(), reader.lv()
    headers, content, trailers = _read_rest(reader)
    return Request(method, scheme, authority, path, headers, content, trailers)


def decode_response(data: bytes) -> Response:
    """Decode a known-length response with its informational responses (RFC 9292 sec. 3.5)."""
    reader = _Reader(data)
    _framing(reader, _FRAMING_RESPONSE)
    informational: list[tuple[int, Fields]] = []
    while True:
        status = reader.varint()
        if 200 <= status <= 599:
            break
        if not 100 <= status <= 199:
            raise BhttpError("status code outside 100..599 (RFC 9292 sec. 3.5)")
        informational.append((status, _read_fields(reader, trailer=False)))
    headers, content, trailers = _read_rest(reader)
    return Response(status, headers, content, trailers, tuple(informational))
