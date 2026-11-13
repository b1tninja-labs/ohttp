"""The QUIC variable-length integer (RFC 9000 sec. 16), which Binary HTTP uses for every length."""

from __future__ import annotations

MAX_VARINT = (1 << 62) - 1


def encode_varint(value: int, *, length: int | None = None) -> bytes:
    """Encode ``value`` on the shortest form, or on ``length`` (1, 2, 4 or 8) bytes if given."""
    if not 0 <= value <= MAX_VARINT:
        raise ValueError("varint out of range 0..2**62-1")
    if length is None:
        length = 1 if value < 1 << 6 else 2 if value < 1 << 14 else 4 if value < 1 << 30 else 8
    if length not in (1, 2, 4, 8) or value >> (8 * length - 2):
        raise ValueError("value does not fit the requested varint length")
    prefix = {1: 0, 2: 1, 4: 2, 8: 3}[length]
    return (value | prefix << (8 * length - 2)).to_bytes(length, "big")


def decode_varint(data: bytes | memoryview, offset: int = 0) -> tuple[int, int]:
    """Return ``(value, new_offset)``; raise ``ValueError`` if ``data`` ends inside the integer."""
    if offset >= len(data):
        raise ValueError("truncated varint")
    length = 1 << (data[offset] >> 6)
    if offset + length > len(data):
        raise ValueError("truncated varint")
    value = data[offset] & 0x3F
    for byte in data[offset + 1 : offset + length]:
        value = (value << 8) | byte
    return value, offset + length
