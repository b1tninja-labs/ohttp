"""RFC 9292 known-length Binary HTTP, with the RFC 9458 Appendix A messages and RFC 9292 sec. 5."""

from __future__ import annotations

import pytest

from ohttp._varint import decode_varint, encode_varint
from ohttp.bhttp import (
    Request,
    Response,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)
from ohttp.errors import BhttpError

APPENDIX_A_REQUEST = bytes.fromhex("00034745540568747470730b6578616d706c652e636f6d012f")
APPENDIX_A_RESPONSE = bytes.fromhex("0140c8")

# RFC 9292 sec. 5.1 Figure 8 (known-length request).
FIG8 = bytes.fromhex(
    "00034745 54056874 74707300 0a2f6865 6c6c6f2e 74787440 6c0a7573 65722d61"
    "67656e74 34637572 6c2f372e 31362e33 206c6962 6375726c 2f372e31 362e3320"
    "4f70656e 53534c2f 302e392e 376c207a 6c69622f 312e322e 3304686f 73740f77"
    "77772e65 78616d70 6c652e63 6f6d0f61 63636570 742d6c61 6e677561 67650665"
    "6e2c206d 690000"
)
# RFC 9292 sec. 5.2 Figure 13 (known-length response with trailer).
FIG13 = bytes.fromhex(
    "0140c800 1d546869 7320636f 6e74656e 7420636f 6e746169 6e732043 524c462e"
    "0d0a0d07 74726169 6c657204 74657874"
)
PREFIX = b"\x00\x03GET\x05https\x00\x01/"


def test_varint_rfc9000_a1_vectors():
    cases = [
        ("c2197c5eff14e88c", 151288809941952652),
        ("9d7f3e7d", 494878333),
        ("7bbd", 15293),
        ("25", 37),
        ("4025", 37),
    ]
    for text, value in cases:
        assert decode_varint(bytes.fromhex(text)) == (value, len(text) // 2)
    assert encode_varint(37, length=2) == bytes.fromhex("4025")
    assert encode_varint(15293) == bytes.fromhex("7bbd")
    with pytest.raises(ValueError, match="truncated"):
        decode_varint(bytes.fromhex("9d7f3e"))


def test_rfc9458_appendix_a_request():
    request = decode_request(APPENDIX_A_REQUEST)
    assert (request.method, request.scheme, request.authority, request.path) == (
        b"GET",
        b"https",
        b"example.com",
        b"/",
    )
    assert request.headers == ()
    assert request.content == b""
    assert request.trailers == ()
    assert encode_request(request, truncate=True) == APPENDIX_A_REQUEST


def test_rfc9458_appendix_a_response():
    response = decode_response(APPENDIX_A_RESPONSE)
    assert response.status == 200
    assert encode_response(response, truncate=True) == APPENDIX_A_RESPONSE


def test_rfc9292_section5_examples():
    request = decode_request(FIG8)
    assert request.path == b"/hello.txt"
    assert request.headers[0][0] == b"user-agent"
    assert encode_request(request) == FIG8
    response = decode_response(FIG13)
    assert response.content == b"This content contains CRLF.\r\n"
    assert response.trailers == ((b"trailer", b"text"),)
    assert encode_response(response) == FIG13


def test_truncation_equivalent_to_zero_length():
    explicit = APPENDIX_A_REQUEST + b"\x00\x00\x00"
    assert decode_request(explicit) == decode_request(APPENDIX_A_REQUEST)
    assert decode_request(FIG8[:-2]) == decode_request(FIG8)  # RFC 9292 sec. 5.1 paragraph 9


def test_padding_roundtrip_and_nonzero_padding_invalid():
    padded = encode_request(decode_request(FIG8), pad_to=200)
    assert len(padded) == 200
    assert decode_request(padded) == decode_request(FIG8)
    with pytest.raises(BhttpError):
        decode_request(FIG8 + b"\x00\x01")


def test_truncated_inside_a_field_invalid():
    # Cutting the header section's length-prefixed body short must raise, not decode.
    header_start = FIG8.index(b"\x40\x6c") + 2
    for cut in (header_start - 1, header_start, header_start + 10, len(FIG8) - 3):
        with pytest.raises(BhttpError):
            decode_request(FIG8[:cut])


def test_length_larger_than_buffer():
    huge = encode_varint(2**40, length=8)
    with pytest.raises(BhttpError):
        decode_request(b"\x00" + huge)
    with pytest.raises(BhttpError):
        decode_request(APPENDIX_A_REQUEST + b"\x00" + huge)


def test_framing_indicator_mismatch_and_indeterminate():
    with pytest.raises(BhttpError):
        decode_request(APPENDIX_A_RESPONSE)
    with pytest.raises(BhttpError):
        decode_response(APPENDIX_A_REQUEST)
    with pytest.raises(BhttpError):
        decode_request(b"\x04")
    with pytest.raises(NotImplementedError):
        decode_request(b"\x02")
    with pytest.raises(NotImplementedError):
        decode_response(b"\x03")


def test_informational_responses_before_final():
    response = Response(
        200,
        headers=((b"date", b"x"),),
        content=b"hi",
        informational=((103, ((b"link", b"</a>"),)), (102, ())),
    )
    assert decode_response(encode_response(response)) == response
    with pytest.raises(BhttpError):
        encode_response(Response(99))


def _with_header(name: bytes, value: bytes) -> bytes:
    line = encode_varint(len(name)) + name + encode_varint(len(value)) + value
    return PREFIX + encode_varint(len(line)) + line + b"\x00\x00"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (b"Host", b"x"),  # uppercase: RFC 9113 sec. 8.2.1
        (b"a b", b"x"),
        (b"a:b", b"x"),
        (b"", b"x"),
        (b"a", b"x\ny"),
        (b"a", b" x"),
        (b":path", b"/"),
    ],
)
def test_invalid_field_lines(name, value):
    with pytest.raises(BhttpError):
        decode_request(_with_header(name, value))


def test_pseudo_field_ordering():
    assert decode_request(_with_header(b":custom", b"x")).headers == ((b":custom", b"x"),)
    section = b"\x01a\x01b" + b"\x07:custom\x01c"
    with pytest.raises(BhttpError):
        decode_request(PREFIX + encode_varint(len(section)) + section)


def test_request_roundtrip_with_everything():
    request = Request(
        b"POST",
        b"https",
        b"example.com",
        b"/p?q=1",
        ((b"content-type", b"text/plain"),),
        b"body",
        ((b"x-trailer", b"1"),),
    )
    assert decode_request(encode_request(request)) == request
