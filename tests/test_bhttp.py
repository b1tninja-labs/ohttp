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
    padded_length,
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
    with pytest.raises(BhttpError):
        decode_request(b"\x02")
    with pytest.raises(BhttpError):
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


# RFC 9292 sec. 5.1 Figure 9 (indeterminate-length request, 10 octets of padding).
FIG9 = bytes.fromhex(
    "02034745 54056874 74707300 0a2f6865 6c6c6f2e 7478740a 75736572 2d616765"
    "6e743463 75726c2f 372e3136 2e33206c 69626375 726c2f37 2e31362e 33204f70"
    "656e5353 4c2f302e 392e376c 207a6c69 622f312e 322e3304 686f7374 0f777777"
    "2e657861 6d706c65 2e636f6d 0f616363 6570742d 6c616e67 75616765 06656e2c"
    "206d6900 00000000 00000000 00000000"
)
# RFC 9292 sec. 5.2 Figure 11 (indeterminate-length response with 102 and 103 before the 200).
FIG11 = bytes.fromhex(
    "03406607 72756e6e 696e670a 22736c65 65702031 35220040 67046c69 6e6b233c"
    "2f737479 6c652e63 73733e3b 2072656c 3d707265 6c6f6164 3b206173 3d737479"
    "6c65046c 696e6b24 3c2f7363 72697074 2e6a733e 3b207265 6c3d7072 656c6f61"
    "643b2061 733d7363 72697074 0040c804 64617465 1d4d6f6e 2c203237 204a756c"
    "20323030 39203132 3a32383a 35332047 4d540673 65727665 72064170 61636865"
    "0d6c6173 742d6d6f 64696669 65641d57 65642c20 3232204a 756c2032 30303920"
    "31393a31 353a3536 20474d54 04657461 67142233 34616133 38372d64 2d313536"
    "38656230 30220d61 63636570 742d7261 6e676573 05627974 65730e63 6f6e7465"
    "6e742d6c 656e6774 68023531 04766172 790f4163 63657074 2d456e63 6f64696e"
    "670c636f 6e74656e 742d7479 70650a74 6578742f 706c6169 6e003348 656c6c6f"
    "20576f72 6c642120 4d792063 6f6e7465 6e742069 6e636c75 64657320 61207472"
    "61696c69 6e672043 524c462e 0d0a0000"
)
FIG11_RESPONSE = Response(
    200,
    headers=(
        (b"date", b"Mon, 27 Jul 2009 12:28:53 GMT"),
        (b"server", b"Apache"),
        (b"last-modified", b"Wed, 22 Jul 2009 19:15:56 GMT"),
        (b"etag", b'"34aa387-d-1568eb00"'),
        (b"accept-ranges", b"bytes"),
        (b"content-length", b"51"),
        (b"vary", b"Accept-Encoding"),
        (b"content-type", b"text/plain"),
    ),
    content=b"Hello World! My content includes a trailing CRLF.\r\n",
    informational=(
        (102, ((b"running", b'"sleep 15"'),)),
        (
            103,
            (
                (b"link", b"</style.css>; rel=preload; as=style"),
                (b"link", b"</script.js>; rel=preload; as=script"),
            ),
        ),
    ),
)


def test_rfc9292_indeterminate_examples():
    request = decode_request(FIG9)
    assert request == decode_request(FIG8)  # the same message in the two framings
    assert request.method == b"GET"
    assert request.content == b""
    assert request.trailers == ()
    assert len(FIG9) == 144
    assert encode_request(request, indeterminate=True, pad_to=len(FIG9)) == FIG9
    # sec. 5.1 para 10: up to 12 octets (10 of padding and the two trailing terminators) may go
    assert decode_request(FIG9[:-12]) == request
    with pytest.raises(BhttpError):
        decode_request(FIG9[:-13])  # inside the header section: not a legal truncation point
    response = decode_response(FIG11)
    assert response == FIG11_RESPONSE
    assert encode_response(FIG11_RESPONSE, indeterminate=True) == FIG11
    assert decode_response(FIG13).trailers == ((b"trailer", b"text"),)
    assert decode_response(encode_response(decode_response(FIG13), indeterminate=True)) == (
        decode_response(FIG13)
    )


def test_indeterminate_chunks_are_not_kept_and_zero_length_chunk_ends_content():
    request = Request(b"POST", b"https", b"example.com", b"/", content=b"abcdefghij")
    one = encode_request(request, indeterminate=True)
    three = encode_request(request, indeterminate=True, chunk_size=4)
    assert one != three
    assert decode_request(one) == decode_request(three) == request
    assert three.endswith(
        b"\x04abcd\x04efgh\x02ij\x00\x00"
    )  # content terminator, then the trailers
    # a trailer section after chunked content
    with_trailer = Request(b"POST", b"https", b"h", b"/", content=b"xyz", trailers=((b"t", b"1"),))
    assert decode_request(encode_request(with_trailer, indeterminate=True, chunk_size=1)) == (
        with_trailer
    )


def test_indeterminate_hostile_input():
    head = b"\x02\x03GET\x05https\x01h\x01/"
    good = head + b"\x00\x00\x00"
    assert decode_request(good).method == b"GET"
    for bad in (
        head + b"\x01a\x01b",  # a header section with no terminator
        head + b"\x00\x05ab",  # a chunk longer than the data
        head + b"\x00\x01a",  # chunked content with no terminator
        head + b"\x00\x00\x01",  # padding that is not zero
        head + b"\x01A\x01b\x00\x00\x00",  # an uppercase field name
        head + b"\x00\x00\x07:status\x01x\x00",  # a pseudo-field in the trailers
        head + b"\x03abc\xff\xff\xff\xff\xff\xff\xff\xff",  # a 2**62-1 length is refused, not read
    ):
        with pytest.raises(BhttpError):
            decode_request(bad)
    # known-length messages may not carry the indeterminate terminator shape by accident
    assert decode_request(APPENDIX_A_REQUEST) == decode_request(
        encode_request(decode_request(APPENDIX_A_REQUEST), indeterminate=True)
    )


def test_pad_to_bucket():
    assert [padded_length(n, (64, 256, 1024)) for n in (1, 64, 65, 256, 1024)] == [
        64,
        64,
        256,
        256,
        1024,
    ]
    assert padded_length(1025, (64, 256, 1024)) == 2048  # past the last bucket: its multiples
    assert padded_length(5, (8,)) == 8
    with pytest.raises(ValueError, match="positive"):
        padded_length(1, ())
    with pytest.raises(ValueError, match="positive"):
        padded_length(1, (0, 8))
    # every message under the policy encodes to its bucket size and decodes unchanged
    for body in (b"", b"x" * 40, b"y" * 100, b"z" * 300):
        request = Request(b"POST", b"https", b"example.com", b"/", content=body)
        bare = encode_request(request, truncate=True)
        padded = encode_request(request, pad_to=padded_length(len(bare), (128, 512)))
        assert len(padded) == padded_length(len(padded), (128, 512))
        assert decode_request(padded) == request
