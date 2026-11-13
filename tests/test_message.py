"""RFC 9458 encapsulation against Appendix A, and HPKE against RFC 9180 Appendix A.1 and A.2."""

from __future__ import annotations

import pytest

from ohttp.crypto import HpkeSuite, setup_base_r, setup_base_s, supported_suites
from ohttp.errors import MessageError
from ohttp.keys import KeyPair, SymmetricSuite, generate_config, parse_config
from ohttp.message import (
    decapsulate,
    decapsulate_response,
    encapsulate,
    encapsulate_response,
)

H = bytes.fromhex

# RFC 9458 Appendix A.
CONFIG = parse_config(
    H("01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003")
)
GATEWAY_SK = H("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a")
CLIENT_SK = H("bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73")
REQUEST = H("00034745540568747470730b6578616d706c652e636f6d012f")
RESPONSE = H("0140c8")
ENC_REQUEST = H(
    "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472"
    "6374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525"
)
RESPONSE_NONCE = H("c789e7151fcba46158ca84b04464910d")
ENC_RESPONSE = H("c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd")
KEYS = [KeyPair(CONFIG, GATEWAY_SK)]


def test_appendix_a_request():
    sealed = encapsulate(REQUEST, CONFIG, suite=SymmetricSuite(1, 1), ephemeral_sk=CLIENT_SK)
    assert sealed.body == ENC_REQUEST
    # The RFC's printed Content-Length: 78 is wrong too: 7 + 32 + 25 + 16 = 80 octets.
    assert len(sealed.body) == 80
    assert sealed.context.enc == H(
        "4b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472"
    )
    opened = decapsulate(ENC_REQUEST, KEYS)
    assert opened.request == REQUEST


def test_appendix_a_response():
    opened = decapsulate(ENC_REQUEST, KEYS)
    enc_response = encapsulate_response(opened.context, RESPONSE, nonce=RESPONSE_NONCE)
    assert enc_response == ENC_RESPONSE
    assert len(enc_response) == 35  # the printed Content-Length 38 is reported erratum 7781
    sealed = encapsulate(REQUEST, CONFIG, ephemeral_sk=CLIENT_SK)
    assert decapsulate_response(sealed.context, ENC_RESPONSE) == RESPONSE


def test_appendix_a_intermediates():
    opened = decapsulate(ENC_REQUEST, KEYS)
    assert opened.context.receiver.export(b"message/bhttp response", 16) == H(
        "62d87a6ba569ee81014c2641f52bea36"
    )


def test_random_roundtrip_every_suite():
    for suite in supported_suites():
        pair = generate_config((SymmetricSuite(suite.kdf_id, suite.aead_id),), 9)
        sealed = encapsulate(REQUEST, pair.config)
        opened = decapsulate(sealed.body, [pair])
        assert opened.request == REQUEST
        enc_response = encapsulate_response(opened.context, RESPONSE)
        assert decapsulate_response(sealed.context, enc_response) == RESPONSE


def test_wrong_key_id_refused():
    with pytest.raises(MessageError):
        decapsulate(b"\x02" + ENC_REQUEST[1:], KEYS)


def test_kem_mismatch_refused():
    with pytest.raises(MessageError, match="step 1a"):
        decapsulate(ENC_REQUEST[:1] + b"\x00\x10" + ENC_REQUEST[3:], KEYS)


def test_unsupported_suite_refused():
    with pytest.raises(MessageError, match="step 1b"):
        decapsulate(ENC_REQUEST[:5] + b"\x00\x02" + ENC_REQUEST[7:], KEYS)
    with pytest.raises(MessageError):
        encapsulate(REQUEST, CONFIG, suite=SymmetricSuite(1, 2))


def test_flipped_bit_each_position():
    for position in range(len(ENC_REQUEST)):
        tampered = bytearray(ENC_REQUEST)
        tampered[position] ^= 0x01
        with pytest.raises(MessageError):
            decapsulate(bytes(tampered), KEYS)
    for position in range(len(ENC_RESPONSE)):
        tampered = bytearray(ENC_RESPONSE)
        tampered[position] ^= 0x01
        sealed = encapsulate(REQUEST, CONFIG, ephemeral_sk=CLIENT_SK)
        with pytest.raises(MessageError):
            decapsulate_response(sealed.context, bytes(tampered))


def test_truncated_request_refused():
    for cut in (0, 3, 6, 7, 20, 38):
        with pytest.raises(MessageError):
            decapsulate(ENC_REQUEST[:cut], KEYS)


def test_response_nonce_length_is_max_nn_nk():
    for suite in (SymmetricSuite(1, 2), SymmetricSuite(1, 3)):
        pair = generate_config((suite,), 3)
        opened = decapsulate(encapsulate(REQUEST, pair.config).body, [pair])
        assert len(encapsulate_response(opened.context, RESPONSE)) == 32 + len(RESPONSE) + 16
        with pytest.raises(MessageError):
            encapsulate_response(opened.context, RESPONSE, nonce=bytes(12))


def test_info_string_exact():
    # Changing the NUL separator must change the request key, so the NUL is part of info.
    from ohttp import message

    assert message._info(b"\x01") == b"message/bhttp request\x00\x01"


# RFC 9180 Appendix A.1 and A.2, base mode. The printed skEm values are the unclamped ones that
# erratum 7121 corrects; both forms must give the same enc.
HPKE_INFO = H("4f6465206f6e2061204772656369616e2055726e")
HPKE_PT = H("4265617574792069732074727574682c20747275746820626561757479")
HPKE_VECTORS = [
    (
        HpkeSuite(0x0020, 1, 1),
        "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        "50c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f776",
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        (
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
        ),
        (
            "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"
        ),
        "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
    ),
    (
        HpkeSuite(0x0020, 1, 3),
        "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
        None,
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        (
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
        ),
        (
            "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"
        ),
        "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69",
    ),
]


@pytest.mark.parametrize(
    ("suite", "sk_printed", "sk_clamped", "pk_e", "pk_r", "sk_r", "ct0", "ct1", "export00"),
    HPKE_VECTORS,
)
def test_hpke_rfc9180_appendix_a_base_mode(
    suite, sk_printed, sk_clamped, pk_e, pk_r, sk_r, ct0, ct1, export00
):
    for sk in filter(None, (sk_printed, sk_clamped)):
        enc, sender = setup_base_s(suite, H(pk_r), HPKE_INFO, ephemeral_sk=H(sk))
        assert enc == H(pk_e)
        assert sender.seal(b"Count-0", HPKE_PT) == H(ct0)
        assert sender.seal(b"Count-1", HPKE_PT) == H(ct1)
        assert sender.export(b"\x00", 32) == H(export00)
    receiver = setup_base_r(suite, H(pk_e), H(sk_r), HPKE_INFO)
    assert receiver.open(b"Count-0", H(ct0)) == HPKE_PT
    assert receiver.open(b"Count-1", H(ct1)) == HPKE_PT


def test_all_zero_dh_refused():
    # A low-order point as enc makes the X25519 output all zero (RFC 9180 sec. 7.1.4).
    with pytest.raises(MessageError):
        setup_base_r(HpkeSuite(0x0020, 1, 1), bytes(32), GATEWAY_SK, b"")


# RFC 9180 Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
P256 = HpkeSuite(0x0010, 1, 1)
P256_SK_E = H("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb")
P256_PK_E = H(
    "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32"
    "5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
)
P256_SK_R = H("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2")
P256_PK_R = H(
    "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70"
    "6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"
)
P256_CT0 = H(
    "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"
)
P256_CT1 = H(
    "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82"
)


def test_hpke_rfc9180_appendix_a_p256():
    enc, sender = setup_base_s(P256, P256_PK_R, HPKE_INFO, ephemeral_sk=P256_SK_E)
    assert enc == P256_PK_E
    assert sender.seal(b"Count-0", HPKE_PT) == P256_CT0
    assert sender.seal(b"Count-1", HPKE_PT) == P256_CT1
    assert sender.export(b"", 32).hex() == (
        "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d"
    )
    assert sender.export(b"\x00", 32).hex() == (
        "6cff87658931bda83dc857e6353efe4987a201b849658d9b047aab4cf216e796"
    )
    receiver = setup_base_r(P256, P256_PK_E, P256_SK_R, HPKE_INFO)
    assert receiver.open(b"Count-0", P256_CT0) == HPKE_PT
    assert receiver.open(b"Count-1", P256_CT1) == HPKE_PT


def test_p256_refuses_bad_keys():
    for bad in (
        P256_PK_E[:-1],  # short
        b"\x02" + P256_PK_E[1:33],  # compressed form is not allowed by sec. 7.1.1
        P256_PK_E[:-1] + bytes([P256_PK_E[-1] ^ 1]),  # off the curve
        bytes(65),  # not a point
    ):
        with pytest.raises(MessageError):
            setup_base_r(P256, bad, P256_SK_R, HPKE_INFO)
    with pytest.raises(MessageError):
        setup_base_s(P256, P256_PK_E[:-1], HPKE_INFO)
    for sk in (bytes(32), b"\xff" * 32, b"\x01" * 31):  # zero, above the order, short
        with pytest.raises(MessageError):
            setup_base_r(P256, P256_PK_E, sk, HPKE_INFO)


def test_p256_ohttp_roundtrip_with_request_and_response():
    suites = (SymmetricSuite(1, 1), SymmetricSuite(2, 2), SymmetricSuite(3, 3))
    pair = generate_config(suites, 7, kem_id=0x0010)
    assert len(pair.config.public_key) == 65
    assert parse_config(
        __import__("ohttp.keys", fromlist=["encode_config"]).encode_config(pair.config)
    ) == (pair.config)
    for suite in suites:
        encapsulated = encapsulate(REQUEST, pair.config, suite=suite)
        assert encapsulated.body[1:3] == b"\x00\x10"  # the KEM id in the header
        opened = decapsulate(encapsulated.body, [pair])
        assert opened.request == REQUEST
        response = encapsulate_response(opened.context, RESPONSE)
        assert decapsulate_response(encapsulated.context, response) == RESPONSE
    # a key identifier bound to P-256 does not open an X25519 message, and the reverse
    other = generate_config(suites, 7)
    x25519 = encapsulate(REQUEST, other.config)
    with pytest.raises(MessageError, match="KEM"):
        decapsulate(x25519.body, [pair])
    # truncation inside the 65-byte enc is refused cleanly
    body = encapsulate(REQUEST, pair.config).body
    with pytest.raises(MessageError):
        decapsulate(body[: 7 + 64], [pair])


def test_supported_suites_include_p256():
    kems = {s.kem_id for s in supported_suites()}
    assert kems == {0x0010, 0x0020}
