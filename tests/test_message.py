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
    assert kems == {0x0010, 0x0011, 0x0012, 0x0020}


# RFC 9180 Appendix A.6.1: DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM, base mode.
P521 = HpkeSuite(0x0012, 3, 2)
P521_SK_E = H(
    "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26a"
    "cf4d68115f8c91a66178cdbd03b7bcc5291e374b"
)
P521_PK_E = H(
    "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce"
    "36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd28"
    "98de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0"
)
P521_SK_R = H(
    "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af6"
    "2c5cadabe2ef9da3760bb21e005202f7b2462847"
)
P521_PK_R = H(
    "0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91"
    "bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bd"
    "a17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64"
)
P521_CT0 = H(
    "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a"
)
P521_CT1 = H(
    "d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256"
)


def test_hpke_rfc9180_appendix_a_p521():
    # the vector uses the KEM's own SHA-512 (kem 0x0012) and a 66-octet private scalar
    assert len(P521_SK_E) == len(P521_SK_R) == 66
    enc, sender = setup_base_s(P521, P521_PK_R, HPKE_INFO, ephemeral_sk=P521_SK_E)
    assert enc == P521_PK_E
    assert sender.seal(b"Count-0", HPKE_PT) == P521_CT0
    assert sender.seal(b"Count-1", HPKE_PT) == P521_CT1
    assert sender.export(b"", 32).hex() == (
        "05e2e5bd9f0c30832b80a279ff211cc65eceb0d97001524085d609ead60d0412"
    )
    assert sender.export(b"\x00", 32).hex() == (
        "fca69744bb537f5b7a1596dbf34eaa8d84bf2e3ee7f1a155d41bd3624aa92b63"
    )
    receiver = setup_base_r(P521, P521_PK_E, P521_SK_R, HPKE_INFO)
    assert receiver.open(b"Count-0", P521_CT0) == HPKE_PT
    assert receiver.open(b"Count-1", P521_CT1) == HPKE_PT


def test_p384_and_p521_key_lengths_and_refusals():
    from ohttp.crypto import KEMS, generate_keypair

    for kem_id, (nsk, npk) in {0x0011: (48, 97), 0x0012: (66, 133)}.items():
        assert (KEMS[kem_id].nsk, KEMS[kem_id].npk, KEMS[kem_id].nenc) == (nsk, npk, npk)
        private, public = generate_keypair(kem_id)
        assert (len(private), len(public)) == (nsk, npk)
        suite = HpkeSuite(kem_id, 2, 2)
        enc, _ = setup_base_s(suite, public, b"")
        for bad in (
            public[:-1],  # short
            b"\x02" + public[1 : 1 + (npk - 1) // 2],  # compressed form (sec. 7.1.1)
            public[:-1] + bytes([public[-1] ^ 1]),  # off the curve
            bytes(npk),  # all zero is not a point
            public + b"\x00",  # long
        ):
            with pytest.raises(MessageError):
                setup_base_s(suite, bad, b"")
            with pytest.raises(MessageError):
                setup_base_r(suite, bad, private, b"")
        for sk in (bytes(nsk), b"\xff" * nsk, private[:-1]):  # zero, above the order, short
            with pytest.raises(MessageError):
                setup_base_r(suite, enc, sk, b"")


def test_p384_hpke_round_trip_and_kem_hash():
    import hashlib
    import hmac

    from ohttp.crypto import KEMS, generate_keypair

    # P-384 has no printed RFC 9180 vector. Each ciphersuite KDF and AEAD must still agree
    # between the roles, and the encapsulation must use HKDF-SHA384 whatever the suite KDF is.
    private, public = generate_keypair(0x0011)
    for kdf in (1, 2, 3):
        for aead in (1, 2, 3):
            suite = HpkeSuite(0x0011, kdf, aead)
            enc, sender = setup_base_s(suite, public, HPKE_INFO)
            receiver = setup_base_r(suite, enc, private, HPKE_INFO)
            assert receiver.open(b"aad", sender.seal(b"aad", HPKE_PT)) == HPKE_PT
            assert receiver.export(b"x", 24) == sender.export(b"x", 24)
    # an independent derivation of sec. 4.1 ExtractAndExpand with SHA-384 matches the shared secret
    from ohttp.crypto import _dh, _kem_shared_secret, _public

    eph, eph_pub = generate_keypair(0x0011)
    dh = _dh(0x0011, eph, public)
    context = _public(0x0011, eph) + public
    suite_id = b"KEM" + (0x0011).to_bytes(2, "big")
    prk = hmac.new(b"\x00" * 48, b"HPKE-v1" + suite_id + b"eae_prk" + dh, hashlib.sha384).digest()
    label = (48).to_bytes(2, "big") + b"HPKE-v1" + suite_id + b"shared_secret" + context
    expected = hmac.new(prk, label + b"\x01", hashlib.sha384).digest()  # one block: T(1)
    assert KEMS[0x0011].nsecret == 48 == len(expected)
    assert _kem_shared_secret(0x0011, dh, context) == expected
    assert eph_pub == context[:97]


def test_p384_and_p521_ohttp_roundtrip():
    suites = (SymmetricSuite(1, 1), SymmetricSuite(2, 2), SymmetricSuite(3, 3))
    for kem_id, npk in ((0x0011, 97), (0x0012, 133)):
        pair = generate_config(suites, 9, kem_id=kem_id)
        assert len(pair.config.public_key) == npk
        for suite in suites:
            encapsulated = encapsulate(REQUEST, pair.config, suite=suite)
            assert encapsulated.body[1:3] == kem_id.to_bytes(2, "big")
            opened = decapsulate(encapsulated.body, [pair])
            assert opened.request == REQUEST
            response = encapsulate_response(opened.context, RESPONSE)
            assert decapsulate_response(encapsulated.context, response) == RESPONSE
