"""HPKE base mode (RFC 9180) built on the ``cryptography`` primitives.

``cryptography`` 47 and later ship ``cryptography.hazmat.primitives.hpke``, but only as the
single-shot ``Suite.encrypt`` and ``Suite.decrypt``: it draws a fresh ephemeral key inside
``encrypt`` and has no ``Export``. RFC 9458 sec. 4.4 needs ``context.Export`` to protect the
response, and Appendix A can be checked only with a caller-chosen ephemeral key. So the key
schedule here is written out from RFC 9180 sec. 4, sec. 5.1 and sec. 5.3, and takes from
``cryptography`` only X25519, HKDF-Expand and the AEADs.

Implemented: mode_base, DHKEM(X25519, HKDF-SHA256) (kem 0x0020), DHKEM(P-256, HKDF-SHA256)
(kem 0x0010, RFC 9180 appendix A.3 vectors), DHKEM(P-384, HKDF-SHA384) (kem 0x0011) and
DHKEM(P-521, HKDF-SHA512) (kem 0x0012, appendix A.6 vector), HKDF-SHA256/384/512 (kdf
0x0001..0x0003), AES-128-GCM, AES-256-GCM and ChaCha20Poly1305 (aead 0x0001..0x0003). The X448
KEM, and the PSK and Auth modes, are not.

The NIST curves follow RFC 9180 sec. 7.1: public keys are the uncompressed SEC1 point (65, 97
or 133 octets; compressed or malformed points are refused, which is the partial validation of
sec. 7.1.4), private keys are the big-endian scalar of Nsk octets (32, 48 or 66) and must lie
in [1, order-1], and the Diffie-Hellman output is the x coordinate. The scalar is not reduced
as sec. 7.1.2 allows; a value outside the range is refused instead, so two implementations
cannot disagree on it. Each KEM runs its own KDF inside the encapsulation (sec. 7.1.3:
SHA-256, SHA-384 or SHA-512), whatever the ciphersuite's KDF is. RFC 9180 has no printed
vector for P-384, so that KEM is checked by round trips, by the curve and length tables, and
by the P-521 vector exercising the same code path.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .errors import MessageError

__all__ = [
    "AEADS",
    "KDFS",
    "KEMS",
    "KEM_P256",
    "KEM_X25519",
    "HpkeSuite",
    "ReceiverContext",
    "SenderContext",
    "aead_for",
    "generate_keypair",
    "kdf_expand",
    "kdf_extract",
    "setup_base_r",
    "setup_base_s",
    "supported_suites",
]

KEM_X25519 = 0x0020
KEM_P256 = 0x0010
KEM_P384 = 0x0011
KEM_P521 = 0x0012
_MODE_BASE = b"\x00"  # RFC 9180 sec. 5 Table 1


@dataclass(frozen=True)
class _Kdf:
    hash_name: str
    algorithm: type[hashes.HashAlgorithm]
    nh: int


@dataclass(frozen=True)
class _Kem:
    """One row of RFC 9180 sec. 7.1 Table 2, with the hash of the KEM's own HKDF."""

    nsecret: int
    nenc: int
    npk: int
    nsk: int
    kdf_id: int  # the KEM's associated KDF (sec. 7.1.3), not the ciphersuite's
    curve: type[ec.EllipticCurve] | None = None  # None for X25519


KEMS: dict[int, _Kem] = {
    KEM_X25519: _Kem(32, 32, 32, 32, 0x0001),
    KEM_P256: _Kem(32, 65, 65, 32, 0x0001, ec.SECP256R1),
    KEM_P384: _Kem(48, 97, 97, 48, 0x0002, ec.SECP384R1),
    KEM_P521: _Kem(64, 133, 133, 66, 0x0003, ec.SECP521R1),
}

# RFC 9180 sec. 7.2 Table 3.
KDFS: dict[int, _Kdf] = {
    0x0001: _Kdf("sha256", hashes.SHA256, 32),
    0x0002: _Kdf("sha384", hashes.SHA384, 48),
    0x0003: _Kdf("sha512", hashes.SHA512, 64),
}


@dataclass(frozen=True)
class _Aead:
    nk: int
    nn: int


# RFC 9180 sec. 7.3 Table 5 (0xFFFF export-only is not offered).
AEADS: dict[int, _Aead] = {0x0001: _Aead(16, 12), 0x0002: _Aead(32, 12), 0x0003: _Aead(32, 12)}


@dataclass(frozen=True)
class HpkeSuite:
    """A (KEM, KDF, AEAD) triple of RFC 9180 sec. 4 identifiers."""

    kem_id: int
    kdf_id: int
    aead_id: int


def supported_suites() -> tuple[HpkeSuite, ...]:
    """The HPKE ciphersuites this module implements, RFC 9180 sec. 7 and RFC 9458 sec. 3.1."""
    return tuple(HpkeSuite(kem, kdf, aead) for kem in KEMS for kdf in KDFS for aead in AEADS)


def _check(suite: HpkeSuite) -> None:
    if suite.kem_id not in KEMS or suite.kdf_id not in KDFS or suite.aead_id not in AEADS:
        raise MessageError("unsupported HPKE ciphersuite")


def _clamp(sk: bytes) -> bytes:
    """RFC 7748 decodeScalar25519 bit operations, which RFC 9180 sec. 7.1.2 requires."""
    if len(sk) != 32:
        raise MessageError("an X25519 private key is 32 bytes")
    b = bytearray(sk)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def generate_keypair(kem_id: int = KEM_X25519) -> tuple[bytes, bytes]:
    """Return ``(private, public)`` for the KEM, the private key serialised as RFC 9180 says."""
    kem = KEMS.get(kem_id)
    if kem is None:
        raise NotImplementedError(f"KEM {kem_id:#06x} is not implemented")
    if kem.curve is None:
        private = _clamp(os.urandom(32))
    else:
        key = ec.generate_private_key(kem.curve())
        private = key.private_numbers().private_value.to_bytes(kem.nsk, "big")
    return private, _public(kem_id, private)


def _ec_curve(kem_id: int) -> tuple[_Kem, ec.EllipticCurve]:
    kem = KEMS[kem_id]
    if kem.curve is None:
        raise MessageError("not an elliptic-curve KEM")
    return kem, kem.curve()


def _ec_private(kem_id: int, private: bytes) -> ec.EllipticCurvePrivateKey:
    kem, curve = _ec_curve(kem_id)
    name = curve.name
    if len(private) != kem.nsk:
        raise MessageError(f"a {name} private key is {kem.nsk} bytes")
    try:
        return ec.derive_private_key(int.from_bytes(private, "big"), curve)
    except ValueError:
        raise MessageError(f"{name} private key is outside [1, order-1]") from None


def _ec_public(kem_id: int, public: bytes) -> ec.EllipticCurvePublicKey:
    # RFC 9180 sec. 7.1.1: uncompressed only; sec. 7.1.4: on the curve, not the point at infinity.
    kem, curve = _ec_curve(kem_id)
    if len(public) != kem.npk or public[0] != 4:
        raise MessageError(f"a {curve.name} public key is a {kem.npk}-byte uncompressed point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, public)
    except ValueError:
        raise MessageError(f"{curve.name} public key is not a point on the curve") from None


def _public(kem_id: int, private: bytes) -> bytes:
    if KEMS[kem_id].curve is not None:
        return (
            _ec_private(kem_id, private)
            .public_key()
            .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        )
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def _dh(kem_id: int, private: bytes, public: bytes) -> bytes:
    if KEMS[kem_id].curve is not None:
        return _ec_private(kem_id, private).exchange(ec.ECDH(), _ec_public(kem_id, public))
    if len(public) != 32:
        raise MessageError("an X25519 public key is 32 bytes")
    try:
        shared = X25519PrivateKey.from_private_bytes(private).exchange(
            X25519PublicKey.from_public_bytes(public)
        )
    except ValueError:
        raise MessageError("X25519 key exchange failed") from None
    if not any(shared):  # RFC 9180 sec. 7.1.4: abort on the all-zero shared secret
        raise MessageError("X25519 shared secret is all zero")
    return shared


def _extract(hash_name: str, salt: bytes, ikm: bytes) -> bytes:
    # HKDF-Extract is HMAC(salt, ikm) (RFC 5869 sec. 2.2); an empty salt is a string of zeros,
    # which HMAC's key padding already is. cryptography exposes only the combined HKDF, so
    # Extract is the standard library's.
    return hmac.new(salt, ikm, getattr(hashlib, hash_name)).digest()


def _expand(kdf: _Kdf, prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(kdf.algorithm(), length, info).derive(prk)


def kdf_extract(suite: HpkeSuite, salt: bytes, ikm: bytes) -> bytes:
    """The HPKE ciphersuite KDF's ``Extract(salt, ikm)`` (RFC 9180 sec. 4)."""
    return _extract(KDFS[suite.kdf_id].hash_name, salt, ikm)


def kdf_expand(suite: HpkeSuite, prk: bytes, info: bytes, length: int) -> bytes:
    """The HPKE ciphersuite KDF's ``Expand(prk, info, L)`` (RFC 9180 sec. 4)."""
    return _expand(KDFS[suite.kdf_id], prk, info, length)


def aead_for(suite: HpkeSuite, key: bytes) -> AESGCM | ChaCha20Poly1305:
    """The suite's AEAD keyed with ``key`` (RFC 9180 sec. 7.3)."""
    return ChaCha20Poly1305(key) if suite.aead_id == 0x0003 else AESGCM(key)


def _labeled_extract(kdf: _Kdf, suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(kdf.hash_name, salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(
    kdf: _Kdf, suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    labeled = length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info
    return _expand(kdf, prk, labeled, length)


def _kem_shared_secret(kem_id: int, dh: bytes, kem_context: bytes) -> bytes:
    kdf = KDFS[KEMS[kem_id].kdf_id]  # sec. 7.1: the KEM's own HKDF hash
    suite_id = b"KEM" + kem_id.to_bytes(2, "big")
    eae_prk = _labeled_extract(kdf, suite_id, b"", b"eae_prk", dh)
    return _labeled_expand(
        kdf, suite_id, eae_prk, b"shared_secret", kem_context, KEMS[kem_id].nsecret
    )


@dataclass
class _Context:
    suite: HpkeSuite
    _key: bytes = field(repr=False)
    _base_nonce: bytes = field(repr=False)
    _exporter_secret: bytes = field(repr=False)
    _suite_id: bytes = field(repr=False)
    seq: int = 0

    def _aead(self) -> AESGCM | ChaCha20Poly1305:
        return aead_for(self.suite, self._key)

    def _nonce(self) -> bytes:
        # RFC 9180 sec. 5.2 ComputeNonce: base_nonce XOR I2OSP(seq, Nn); overflow is an error.
        nn = len(self._base_nonce)
        if self.seq >= (1 << (8 * nn)) - 1:
            raise MessageError("HPKE message limit reached")
        return bytes(
            a ^ b for a, b in zip(self._base_nonce, self.seq.to_bytes(nn, "big"), strict=True)
        )

    def export(self, exporter_context: bytes, length: int) -> bytes:
        """``Context.Export`` (RFC 9180 sec. 5.3), usable by either role."""
        kdf = KDFS[self.suite.kdf_id]
        if length > 255 * kdf.nh:
            raise MessageError("export length exceeds 255*Nh")
        return _labeled_expand(
            kdf, self._suite_id, self._exporter_secret, b"sec", exporter_context, length
        )


class SenderContext(_Context):
    """The sending context of SetupBaseS; it may seal and must not open (RFC 9180 sec. 5.2)."""

    def seal(self, aad: bytes, plaintext: bytes) -> bytes:
        """ContextS.Seal."""
        ciphertext = self._aead().encrypt(self._nonce(), plaintext, aad)
        self.seq += 1
        return ciphertext


class ReceiverContext(_Context):
    """The receiving context of SetupBaseR; it may open and must not seal (RFC 9180 sec. 5.2)."""

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        """ContextR.Open; raises ``MessageError`` on any authentication failure."""
        try:
            plaintext = self._aead().decrypt(self._nonce(), ciphertext, aad)
        except InvalidTag:
            raise MessageError("HPKE decryption failed") from None
        self.seq += 1
        return plaintext


def _key_schedule(
    cls: type[_Context], suite: HpkeSuite, shared_secret: bytes, info: bytes
) -> _Context:
    kdf, aead = KDFS[suite.kdf_id], AEADS[suite.aead_id]
    suite_id = (
        b"HPKE"
        + suite.kem_id.to_bytes(2, "big")
        + suite.kdf_id.to_bytes(2, "big")
        + suite.aead_id.to_bytes(2, "big")
    )
    psk_id_hash = _labeled_extract(kdf, suite_id, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(kdf, suite_id, b"", b"info_hash", info)
    context = _MODE_BASE + psk_id_hash + info_hash
    secret = _labeled_extract(kdf, suite_id, shared_secret, b"secret", b"")
    key = _labeled_expand(kdf, suite_id, secret, b"key", context, aead.nk)
    nonce = _labeled_expand(kdf, suite_id, secret, b"base_nonce", context, aead.nn)
    exporter = _labeled_expand(kdf, suite_id, secret, b"exp", context, kdf.nh)
    return cls(suite, key, nonce, exporter, suite_id)


def setup_base_s(
    suite: HpkeSuite, public_key: bytes, info: bytes, *, ephemeral_sk: bytes | None = None
) -> tuple[bytes, SenderContext]:
    """SetupBaseS (RFC 9180 sec. 5.1.1): return ``(enc, context)``.

    ``ephemeral_sk`` exists so Appendix A of RFC 9458 can be reproduced; leave it out otherwise.
    """
    _check(suite)
    if ephemeral_sk is None:
        ephemeral_sk = generate_keypair(suite.kem_id)[0]
    enc = _public(suite.kem_id, ephemeral_sk)
    dh = _dh(suite.kem_id, ephemeral_sk, public_key)
    shared = _kem_shared_secret(suite.kem_id, dh, enc + public_key)
    return enc, cast(SenderContext, _key_schedule(SenderContext, suite, shared, info))


def setup_base_r(suite: HpkeSuite, enc: bytes, private_key: bytes, info: bytes) -> ReceiverContext:
    """SetupBaseR (RFC 9180 sec. 5.1.1)."""
    _check(suite)
    dh = _dh(suite.kem_id, private_key, enc)
    shared = _kem_shared_secret(suite.kem_id, dh, enc + _public(suite.kem_id, private_key))
    return cast(ReceiverContext, _key_schedule(ReceiverContext, suite, shared, info))
