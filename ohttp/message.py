"""encapsulated request and response formats (RFC 9458 sec. 4).

The request side is HPKE SetupBaseS/SetupBaseR with the ``message/bhttp request`` info string,
and the response side is the export, Extract and Expand construction of sec. 4.4. Randomness is
injectable by keyword (``ephemeral_sk``, ``nonce``) so the Appendix A vector can be reproduced;
production callers leave them out.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag

from .crypto import (
    AEADS,
    KDFS,
    HpkeSuite,
    ReceiverContext,
    SenderContext,
    aead_for,
    kdf_expand,
    kdf_extract,
    setup_base_r,
    setup_base_s,
)
from .errors import MessageError
from .keys import KeyConfig, KeyPair, SymmetricSuite

__all__ = [
    "ClientContext",
    "Decapsulated",
    "Encapsulated",
    "GatewayContext",
    "decapsulate",
    "decapsulate_response",
    "encapsulate",
    "encapsulate_response",
]

_REQUEST_LABEL = b"message/bhttp request"
_RESPONSE_LABEL = b"message/bhttp response"
_HEADER_LENGTH = 7  # key_id (1) + kem_id, kdf_id, aead_id (2 each)


@dataclass(frozen=True)
class ClientContext:
    """What a client keeps to open the response: the sending context and ``enc``."""

    sender: SenderContext = field(repr=False)
    enc: bytes
    suite: HpkeSuite


@dataclass(frozen=True)
class GatewayContext:
    """What a gateway keeps to answer: the receiving context and ``enc`` from the request."""

    receiver: ReceiverContext = field(repr=False)
    enc: bytes
    suite: HpkeSuite


@dataclass(frozen=True)
class Encapsulated:
    """An Encapsulated Request (``body``, ``message/ohttp-req``) and the client's context."""

    body: bytes
    context: ClientContext


@dataclass(frozen=True)
class Decapsulated:
    """A decrypted binary HTTP request and the gateway's context for the response."""

    request: bytes
    context: GatewayContext


def _header(key_id: int, suite: HpkeSuite) -> bytes:
    return (
        bytes([key_id])
        + suite.kem_id.to_bytes(2, "big")
        + suite.kdf_id.to_bytes(2, "big")
        + suite.aead_id.to_bytes(2, "big")
    )


def _info(header: bytes) -> bytes:
    return _REQUEST_LABEL + b"\x00" + header


def encapsulate(
    request: bytes,
    config: KeyConfig,
    *,
    suite: SymmetricSuite | None = None,
    ephemeral_sk: bytes | None = None,
) -> Encapsulated:
    """Encapsulate a binary HTTP ``request`` for ``config``, RFC 9458 sec. 4.3.

    The client's choice of KDF and AEAD is ``suite`` if given, otherwise the first pair in the
    configuration that this library implements. The aad is empty, as the RFC specifies.
    """
    if suite is None:
        suite = next((s for s in config.suites if s.kdf_id in KDFS and s.aead_id in AEADS), None)
        if suite is None:
            raise MessageError("the key configuration offers no suite this library implements")
    elif suite not in config.suites:
        raise MessageError("the chosen KDF and AEAD are not in the key configuration")
    hpke = HpkeSuite(config.kem_id, suite.kdf_id, suite.aead_id)
    header = _header(config.key_id, hpke)
    enc, sender = setup_base_s(hpke, config.public_key, _info(header), ephemeral_sk=ephemeral_sk)
    ciphertext = sender.seal(b"", request)
    return Encapsulated(header + enc + ciphertext, ClientContext(sender, enc, hpke))


def decapsulate(body: bytes, keys: Sequence[KeyPair]) -> Decapsulated:
    """Decapsulate an Encapsulated Request with the gateway's ``keys``, RFC 9458 sec. 4.3.

    Refuses, with ``MessageError`` and no partial plaintext: a body shorter than header plus
    ``enc``, an unknown key identifier, a KEM that does not match the key (step 1a), a KDF and
    AEAD pair the key's configuration does not offer or this library cannot use (step 1b), and
    any ciphertext that does not authenticate.
    """
    data = bytes(body)
    if len(data) < _HEADER_LENGTH:
        raise MessageError("encapsulated request is shorter than its header")
    key_id = data[0]
    suite = HpkeSuite(
        int.from_bytes(data[1:3], "big"),
        int.from_bytes(data[3:5], "big"),
        int.from_bytes(data[5:7], "big"),
    )
    pair = next((k for k in keys if k.config.key_id == key_id), None)
    if pair is None:
        raise MessageError("no key for this key identifier")
    if pair.config.kem_id != suite.kem_id:
        raise MessageError("key identifier does not match the KEM (RFC 9458 sec. 4.3 step 1a)")
    if SymmetricSuite(suite.kdf_id, suite.aead_id) not in pair.config.suites:
        raise MessageError("KDF and AEAD not offered for this key (RFC 9458 sec. 4.3 step 1b)")
    enc_end = _HEADER_LENGTH + 32  # Nenc of DHKEM(X25519, HKDF-SHA256)
    if len(data) < enc_end:
        raise MessageError("encapsulated request is shorter than its encapsulated key")
    enc = data[_HEADER_LENGTH:enc_end]
    receiver = setup_base_r(suite, enc, pair.private_key, _info(data[:_HEADER_LENGTH]))
    request = receiver.open(b"", data[enc_end:])
    return Decapsulated(request, GatewayContext(receiver, enc, suite))


def _response_keys(
    suite: HpkeSuite, context: SenderContext | ReceiverContext, enc: bytes, nonce: bytes
) -> tuple[bytes, bytes]:
    aead = AEADS[suite.aead_id]
    secret = context.export(_RESPONSE_LABEL, max(aead.nn, aead.nk))
    prk = kdf_extract(suite, enc + nonce, secret)
    return kdf_expand(suite, prk, b"key", aead.nk), kdf_expand(suite, prk, b"nonce", aead.nn)


def encapsulate_response(
    context: GatewayContext, response: bytes, *, nonce: bytes | None = None
) -> bytes:
    """Encapsulate a binary HTTP ``response`` for the request ``context`` opened, sec. 4.4."""
    aead = AEADS[context.suite.aead_id]
    size = max(aead.nn, aead.nk)
    if nonce is None:
        nonce = os.urandom(size)
    elif len(nonce) != size:
        raise MessageError("response nonce must be max(Nn, Nk) bytes")
    key, aead_nonce = _response_keys(context.suite, context.receiver, context.enc, nonce)
    return nonce + aead_for(context.suite, key).encrypt(aead_nonce, response, b"")


def decapsulate_response(context: ClientContext, enc_response: bytes) -> bytes:
    """Open an Encapsulated Response with the client's ``context``, RFC 9458 sec. 4.4."""
    aead = AEADS[context.suite.aead_id]
    size = max(aead.nn, aead.nk)
    data = bytes(enc_response)
    if len(data) < size + 16:
        raise MessageError("encapsulated response is shorter than its nonce and tag")
    nonce, ciphertext = data[:size], data[size:]
    key, aead_nonce = _response_keys(context.suite, context.sender, context.enc, nonce)
    try:
        return aead_for(context.suite, key).decrypt(aead_nonce, ciphertext, b"")
    except InvalidTag:
        raise MessageError("response decryption failed") from None
