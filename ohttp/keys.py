"""key configurations, identifier, generation and rotation (RFC 9458).

``parse_config`` and ``encode_config`` are a pure codec for RFC 9458 sec. 3.1 and
``parse_config_list`` for the ``application/ohttp-keys`` collection of sec. 3.2. ``KeyRing``
holds a gateway's keys through rotation (sec. 6.4, sec. 6.6) as pure state.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .crypto import generate_keypair
from .errors import KeyConfigError

__all__ = [
    "KEM_PUBLIC_KEY_LENGTH",
    "KeyConfig",
    "KeyPair",
    "KeyRing",
    "RotationEvent",
    "SymmetricSuite",
    "encode_config",
    "encode_config_list",
    "generate_config",
    "parse_config",
    "parse_config_list",
]

# Npk per KEM, RFC 9180 sec. 7.1 Table 2: P-256, P-384, P-521, X25519, X448.
KEM_PUBLIC_KEY_LENGTH: dict[int, int] = {
    0x0010: 65,
    0x0011: 97,
    0x0012: 133,
    0x0020: 32,
    0x0021: 56,
}

_MIN_SUITES = 4  # RFC 9458 sec. 3.1 Figure 2: "= 4..65532"
_MAX_SUITES = 65532


@dataclass(frozen=True)
class SymmetricSuite:
    """One HPKE KDF and AEAD pair a gateway accepts (RFC 9458 sec. 3.1)."""

    kdf_id: int
    aead_id: int


@dataclass(frozen=True)
class KeyConfig:
    """A single key configuration (RFC 9458 sec. 3.1 Figure 2)."""

    key_id: int
    kem_id: int
    public_key: bytes
    suites: tuple[SymmetricSuite, ...] = ()


@dataclass(frozen=True)
class KeyPair:
    """A key configuration with the private key that answers it; ``repr`` hides the secret."""

    config: KeyConfig
    private_key: bytes = field(repr=False)


def encode_config(config: KeyConfig) -> bytes:
    """Serialise ``config`` per RFC 9458 sec. 3.1, refusing a value that could not be parsed."""
    expected = KEM_PUBLIC_KEY_LENGTH.get(config.kem_id)
    if expected is None:
        raise KeyConfigError(f"unknown KEM {config.kem_id:#06x}: Npk is not known")
    if len(config.public_key) != expected:
        raise KeyConfigError("public key length does not match the KEM's Npk")
    if not 0 <= config.key_id <= 0xFF or not config.suites:
        raise KeyConfigError("key_id must fit 8 bits and at least one suite is required")
    if len(config.suites) * 4 > _MAX_SUITES:
        raise KeyConfigError("too many symmetric algorithms")
    try:
        suites = b"".join(
            s.kdf_id.to_bytes(2, "big") + s.aead_id.to_bytes(2, "big") for s in config.suites
        )
    except OverflowError:
        raise KeyConfigError("KDF and AEAD identifiers are 16-bit values") from None
    return (
        bytes([config.key_id])
        + config.kem_id.to_bytes(2, "big")
        + config.public_key
        + len(suites).to_bytes(2, "big")
        + suites
    )


def parse_config(raw: bytes) -> KeyConfig:
    """Parse exactly one key configuration, RFC 9458 sec. 3.1.

    ``raw`` must be consumed completely: trailing bytes, a truncation anywhere, an unknown KEM
    (whose Npk is unknown) and a suites length that is not a multiple of four in 4..65532 all
    raise ``KeyConfigError``.
    """
    data = bytes(raw)
    if len(data) < 3:
        raise KeyConfigError("truncated key configuration")
    key_id = data[0]
    kem_id = int.from_bytes(data[1:3], "big")
    npk = KEM_PUBLIC_KEY_LENGTH.get(kem_id)
    if npk is None:
        raise KeyConfigError(f"unknown KEM {kem_id:#06x}: Npk is not known")
    at = 3 + npk
    if len(data) < at + 2:
        raise KeyConfigError("truncated key configuration")
    public_key = data[3:at]
    length = int.from_bytes(data[at : at + 2], "big")
    at += 2
    if length < _MIN_SUITES or length > _MAX_SUITES or length % 4:
        raise KeyConfigError("symmetric algorithms length must be a multiple of 4 in 4..65532")
    if len(data) != at + length:
        raise KeyConfigError("key configuration length does not match its contents")
    suites = tuple(
        SymmetricSuite(
            int.from_bytes(data[i : i + 2], "big"), int.from_bytes(data[i + 2 : i + 4], "big")
        )
        for i in range(at, at + length, 4)
    )
    return KeyConfig(key_id, kem_id, public_key, suites)


def parse_config_list(raw: bytes) -> list[KeyConfig]:
    """Parse an ``application/ohttp-keys`` body, RFC 9458 sec. 3.2.

    All or nothing: "Clients MUST discard incorrectly encoded key configuration collections",
    so one bad entry raises and no partial list is returned. An empty collection is refused
    because the media type requires one or more configurations.
    """
    data = bytes(raw)
    configs: list[KeyConfig] = []
    at = 0
    while at < len(data):
        if at + 2 > len(data):
            raise KeyConfigError("truncated length prefix in key configuration collection")
        length = int.from_bytes(data[at : at + 2], "big")
        at += 2
        if at + length > len(data):
            raise KeyConfigError("key configuration runs past the end of the collection")
        configs.append(parse_config(data[at : at + length]))
        at += length
    if not configs:
        raise KeyConfigError("a key configuration collection holds at least one entry")
    return configs


def encode_config_list(configs: list[KeyConfig]) -> bytes:
    """Serialise ``configs`` as ``application/ohttp-keys`` (RFC 9458 sec. 3.2)."""
    if not configs:
        raise KeyConfigError("a key configuration collection holds at least one entry")
    out = b""
    for config in configs:
        encoded = encode_config(config)
        out += len(encoded).to_bytes(2, "big") + encoded
    return out


def generate_config(
    suites: tuple[SymmetricSuite, ...], key_id: int, *, kem_id: int = 0x0020
) -> KeyPair:
    """Generate a key pair and its key configuration, RFC 9458 sec. 3.

    DHKEM(X25519, HKDF-SHA256) (0x0020) and DHKEM(P-256, HKDF-SHA256) (0x0010) are implemented. An X25519 private key is serialised
    clamped, as RFC 9180 sec. 7.1.2 requires and its erratum 7121 explains.
    """
    private, public = generate_keypair(kem_id)
    return KeyPair(KeyConfig(key_id, kem_id, public, tuple(suites)), private)


@dataclass(frozen=True)
class RotationEvent:
    """What a :class:`KeyRing` tells a listener: ``kind`` is added, retired or expired."""

    kind: str
    key_id: int
    at: float


class KeyRing:
    """A gateway's keys over time: publish the current ones, accept the retired ones for a while.

    RFC 9458 sec. 6.4 asks a gateway to have a plan for replacing keys, with new key identifiers;
    a request naming an unknown or replaced key identifier is answered 422 (the gateway module
    does that). Sec. 6.6 gives forward secrecy only by generating a new configuration and then
    deleting the old keys after a suitable period, which :meth:`expire` does and reports so the
    caller can delete the secret from wherever else it kept it.

    Pure state: time is whatever ``now`` the caller passes, in seconds. Policies, each pinned by
    a test: a retired key still opens requests for ``grace`` seconds (clients holding the old
    configuration are not cut off at once); it is never published again; an identifier in use
    cannot be reused, and :meth:`next_key_id` skips identifiers still held (the identifier is
    one octet, so 256 keys is the hard limit).
    """

    def __init__(self, *, grace: float = 3600.0) -> None:
        if grace < 0:
            raise ValueError("grace cannot be negative")
        self.grace = grace
        self._current: dict[int, KeyPair] = {}
        self._retired: dict[int, tuple[KeyPair, float]] = {}
        self._listeners: list[Callable[[RotationEvent], None]] = []
        self._last_id = -1

    def subscribe(self, listener: Callable[[RotationEvent], None]) -> Callable[[], None]:
        """Call ``listener`` on every change; the returned function removes it."""
        self._listeners.append(listener)
        return lambda: self._listeners.remove(listener)

    def _emit(self, kind: str, key_id: int, now: float) -> None:
        event = RotationEvent(kind, key_id, now)
        for listener in list(self._listeners):
            listener(event)

    def next_key_id(self) -> int:
        """An identifier not held by any current or retired key, counting on from the last."""
        used = self._current.keys() | self._retired.keys()
        for step in range(1, 257):
            candidate = (self._last_id + step) % 256
            if candidate not in used:
                return candidate
        raise KeyConfigError("all 256 key identifiers are in use")

    def add(self, pair: KeyPair, now: float) -> None:
        """Start publishing ``pair``; its identifier must not be held already."""
        key_id = pair.config.key_id
        if key_id in self._current or key_id in self._retired:
            raise KeyConfigError(f"key identifier {key_id} is in use")
        self._current[key_id] = pair
        self._last_id = key_id
        self._emit("added", key_id, now)

    def rotate(self, new: KeyPair, now: float) -> None:
        """Publish ``new`` and retire every key that was current, to be dropped after ``grace``."""
        self.add(new, now)
        for key_id in [k for k in self._current if k != new.config.key_id]:
            self._retired[key_id] = (self._current.pop(key_id), now + self.grace)
            self._emit("retired", key_id, now)

    def expire(self, now: float) -> list[KeyPair]:
        """Drop retired keys whose grace has run out and return them (RFC 9458 sec. 6.6)."""
        gone = [k for k, (_, until) in self._retired.items() if now >= until]
        dropped = [self._retired.pop(k)[0] for k in gone]
        for key_id in gone:
            self._emit("expired", key_id, now)
        return dropped

    def current(self) -> list[KeyPair]:
        """The keys to publish in the key configuration collection."""
        return list(self._current.values())

    def decapsulation_keys(self, now: float) -> list[KeyPair]:
        """The keys that may open a request at ``now``: current, then retired within grace."""
        keys = list(self._current.values())
        keys += [pair for pair, until in self._retired.values() if now < until]
        return keys

    def config_list(self) -> bytes:
        """The ``application/ohttp-keys`` body for the current keys (RFC 9458 sec. 3.2)."""
        return encode_config_list([pair.config for pair in self._current.values()])
