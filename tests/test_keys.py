"""RFC 9458 sec. 3 key configuration codec, against the Appendix A vector."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ohttp.errors import KeyConfigError
from ohttp.keys import (
    KEM_PUBLIC_KEY_LENGTH,
    KeyConfig,
    SymmetricSuite,
    encode_config,
    encode_config_list,
    generate_config,
    parse_config,
    parse_config_list,
)

# RFC 9458 Appendix A paragraph 5.
APPENDIX_A_CONFIG = bytes.fromhex(
    "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003"
)
APPENDIX_A_PUBLIC = bytes.fromhex(
    "31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155"
)


def test_appendix_a_config():
    config = parse_config(APPENDIX_A_CONFIG)
    assert config.key_id == 1
    assert config.kem_id == 0x0020
    assert config.public_key == APPENDIX_A_PUBLIC
    assert config.suites == (SymmetricSuite(1, 1), SymmetricSuite(1, 3))
    assert encode_config(config) == APPENDIX_A_CONFIG


def test_unknown_kem_refused():
    bad = APPENDIX_A_CONFIG[:1] + b"\x00\x13" + APPENDIX_A_CONFIG[3:]
    with pytest.raises(KeyConfigError):
        parse_config(bad)


def test_pubkey_length_mismatch():
    with pytest.raises(KeyConfigError):
        encode_config(KeyConfig(1, 0x0020, bytes(31), (SymmetricSuite(1, 1),)))
    with pytest.raises(KeyConfigError):
        encode_config(KeyConfig(1, 0x0020, bytes(33), (SymmetricSuite(1, 1),)))


@pytest.mark.parametrize("length", [0, 2, 3, 5, 65533])
def test_suites_length_invalid(length):
    head = APPENDIX_A_CONFIG[:35]
    with pytest.raises(KeyConfigError):
        parse_config(head + length.to_bytes(2, "big") + bytes(min(length, 8)))


def test_trailing_bytes_refused():
    with pytest.raises(KeyConfigError):
        parse_config(APPENDIX_A_CONFIG + b"\x00")


def test_truncated_everywhere():
    for cut in range(len(APPENDIX_A_CONFIG)):
        with pytest.raises(KeyConfigError):
            parse_config(APPENDIX_A_CONFIG[:cut])


def test_collection_discarded_on_error():
    good = len(APPENDIX_A_CONFIG).to_bytes(2, "big") + APPENDIX_A_CONFIG
    corrupt = len(APPENDIX_A_CONFIG).to_bytes(2, "big") + APPENDIX_A_CONFIG[:-1] + b"\x07"
    assert len(parse_config_list(good + good)) == 2
    with pytest.raises(KeyConfigError):
        parse_config_list(good + good + corrupt[:-3])
    with pytest.raises(KeyConfigError):
        parse_config_list(good + b"\x00")  # dangling half of a length prefix
    with pytest.raises(KeyConfigError):
        parse_config_list(good + (999).to_bytes(2, "big") + b"\x01")  # runs past the end


def test_empty_collection_refused():
    with pytest.raises(KeyConfigError):
        parse_config_list(b"")
    with pytest.raises(KeyConfigError):
        encode_config_list([])


def test_collection_roundtrip():
    config = parse_config(APPENDIX_A_CONFIG)
    assert parse_config_list(encode_config_list([config, config])) == [config, config]


def test_generate_config():
    suites = (SymmetricSuite(1, 1), SymmetricSuite(1, 3))
    pair = generate_config(suites, 7)
    assert pair.config.key_id == 7
    assert pair.config.kem_id == 0x0020
    assert len(pair.config.public_key) == 32
    assert parse_config(encode_config(pair.config)) == pair.config
    assert pair.private_key.hex() not in repr(pair)
    assert pair.private_key[0] & 7 == 0
    assert pair.private_key[31] & 0xC0 == 0x40  # clamped (RFC 9180 sec. 7.1.2, erratum 7121)
    with pytest.raises(NotImplementedError):
        generate_config(suites, 1, kem_id=0x0010)


@given(
    key_id=st.integers(0, 255),
    kem=st.sampled_from(sorted(KEM_PUBLIC_KEY_LENGTH)),
    data=st.data(),
    suites=st.lists(
        st.builds(SymmetricSuite, st.integers(0, 0xFFFF), st.integers(0, 0xFFFF)),
        min_size=1,
        max_size=8,
    ),
)
def test_roundtrip_property(key_id, kem, data, suites):
    size = KEM_PUBLIC_KEY_LENGTH[kem]
    key = data.draw(st.binary(min_size=size, max_size=size))
    config = KeyConfig(key_id, kem, key, tuple(suites))
    assert parse_config(encode_config(config)) == config
