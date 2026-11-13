# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation ohttp could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `keys.generate_config()` | RFC 9458 sec. 3, RFC 9180 sec. 7.1.2 | `[ok]` | `tests/test_keys.py::test_generate_config` | M1 |
| `keys.parse_config()` | RFC 9458 sec. 3.1 | `[ok]` | `tests/test_keys.py::test_appendix_a_config`, `tests/test_keys.py::test_truncated_everywhere` | M1 |
| `keys.encode_config()` | RFC 9458 sec. 3.1 | `[ok]` | `tests/test_keys.py::test_appendix_a_config`, `tests/test_keys.py::test_roundtrip_property` | M1 |
| `keys.parse_config_list()` | RFC 9458 sec. 3.2 | `[ok]` | `tests/test_keys.py::test_collection_discarded_on_error` | M1 |
| `bhttp.encode_request()` | RFC 9292 sec. 3.1, sec. 3.4, sec. 3.8 | `[ok]` | `tests/test_bhttp.py::test_rfc9458_appendix_a_request`, `tests/test_bhttp.py::test_rfc9292_section5_examples` | M1 |
| `bhttp.decode_request()` | RFC 9292 sec. 3.1, sec. 3.6, sec. 3.8, sec. 4 | `[ok]` | `tests/test_bhttp.py::test_rfc9458_appendix_a_request`, `tests/test_bhttp.py::test_invalid_field_lines`, `tests/test_bhttp.py::test_padding_roundtrip_and_nonzero_padding_invalid` | M1 |
| `bhttp.encode_response()` | RFC 9292 sec. 3.5 | `[ok]` | `tests/test_bhttp.py::test_rfc9458_appendix_a_response`, `tests/test_bhttp.py::test_informational_responses_before_final` | M1 |
| `bhttp.decode_response()` | RFC 9292 sec. 3.5, sec. 3.5.1 | `[ok]` | `tests/test_bhttp.py::test_rfc9458_appendix_a_response`, `tests/test_bhttp.py::test_rfc9292_section5_examples` | M1 |
| `message.encapsulate()` | RFC 9458 sec. 4.3 | `[ok]` | `tests/test_message.py::test_appendix_a_request` | M2 |
| `message.decapsulate()` | RFC 9458 sec. 4.3 | `[ok]` | `tests/test_message.py::test_appendix_a_request`, `tests/test_message.py::test_flipped_bit_each_position`, `tests/test_message.py::test_kem_mismatch_refused` | M2 |
| `message.encapsulate_response()` | RFC 9458 sec. 4.4 | `[ok]` | `tests/test_message.py::test_appendix_a_response`, `tests/test_message.py::test_response_nonce_length_is_max_nn_nk` | M2 |
| `message.decapsulate_response()` | RFC 9458 sec. 4.4 | `[ok]` | `tests/test_message.py::test_appendix_a_response`, `tests/test_message.py::test_flipped_bit_each_position` | M2 |
| `crypto.supported_suites()` | RFC 9180 sec. 7, RFC 9458 sec. 3.1 | `[ok]` | `tests/test_message.py::test_random_roundtrip_every_suite`, `tests/test_message.py::test_hpke_rfc9180_appendix_a_base_mode` | M2 |
| `crypto.setup_base_s()` | RFC 9180 sec. 5.1.1, sec. 5.2, sec. 5.3 | `[ok]` | `tests/test_message.py::test_hpke_rfc9180_appendix_a_base_mode` | M2 |
| `crypto.setup_base_r()` | RFC 9180 sec. 5.1.1, sec. 7.1.4 | `[ok]` | `tests/test_message.py::test_hpke_rfc9180_appendix_a_base_mode`, `tests/test_message.py::test_all_zero_dh_refused` | M2 |
| `gateway.relay()` | RFC 9458 sec. 6.2 | `[ ]` | `tests/test_relay.py::test_correlation_leak` (to be written) | M3 |
| `client.request()` | RFC 9458 sec. 5 | `[ ]` | `tests/test_client.py::test_request` (to be written) | M2 |
| `svcb.select_gateway()` | RFC 9540 sec. 4, sec. 5, sec. 6 | `[ ]` | `tests/test_svcb.py::test_https_rr_selection` (to be written) | M5 |
| `crypto.p256_kem` (DHKEM(P-256, HKDF-SHA256) 0x0010 over `cryptography`'s ECDH; uncompressed points only, on-curve check, scalar in [1, order-1]; P-384 0x0011 and P-521 0x0012 are not implemented) | RFC 9180 sec. 7.1, appendix A.3 | `[ok]` | `tests/test_message.py::test_hpke_rfc9180_appendix_a_p256` | M2 |
| `crypto.p256_bad_keys` (short, compressed, off-curve and zero or oversized-scalar inputs raise `MessageError`) | RFC 9180 sec. 7.1.1, sec. 7.1.4 | `[ok]` | `tests/test_message.py::test_p256_refuses_bad_keys` | M2 |
| `crypto.p256_ohttp_roundtrip` (request and response through the P-256 key with all three AEAD suites) | RFC 9458 sec. 4.3, sec. 4.4 | `[ok]` | `tests/test_message.py::test_p256_ohttp_roundtrip_with_request_and_response` | M2 |
| `crypto.p384_p521_kems` (0x0011, 0x0012: the table has room, nothing tests them and RFC 9180 appendix A has no vector for them) | RFC 9180 sec. 7.1 | `[ ]` | `tests/test_message.py::test_hpke_p384_vector` (to be written) | M2 |
| `crypto.psk_auth_modes` | RFC 9180 sec. 5.1.2-5.1.4 | `[no]` | OHTTP uses base mode only (RFC 9458 sec. 4.3); revisit if ODoH or ECH is scoped | - |
| `bhttp.indeterminate` (framing 2 and 3, encode and decode, chunking, truncation at part boundaries only; Figures 9 and 11 reproduce byte for byte) | RFC 9292 sec. 3.2, sec. 5 | `[ok]` | `tests/test_bhttp.py::test_rfc9292_indeterminate_examples` | M1 |
| `bhttp.indeterminate_hostile` (unterminated sections, over-long chunks, non-zero padding, uppercase names, a 2**62-1 length) | RFC 9292 sec. 3.2, sec. 3.8, sec. 4 | `[ok]` | `tests/test_bhttp.py::test_indeterminate_hostile_input` | M1 |
| `bhttp.chunked_padding_policy` (`bhttp.padded_length`: smallest bucket that holds the message, multiples of the last past it; the cited section was wrong, padding advice is RFC 9458 sec. 6.2.3 para 6 and sec. 6.3 para 3, not sec. 6.1) | RFC 9292 sec. 3.8, RFC 9458 sec. 6.2.3, sec. 6.3 | `[ok]` | `tests/test_bhttp.py::test_pad_to_bucket` | M3 |
| `keys.rotate` (`KeyRing`: publish current keys, retired keys open requests for a grace period, `expire` returns keys to delete, listeners, identifiers not reused; 422 for an unknown key is `gateway.error_responses`) | RFC 9458 sec. 6.4, sec. 6.6 | `[ok]` | `tests/test_keys.py::test_rotation_listener` | M4 |
| `gateway.replay_policy` (`ReplayCache`: `enc` remembered for a window, a repeat answered with an encapsulated 400; the window is a parameter and not secret) | RFC 9458 sec. 6.5, sec. 6.5.1 | `[ok]` | `tests/test_gateway.py::test_replay_refused` | M3 |
| `gateway.date-window` (`process_request(date_window=...)`: a `Date` outside the window is an encapsulated 400 with the `date` problem type and a `Date` header; no `Date` is not refused) | RFC 9458 sec. 6.5.1, sec. 6.5.2 | `[ok]` | `tests/test_gateway.py::test_date_window_and_the_correcting_response` | M3 |
| `gateway.error_responses` (`process_request`: 415 and 422 unprotected before decapsulation, 422 with the `ohttp-key` problem type for an unknown key identifier, encapsulated 400, 500 and 504 after it, `Expect: 100-continue` an error) | RFC 9458 sec. 5.2, sec. 5.1, sec. 5.3, sec. 6.4 | `[ok]` | `tests/test_gateway.py::test_error_status_codes` | M3 |
| `gateway.process_request()` (the gateway as a pure function over a forward callable; success is a bare 200 `message/ohttp-res`) | RFC 9458 sec. 5, sec. 4.4 | `[ok]` | `tests/test_gateway.py::test_success_is_a_bare_200_with_the_response_media_type` | M3 |
| `message.response_content_type` (media types `application/ohttp-keys`, `message/ohttp-req`, `message/ohttp-res`, none with parameters; enforced on the request type by the gateway) | RFC 9458 sec. 4.5, sec. 6.9, sec. 9 | `[ok]` | `tests/test_gateway.py::test_media_type_enforced` | M2 |
| `ohttp.oblivious_doh` | RFC 9230 (Experimental, separate message format) | `[no]` | a named document requires it; not a variant of RFC 9458 | - |


## 2. Milestones

- M1 message and key configuration codecs, byte-exact
- M2 responder and client against published vectors, on the HPKE written in `crypto.py` (no `hpke` extra: `cryptography` supplies the primitives, see `docs/strategy.md`)
- M3 gateway with its hardening rules, and a correlation-leak test suite
- M4 key rotation with listener notification
- M5 SVCB discovery, then a runnable gateway binary
- M6 publication: 0.1.0 with an end-to-end privacy trace in the docs

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 9180 carries 6 verified errata: read them before writing or depending on an HPKE layer. 7121 (unclamped X25519 keys in Appendix A) is pinned by `tests/test_message.py::test_hpke_rfc9180_appendix_a_base_mode`, which runs both forms of skEm; 7937 and 7934 concern DeriveKeyPair, unimplemented.
- RFC 9458 has one reported erratum (7781): Appendix A prints `Content-Length: 38` for a 35-octet encapsulated response. Its request example is wrong the same way (`78` for 80 octets) and is not on file. Do not copy either header into a test.
- RFC 9458 sec. 5.3 shows the `ohttp-key` problem type with a 400 status, while sec. 6.4 says a gateway "can respond with an HTTP 422" for an unknown or replaced key. Both are MAY, so `process_request` uses 422 with the problem body; a client must not depend on either (sec. 5.3 para 4). RFC 9458 sec. 6.5.2 and sec. 9.4 add the `date` problem type; `Date` handling is in `gateway`. Section citations in earlier rows were corrected on 2026-11-13: padding is sec. 6.2.3 and sec. 6.3, key replacement sec. 6.4 and sec. 6.6.
- RFC 9180 errata 7937 (suite_id of DeriveKeyPair, 6 verified in all) is still not exercised: no `DeriveKeyPair` exists, the keys are drawn directly. Add the row when ikm-derived keys are wanted.
- RFC 9292 erratum 8559 (held): the HTTP/2 malformed rule covers field names, so `bhttp` rejects uppercase names.
- RFC 9230 is Oblivious DoH, a separate Experimental protocol; it is not a variant of RFC 9458.
- RFC 9540 defines the SVCB keys that identify an oblivious gateway, so discovery and the message layer cannot be built independently.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a general HTTP client: bring httpx and hand it a transport | `[no]` | a named document requires it |
| OHTTP-KEM and other draft-stage variants still moving under the IETF | `[no]` | a named document requires it |
| an anonymity network: one honest component is enough by design, two colluding ones are not | `[no]` | a named document requires it |

## 5. Open questions

- ~~is the HPKE layer a dependency on hpke or a pinned local implementation~~ Decided 2026-11-13: local, on `cryptography`'s primitives. `cryptography` 47+ ships a single-shot HPKE with no `Export` and no injectable ephemeral key, so it cannot carry RFC 9458 sec. 4.4; the `hpke` extra is removed.
- gateway.relay: the module is named for the Oblivious Gateway Resource but described as the relay (RFC 9458 sec. 6.2, Relay Responsibilities); settle which role the row is before it is implemented. Proposal: a `relay` module that forwards opaque bodies and never decrypts (no HPKE needed) and a `gateway` module that decapsulates, forwards to the target and encapsulates the response.
- M4 names key rotation with listener notification, and a `keys.rotate` row now sits on it (RFC 9458 sec. 6.4, sec. 5.3).
- P-256 (0x0010) is built and proven against RFC 9180 appendix A.3 (decided with the owner's rule: `cryptography` supplies ECDH). Whether the first release ships both KEMs is the owner's call; nothing blocks it.
- Follow-up from the 2026-11-13 first pass: the QUIC varint is duplicated in `ohttp/_varint.py` (also in h3tunnel); a shared home is a portfolio decision, not an ohttp one.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
