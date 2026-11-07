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
| `keys.generate_config()` | RFC 9458 sec. 3 | `[ ]` | `tests/test_obligations.py::test_generate_config` (to be written) | M1 |
| `keys.parse_config()` | RFC 9458 sec. 3.1 | `[ ]` | `tests/test_obligations.py::test_parse_config` (to be written) | M1 |
| `message.encapsulate()` | RFC 9458 sec. 4 | `[ ]` | `tests/test_obligations.py::test_encapsulate` (to be written) | M2 |
| `message.decapsulate()` | RFC 9458 sec. 4 | `[ ]` | `tests/test_obligations.py::test_decapsulate` (to be written) | M2 |
| `gateway.relay()` | RFC 9458 | `[ ]` | `tests/test_obligations.py::test_relay` (to be written) | M3 |
| `client.request()` | RFC 9458 sec. 5 | `[ ]` | `tests/test_obligations.py::test_request` (to be written) | M2 |
| `svcb.select_gateway()` | RFC 9540 sec. 4, sec. 5 | `[ ]` | `tests/test_obligations.py::test_select_gateway` (to be written) | M5 |
| `crypto.supported_suites()` | RFC 9180 sec. 7 | `[ ]` | `tests/test_obligations.py::test_supported_suites` (to be written) | M2 |

## 2. Milestones

- M1 message and key configuration codecs, byte-exact
- M2 responder and client against published vectors, using the hpke extra
- M3 gateway with its hardening rules, and a correlation-leak test suite
- M4 key rotation with listener notification
- M5 SVCB discovery, then a runnable gateway binary
- M6 publication: 0.1.0 with an end-to-end privacy trace in the docs

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 9180 carries 6 verified errata: read them before writing or depending on an HPKE layer.
- RFC 9540 defines the SVCB keys that identify an oblivious gateway, so discovery and the message layer cannot be built independently.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a general HTTP client: bring httpx and hand it a transport | `[no]` | a named document requires it |
| OHTTP-KEM and other draft-stage variants still moving under the IETF | `[no]` | a named document requires it |
| an anonymity network: one honest component is enough by design, two colluding ones are not | `[no]` | a named document requires it |

## 5. Open questions

- is the HPKE layer a dependency on hpke or a pinned local implementation
- gateway.relay: the module is named for the Oblivious Gateway Resource but described as the relay (RFC 9458 sec. 6.2, Relay Responsibilities); settle which role the row is before it is implemented
- M4 names key rotation with listener notification, but no api row sits on it: add a keys row, or drop the rung

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
