# ohttp

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
The key configuration codec, Binary HTTP, HPKE base mode and request and response
encapsulation are implemented and checked against the RFC 9458 and RFC 9180 test vectors. The
relay, client and SVCB discovery are not: those public functions raise `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

ohttp -- Oblivious HTTP client, gateway and responder

OHTTP exists so that the party who sees the content never sees who asked, and the party who relays never sees the content. It is the reporting path for privacy-preserving systems and it is standardised: RFC 9458 for the mechanism, RFC 9540 for discovering a gateway through SVCB records, RFC 9230 for the separate Oblivious DoH protocol. Python has nothing: ohttp, pyohttp and ohttp-relay are all absent from PyPI, and the one implementation people reach for is a Rust binding built for Firefox. The crypto primitives are not the blocker, since `cryptography` supplies them; what nobody has is the message format and the gateway that must not leak correlation data.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| hpke | 0.3.2 | 2024-10-26 | the HPKE primitives; not OHTTP and no gateway |
| pyohttp | - | - | Rust with Python bindings built for Firefox; absent from PyPI |
| ohttp, ohttp-relay | - | - | absent from PyPI (2026-11-05) |

What this project intends to add:

- all three roles in one library: client, gateway and responder
- key configuration and rotation with an explicit listener bound to config changes
- gateway hardening: no redirects followed, bounded body sizes, no correlation identifiers logged
- SVCB-based gateway discovery per RFC 9540 rather than a hand-configured URL
- a runnable gateway binary, because a relay you cannot deploy is not a reference implementation

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 9458 | Proposed Standard | 2024-01 | Oblivious HTTP: encapsulated messages, keys, the gateway contract |
| RFC 9540 | Proposed Standard | 2024-02 | discovering oblivious services through Service Binding records |
| RFC 9230 | Experimental | 2022-06 | Oblivious DNS over HTTPS: a separate protocol with its own message format, not implemented here |
| RFC 9180 | IRTF Informational | 2022-02 | HPKE, the encryption envelope underneath |
| RFC 9292 | Proposed Standard | 2022-08 | Binary HTTP, the payload RFC 9458 encapsulates |
| RFC 9000 | Proposed Standard | 2021-05 | sec. 16 variable-length integers, used by every Binary HTTP length |
| RFC 9113 | Proposed Standard | 2022-06 | sec. 8.2.1 field validity, which Binary HTTP decoding applies |

### Errata watch

- RFC 9180 carries 6 verified errata: read them before writing or depending on an HPKE layer. Erratum 7121 (Appendix A secret keys are printed unclamped for X25519) is handled in `crypto`, and the test vectors run with both forms.
- RFC 9458 Appendix A prints `Content-Length: 78` for an 80-octet encapsulated request and `38` for a 35-octet response (erratum 7781, reported). The octets are right and the lengths are wrong; do not copy either header.
- RFC 9540 defines the SVCB keys that identify an oblivious gateway, so discovery and the message layer cannot be built independently.

## Module layout

| Module | Responsibility |
|---|---|
| `message` | encapsulated request and response formats (RFC 9458) |
| `keys` | key configurations, identifier, generation and rotation (RFC 9458) |
| `client` | encapsulate, send, de-encapsulate (RFC 9458) |
| `gateway` | the relay: forward without reading, and what that forbids (RFC 9458) |
| `responder` | de-encapsulate, answer, re-encapsulate (RFC 9458) |
| `svcb` | oblivious gateway discovery via HTTPS and SVCB records (RFC 9540) |
| `crypto` | HPKE base mode on `cryptography`'s X25519, HKDF-Expand and AEADs (RFC 9180) |
| `bhttp` | Binary HTTP known-length codec (RFC 9292) |
| `errors` | the exceptions raised on input the library refuses |

## Dependency

One runtime dependency, `cryptography`, for X25519, HKDF-Expand, AES-GCM and ChaCha20-Poly1305. The
standard library cannot do any of them. `cryptography` 47 and later include an HPKE module, but it
offers only single-shot encrypt and decrypt with no `Export` and no way to fix the ephemeral key,
and RFC 9458 needs both, so the HPKE key schedule is written here (see `docs/strategy.md`).

## What it does not do

- a general HTTP client: bring httpx and hand it a transport
- OHTTP-KEM and other draft-stage variants still moving under the IETF
- an anonymity network: one honest component is enough by design, two colluding ones are not


## Install

```bash
git clone https://github.com/b1tninja/ohttp.git
cd ohttp
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy ohttp tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
