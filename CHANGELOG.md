# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

- Key configuration codec (RFC 9458 sec. 3), Binary HTTP known-length codec (RFC 9292), HPKE base mode
  on `cryptography` primitives (RFC 9180), and request and response encapsulation (RFC 9458 sec. 4),
  all checked against RFC 9458 Appendix A and RFC 9180 Appendix A.1 and A.2.
- Runtime dependency `cryptography>=42`; the planned `hpke` extra is dropped.
- Still stubs: `gateway.relay`, `client.request`, `svcb.select_gateway`. See [ROADMAP.md](ROADMAP.md).

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for ohttp.
- `ohttp.apps` namespace reserved for composition that is not protocol behaviour.
