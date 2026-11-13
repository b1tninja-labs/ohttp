# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 9458 | Proposed Standard | 2024-01 | 2026-11-05 |
| RFC 9540 | Proposed Standard | 2024-02 | 2026-11-05 |
| RFC 9230 | Experimental | 2022-06 | 2026-11-05 |
| RFC 9180 | IRTF Informational | 2022-02 | 2026-11-05 |
| RFC 9292 | Proposed Standard | 2022-08 | 2026-11-13 |
| RFC 9000 | Proposed Standard | 2021-05 | 2026-11-13 |
| RFC 9113 | Proposed Standard | 2022-06 | 2026-11-13 |
| RFC 9460 | Proposed Standard | 2023-11 | 2026-11-13 |
| RFC 7748 | Informational (IRTF) | 2016-01 | 2026-11-13 |
| RFC 5869 | Informational | 2010-05 | 2026-11-13 |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.

## Errata and status, read through rfclib on 2026-11-13

| Document | Errata | Effect here |
|---|---|---|
| RFC 9458 | 7781 reported (not verified): Appendix A response `Content-Length: 38` for a 35-octet body | Octets are right. Not an erratum on file: the request example prints `Content-Length: 78` for an 80-octet encapsulated request (7 + 32 + 25 + 16). Both lengths are asserted correctly in `tests/test_message.py`; neither header is copied. |
| RFC 9180 | 6 verified, 2 held. 7121 (Appendix A skEm/skRm printed unclamped for X25519), 7934, 7937, 6941, 7790, 7932; held 7251, 7933 | 7121: `crypto` clamps keys it serialises (sec. 7.1.2), and the Appendix A.1/A.2 vectors run with the printed and the clamped skEm, which must agree. 7937 and 7934 concern DeriveKeyPair, which is not implemented (no row needs it). 7251 (held): info and psk limit of 66 rather than 64 is moot for base mode. |
| RFC 9292 | 8559 held for document update: HTTP/2 malformed-message rule should name field names as well as values | `bhttp` rejects uppercase and other invalid names, which is the corrected reading. |
| RFC 9230 | 1 on file | Oblivious DoH is a separate Experimental protocol (independent stream) with its own message format. It is not "the DNS variant" of RFC 9458, and nothing here implements it. |
| RFC 9460 | 3 on file | Not read yet. Needed by the `svcb` row (RFC 9540 sec. 4 is an SvcParamKey of it). |
| RFC 7748 | 4 verified (4730, 5028, 7095, 7625: Montgomery base point v, wording, notation) | None affect X25519 as used here; the arithmetic is `cryptography`'s. |
| RFC 5869 | 0 verified (1 on file) | HKDF-Extract is stdlib HMAC and Expand is `cryptography`'s `HKDFExpand`. |

## Where the cryptographic primitives come from

Reads of 2026-11-13: RFC 9292 sec. 3.2 to 3.8 and sec. 5 (indeterminate length; Figures 9 and 11 are test vectors), RFC 9458 sec. 4.5, sec. 5 (5.1 to 5.3), sec. 6 (in full), sec. 9.1 to 9.3, RFC 9180 sec. 7.1 and appendix A.3 (the P-256 vector). RFC 9458 has 1 erratum on file (7781, reported), RFC 9292 1 (8559, held), RFC 9180 6 verified and 2 held, rechecked the same day.

RFC 9180 HPKE base mode is written in `ohttp/crypto.py` on `cryptography`'s X25519, `HKDFExpand`,
`AESGCM` and `ChaCha20Poly1305`. `cryptography` 47.0.0 (2026-04-24) added
`cryptography.hazmat.primitives.hpke` (documented at
<https://cryptography.io/en/latest/hazmat/primitives/hpke/>) with `Suite.encrypt` and
`Suite.decrypt` only: a fresh ephemeral key per call, no `Export`, no way to inject the ephemeral
key. RFC 9458 sec. 4.4 calls `context.Export`, so that module cannot carry OHTTP; and the installed
version here is 46.0.7, which has no HPKE module at all.
