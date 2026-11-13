# Strategy

The completeness matrix is [../ROADMAP.md](../ROADMAP.md). This document is *why* the rows
are ordered the way they are, and the rules that order has to respect.

## The constitution

1. **The core is the specification implementation.** `ohttp/` holds codecs, state machines
   and the vocabulary of ohttp. New core code appears when a document defines the
   behaviour, or when an ordering rule with no document earns an explicit convention label.
2. **Sans-IO before sockets.** Anything decidable from data plus a clock is implemented
   without touching a socket, so every timeout, retry and rollover is testable without
   sleeping or networking.
3. **Dependency-free by default.** An exception needs a sentence in README.md explaining why
   the rule was broken, and a floor with no ceiling. The one exception is `cryptography>=42`,
   for X25519, HKDF-Expand, AES-GCM and ChaCha20-Poly1305, which the standard library lacks
   (measured: `hashlib` has no AEAD and `ssl` exposes none). It is a floor, and the HPKE key
   schedule, Binary HTTP and the codecs stay ours. `cryptography` 47.0.0 (2026-04-24) added
   `cryptography.hazmat.primitives.hpke`, but its documented surface is `Suite.encrypt` and
   `Suite.decrypt`, single-shot, with a fresh ephemeral key per call and no `Export`; RFC 9458
   sec. 4.4 needs `Export` and Appendix A needs a fixed ephemeral key, so it cannot carry this
   protocol. The earlier plan of an `hpke` extra on the PyPI `hpke` package is withdrawn.
4. **Positioning is correctness and legibility, not throughput.** The incumbents in this
   corner are usually stale, untyped, or welded to a product. This is the implementation that
   says how it knows what it claims.
5. **Every answer carries its provenance.** Verified or cached, which document, refused or
   believed. An answer without provenance is a guess with a confident type.

## The three tiers

| Tier | Home | Contents | Rule |
|---|---|---|---|
| Core | `ohttp/` | codecs, state machines, policy objects | RFC-cited or convention-labelled |
| Apps | `ohttp/apps/` | reusable assemblies that compose core | no new protocol surface |
| Examples | `examples/` | one runnable script per use case | configures; never restates logic |

## Interface grammar

One engine, three drives, never parallel implementations:

- **await** -- the native asyncio surface.
- **blocking** -- a facade owning a private loop, so a call from inside a caller's running
  loop works instead of deadlocking.
- **callback** -- plain callables, no third-party promise type.

## Naming

One string everywhere: the distribution, the import and the console script. A name that
means one thing in the installer, in `import` and on `PATH` is the only arrangement that
cannot surprise anyone, and it is also why this project does not sit one edit away from a
project that already exists.
