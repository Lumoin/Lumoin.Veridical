# Security policy

Lumoin.Veridical is a from-scratch .NET cryptography library (zero-knowledge proof systems, polynomial
commitments, folding, BBS selective-disclosure signatures, and SECDSA split-ECDSA sole-control signing). This
document states how to report a vulnerability and the security posture you can — and cannot — assume from the
current code.

> **Maturity.** This is an early (`0.0.x`) version under active development; public APIs may change between
> versions, and the library has **not** undergone an independent third-party security audit. Treat it
> accordingly for production use.

## Reporting a vulnerability

Please report suspected security vulnerabilities **privately** through
[GitHub security advisories](https://github.com/Lumoin/Lumoin.Veridical/security/advisories), **not** through
public issues, pull requests, or discussions. Include enough detail to reproduce the issue (affected package
and version, a minimal example, and the impact you observed). We will acknowledge the report and coordinate a
fix and disclosure timeline with you.

## Side-channel and constant-time posture

The library applies a **best-effort, managed-code constant-time discipline** to the secret-bearing arithmetic
paths, and is explicit about its limits.

- **What is defended.** The accelerated field and scalar backends are written without secret-dependent control
  flow: loop bounds are fixed by the limb count, conditional reductions use branch-free select masks rather
  than `if`, there is no secret-indexed table lookup, and the modular inversions are fixed-exponent ladders
  (Fermat over a *public* exponent), not data-dependent. In particular, NIST P-256 **scalar** arithmetic mod
  the group order `n` — the field SECDSA and ECDSA sign in — runs through a constant-time Montgomery backend
  (`P256ScalarMontgomeryBackend`), so signing does not branch on the nonce, the PIN-key, or the hardware-key
  blinds.
- **The honest limit.** This is *best-effort constant-time in managed code*, **not** a hardware-guaranteed
  constant-time bound. .NET does not guarantee that a value-selecting expression (`cond ? ~0UL : 0UL`) compiles
  to a conditional move rather than a branch, and the JIT, GC, and platform may introduce timing variation
  outside the library's control. Where a guarantee must be absolute, a hardened native backend behind the
  existing delegate seams is the appropriate follow-on.
- **Reference backends are oracles, not production paths.** The `BigInteger`-based reference backends
  (`*BigIntegerScalarReference`, `*BigIntegerG1Reference`, …) are the correctness ground truth the production
  backends are agreement-tested against. `BigInteger` modular arithmetic is **variable-time**; do not select a
  reference backend for a secret-bearing operation in production.
- **Per-operation caveats travel with the code.** Individual files state where their constant-time guarantees
  begin and end (for example the SECDSA timing-hardening remarks and the `ConstantTimeComparison` helper);
  this document is the consolidated summary, not a replacement for those specifics.

## Memory handling of secret material

Field elements, scalars, group points, polynomials, and proofs are wrapped in pool-backed `SensitiveMemory`
types tagged with their algebraic role. Buffers are cleared on disposal before returning to the pool. There is
deliberately **no buffer-touching finalizer**: a missed `Dispose` orphans the pool slot (a bounded leak)
rather than risking a use-after-free against an in-flight span read. There are no static caches or hidden
global secret state in the cryptographic core.

## Scope

This repository is **WSCA-side cryptography only**: primitives and proof systems. Agent protocols, OID4VP, the
relying-party exchange, transport, and application orchestration are the application layer and live in other
repositories — they are out of scope here. Reports about cryptographic primitives, their implementations, the
memory model, or the constant-time posture are in scope; reports about how a *consuming* application wires
these primitives belong to that application's project.

## Cryptographic conformance

Where the library targets an external specification or reference implementation, byte-conformance is the
load-bearing gate: the IETF BBS draft Appendix A vectors, RFC 9380 hash-to-curve vectors, the platform
`System.Security.Cryptography` oracles for ECDSA/SHA-256, and byte-conformance to `google/longfellow-zk` for
the dual-field zero-knowledge stack. A change that would alter a proof's bytes is gated by those fixtures.
