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

## Proof-system soundness posture

The zero-knowledge proof systems (Spartan and the polynomial-commitment schemes it composes with —
Hyrax, Ligero, BaseFold/ZkBaseFold — plus the Bulletproofs range arguments and the relaxed-R1CS
folding chain) are non-interactive via the Fiat-Shamir transform over a `FiatShamirTranscript`. Their
soundness rests on assumptions a consumer must uphold:

- **The circuit or statement is fixed and agreed out of band.** Fiat-Shamir soundness for these
  arguments assumes the constraint system (R1CS matrices, verifying key, code parameters) is fixed
  before any challenge is drawn; the transcript binds the *witness-dependent* prover messages, not the
  circuit definition. A verifier must obtain the circuit and the verifying key from a trusted channel,
  not from the prover alongside the proof. This is the standard fixed-circuit assumption; the library
  does not implement a stronger "unbound" Fiat-Shamir variant (which has known counterexamples).
- **The polynomial-commitment opening sub-protocols bind the statement through the caller's
  transcript, not their own.** The evaluation point, the claimed value, and any weighting travel into
  the inner-product and BaseFold opening arguments through the enclosing protocol's transcript (as
  masked Spartan does), which is where the composed proof binds them. A consumer that wires a
  commitment scheme's opening delegate *standalone* — outside a protocol that has already absorbed the
  statement into the shared transcript — must absorb the evaluation point and claimed value itself
  before invoking the opening. The delegate surface does not enforce this; it is the caller's
  obligation, documented on the delegate types.
- **Proof bytes are not canonicalized end to end, so proof-byte identity is not a uniqueness
  primitive.** Field-element inputs read from *external* sources (the Circom / ZkInterface R1CS and
  witness readers) are rejected at deserialization if they encode an integer at or above the
  scalar-field order, and a sumcheck round-polynomial coefficient at or above the order is rejected
  when the polynomial is reconstructed — at proof deserialization for BaseFold, and during
  verification for Spartan, where it makes the verifier return `false`. The remaining scalar sections
  of a
  proof container (for example the Spartan opening responses and the Bulletproofs inner-product
  scalars) are reduced modulo the order by the arithmetic backends rather than rejected, so a valid
  proof admits a second, byte-distinct encoding that still verifies. This is a proof-*byte*
  malleability, not a soundness break — the accepted statement is unchanged — but a consumer must not
  treat a proof's byte identity (or its hash) as a deduplication, anti-replay, or nullifier key. Bind
  such keys to the statement or a canonical semantic digest instead.

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

### Longfellow upstream pin

The `draft-google-cfrg-libzk` Internet-Draft is expired (`-01` is the latest revision; not adopted by CFRG),
so the `google/longfellow-zk` repository is the de-facto specification. The committed Longfellow fixtures are
pinned to upstream commit `d8ad8f65187c7c364a3c2181ad484bcab03f0ec2` (`v0.9-90-gd8ad8f6`, 2026-05-29 — also
the upstream `main` HEAD as of 2026-07-09) and to the circuit generation the upstream `kZkSpecs` table names
`longfellow-libzk-v1` version 7 (the pinned mdoc bundle: one disclosed attribute, `block_enc` 4151/4096,
Ligero rate 7 with 132 opened columns, 40 SHA-256 blocks of MSO capacity). Two identity subtleties are
deliberate:

- **The raw circuit bytes are the identity; the published circuit hash is a registry key.** The `kZkSpecs`
  `circuit_hash` (`8d079211…` for the pinned bundle) is the SHA-256 of the canonical 2026-01-09 zstd
  compression, which zstd does not reproduce across builds — neither upstream's own in-tree blob nor any
  other public artifact hashes to it. The committed fixture pins the decompressed raw stream
  (`raw_rawsha 332e3a96…`, asserted on every read), which is byte-identical to the decompression of
  upstream's canonical in-tree blob (verified 2026-07-09). Proof envelopes carry the registry-key hash only
  as a circuit-lookup identifier; the Fiat-Shamir transcript binds the structural circuit ids inside the
  raw stream.
- **Re-pin tripwires.** An upstream release newer than `v0.9`, a `kZkSpecs` table change (a new circuit
  version or changed hashes), or a normative `docs/specs` change that alters transcript or wire bytes each
  trigger re-verification of the Longfellow fixtures against the new upstream state before any claim of
  conformance to it. The per-fixture provenance inventory lives at
  `test/Lumoin.Veridical.Tests/TestMaterial/Longfellow/PROVENANCE.md`.

### BBS extension drafts (blind signatures, per-verifier pseudonyms)

The BBS extension surfaces implement moving IETF drafts and are pinned to specific revisions:
`draft-irtf-cfrg-bbs-blind-signatures-03` and `draft-irtf-cfrg-bbs-per-verifier-linkability-03`, both
normatively referencing core `draft-irtf-cfrg-bbs-signatures-10`. The Interface identifiers (api_ids) are
draft-versioned by construction — every generator, domain separation tag, and challenge derives from them —
so artifacts produced under these revisions will not silently interoperate with a future revision that
changes the semantics; a mismatch is a hard verification failure.

- **Fixture status.** The blind commitment surface is KAT-gated on the still-valid `-02` commitment vectors
  (textually identical in `-03`); the pseudonym surfaces are KAT-gated on the nym `-03` vectors, which also
  transitively byte-anchor the blind signing machinery. The blind `-03` **proof wire surface (the framed
  proof with committed disclosure) has no published test vectors** (draft §10: fixtures are being regenerated)
  — it is gated by self-consistency roundtrips and tamper suites, and the draft-defect interpretation choices
  are marked as fixture-pending at their decision sites in code. Also fixture-pending, and the highest-risk
  unpinned byte choice of the batch, is the **blind interface's `e`-scalar derivation**: `BlindSign` follows
  the blind `-03` text and binds the domain into `e` (`serialize((SK, B, domain))`), while the pseudonym
  interface pins the domain-free `serialize((SK, B))` form that the nym `-03` vectors byte-anchor (see
  `BbsBlindAlgorithm.DeriveBlindSigningScalar`); if the regenerated blind fixtures pin the domain-free form,
  every blind signature and blind proof byte changes. **Re-KAT tripwires:** a core `-11` revision,
  the blind draft's regenerated fixtures, and a nym `-04` revision each trigger re-verification of the
  corresponding byte surfaces before any claim of conformance to the new revision.
- **Pseudonym unlinkability budget.** The per-verifier pseudonym construction offers *limited everlasting*
  unlinkability: with a `nym_secrets` vector of length `N`, pseudonyms stay unlinkable — even against a
  cryptographically-relevant quantum computer breaking discrete log — only while the number of distinct
  verifier contexts used, `M`, satisfies `N > M`. Applications wanting everlasting unlinkability must size
  the prover-nym vector for the expected number of contexts; exceeding the budget degrades to computational
  unlinkability only.
- **Prover-side secrets.** `secret_prover_blind` (returned by `Commit`) and the `add_zkp_info` openings
  returned by blind proof generation (`BbsBlindProofCommitmentOpenings`: the committed-disclosure commitments
  paired with their Pedersen randomness) MUST remain with the prover. Neither is ever serialized by this
  library, and neither may be sent to a verifier or any other party — leaking them collapses the hiding of
  the committed messages that blind issuance and committed disclosure exist to provide.
