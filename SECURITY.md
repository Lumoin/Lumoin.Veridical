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

The pool (`Lumoin.Base`) distinguishes three allocation kinds by algebraic role, and the code chooses the
kind where a buffer is rented. Public structure (wire-index arenas, public coefficients, the fixed constant
basis) is `Managed` — ordinary relocatable heap. Bulk secret-bearing regions — the witness and scalar
arenas that carry ECDSA nonce coordinates, the Ligero and Longfellow tableaux, the proof pad, per-leaf
Merkle blinding nonces — are `Pinned`, allocated through `GC.AllocateArray(pinned: true)` on the pinned
object heap so a compacting collection never relocates them; the wipe-on-return then erases the exact bytes
that held the secret. Small, long-lived key material (the BBS secret key) is `Native`. Clearing on return
uses a non-elidable zeroization (`CryptographicOperations.ZeroMemory`, never `Span.Clear`), and slabs are
reused across rentals, so the zero-on-return is what prevents a later renter from observing a prior
renter's bytes. The pinnedness and the wipe are exercised as an explicit behavioral regression test, not
merely assumed.

The `Native` kind is backed by an injected OS allocator, so its guarantee is the deployment's to wire, not
the library's to assume. When a consumer constructs the pool with the libsodium backing
(`Lumoin.Base.Sodium`, `new BaseMemoryPool(nativeBacking: SodiumBacking.Allocate)`), every `Native` rent
becomes a `sodium_malloc` guarded allocation: **best-effort memory locking** (`mlock`/`VirtualLock`, so the
pages resist being swapped to disk), no-access **guard pages** bracketing the buffer (an overflow crashes
immediately), a **canary** checked at free (a small underflow aborts the process), and zero-on-free. The
pool is strict by default — with no native backing wired it throws on a `Native` rent, unless constructed
`allowNativeDegradation: true`, which falls back to `Pinned` on hosts (browser, mobile, unconfigured
servers) where a native lock is unavailable, and records the effective kind in telemetry. The library
itself stays allocator-agnostic: it threads the pool from the top and never names a concrete native
allocator, so which protection the key material actually receives is a property of how the consuming
deployment builds the pool.

**Residual risk (what remains after the tiers above).** The relocation-erase gap is closed for `Pinned`
and `Native` secrets, and paging is closed for `Native` secrets when the libsodium backing is wired
(best-effort locking, subject to the platform's locked-memory limit). What is **not** closed: the bulk
`Pinned` witness and tableau arenas are on the managed pinned heap, which is not locked, so a host under
memory pressure may still swap them; register and stack spills, where the JIT may leave a copy of a secret
scalar in a spill slot or a caller-saved register that no clear touches; a live-process memory dump or a
debugger with process access, which sees any secret while it is legitimately in use; and side-channel
observation of the secret's *use*, which is the constant-time posture's concern above, not this section's.
A deployment that must resist a hostile host or a memory-dump adversary across *all* secret material — not
only the locked key tier — needs OS- or hardware-level protection (an HSM, a `CKM_*` key that never leaves
the module, encrypted swap, memory encryption). The library provides the WSCA-side mathematics such a
deployment assumes and the allocation seams to wire that protection into, not the host hardening itself.

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
- **Vector commitments are position-binding at a fixed depth, not by leaf/internal domain separation.**
  The binary Merkle trees the commitment schemes use (the BaseFold codeword trees, the Ligero and
  Longfellow column trees, the Poseidon-ready set commitment) apply **no domain separation between leaf
  and internal-node hashing** — every internal node is the two-to-one compression of its children, and
  the leaves are pre-hashed values (a codeword position, a salted `hash(value‖salt)`, a `hash(key‖value)`
  entry, or a `hash(nonce‖column)`). This is sound for two independent reasons, both of which the analysis
  in "The Billion Dollar Merkle Tree" (Coratger, Khovratovich, Mennink, Wagner, IACR ePrint 2026/089)
  makes precise: the wired compression is a **collision-resistant** hash (BLAKE3-32 or SHA-256), so a leaf
  digest cannot collide with an internal digest; and the tree **depth is fixed** and the verifier folds
  exactly the authentication-path length, binding a leaf to its position so that a leaf and an internal
  node never occupy interchangeable slots. A leaf index carrying a bit at or beyond the path length is
  rejected rather than silently aliased onto its in-range counterpart. If a future wiring substitutes a
  **truncated algebraic compression** (a native Poseidon shadow root), that compression is not
  collision-resistant and position binding then rests on the eprint 2026/089 argument — the leaf
  pre-hashing that argument requires is already in place and must be preserved.

## Post-quantum posture

The library mixes proof systems and signatures with different post-quantum standing. This ledger states
where each path stands against a quantum adversary; none of it changes the classical soundness above.

- **Plausibly post-quantum (in the random-oracle model): the hash-committed argument stack.** Spartan
  composed over BaseFold or ZkBaseFold — and WHIR when it lands — rests on the collision resistance of the
  wired hash and the Fiat-Shamir random oracle, with no discrete-logarithm or pairing assumption in the
  soundness argument. These are the paths to reach for when a consumer needs a plausibly quantum-resistant
  proof, subject to the usual caveats (a quantum random-oracle analysis, and hash output sizes chosen for
  the lower post-quantum collision bound).
- **Not post-quantum: the discrete-log paths.** Hyrax inner-product openings, the Bulletproofs range
  arguments, BBS+ signatures and proofs, and ECDSA/SECDSA all rest on discrete-logarithm hardness in a
  prime-order elliptic-curve group, which a cryptographically relevant quantum computer breaks. They are
  in the library because they are what the deployed EUDI and W3C ecosystems require today; their presence
  is a statement about current interoperability, not about long-term quantum resistance.
- **The SECDSA post-quantum transition is an application-layer and future-primitive concern, not new
  library crypto.** The SECDSA paper's Annex C describes a two-step PQC roadmap (no quantum-vulnerable
  data stored or exchanged, then none processed outside HSMs) with a modified blinding protocol, modified
  signing and evidence algorithms over the plain generator, and ICAO Chip-Authentication secure messaging
  with the certified Diffie-Hellman key replaced by **ML-KEM** (FIPS 203). The proof-of-knowledge shapes
  those variants use are the same discrete-log-equality statements `DlEqualityNizk` already proves and
  verifies over generic generator/target pairs, so the PQC variant needs **no new library crypto**; the
  genuinely new surfaces — an ML-KEM key encapsulation, the Chip-Authentication secure channel, and the
  seeded-hash internal-certificate records — are application-layer wiring or future primitives outside
  this repository's WSCA-side scope.

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
`longfellow-libzk-v1` version 7. Two registry rows are pinned: the one-attribute bundle (`block_enc`
4151/4096) and the four-attribute breadth bundle (`kZkSpecs[3]`, `block_enc` 4415/4096, sharing the
byte-identical signature circuit); both run Ligero rate 7 with 132 opened columns and 40 SHA-256 blocks of
MSO capacity, and both are carried as public `LongfellowMdocZkSpec` registry rows asserted against the
reference anchors by the default suite. Two identity subtleties are deliberate:

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

### SECDSA paper pin

SECDSA has no IETF/ISO specification; the specification is Verheul's paper *An HSM-based EUDI wallet using
Split-ECDSA (SECDSA) providing verifiable "sole control"* at https://wellet.nl/SECDSA-EUDI-wallet-latest.pdf —
a **rolling URL** whose content changes without the link changing. The implemented surfaces (`SecdsaAlgorithm`,
`DlEqualityNizk`, `SecdsaEvidence`, `EcdhMacAlgorithm`) are pinned to the revision **"Version 21 June 2026"** (verified 2026-07-09;
upstream keeps frozen copies only up to `…walletV6.pdf` of Sep 2025, so 2026 revisions exist solely under the
rolling URL). Within that revision the implemented algorithm map is: Algorithms 1/2 with Propositions 3.1/3.2
(key generation and split sign), Algorithms 14/15 with Proposition A.1 (verification and the full
representation), Algorithms 19/20 over statement (9) (the discrete-log-equality NIZK), the blinding relation of
Algorithm 3 step 7 / Algorithm 4 step 11, and the control relation of Equation (7) / Algorithms 9/10; the §4
split-key Algorithm 11 is realized by composing the two `SplitSign` entry points; Algorithms 16/17 with the §4
split variant Algorithm 12 (ECDH-MAC and Split-ECDH-MAC, `EcdhMacAlgorithm` over HKDF-SHA256 per RFC 5869).
Three standing caveats:

- **The paper pins no wire encoding for the NIZK transcript.** "Convert point to byte array" is left to the
  implementation, so no cross-implementation byte fixture is possible; this library's documented choice is
  33-byte SEC1 compressed points throughout the Fiat–Shamir transcript, with the challenge `r` carried
  full-width (never reduced) exactly as Algorithm 20's range check `r ∈ {1, 2^(8·|q|)−1}` requires. Nonce
  determinism (RFC 6979 for signing; a domain-separated statement digest for the NIZK commitment nonce) is a
  documented implementation choice the paper's "select random k" permits — wire bytes are unaffected.
- **ECDH-MAC has no published test vectors.** ISO/IEC 18013-5 §9.1.3.5 defines the primitive only implicitly
  and publishes no vectors, so conformance is gated in layers: RFC 5869 Appendix A KATs plus BCL `HKDF`
  cross-checks for the derivation stage, a full-pipeline independent oracle (the platform's raw-ECDH agreement
  + `HKDF` + `HMACSHA256` reproduces Algorithm 16 byte-for-byte), and the split-vs-direct agreement gate
  (Algorithm 12's three-share chain against a direct Algorithm 16 under the composed key, with the composition
  computed in the opposite operation order so the two paths are independent).
- **Re-diff tripwire.** A changed `Last-Modified`/version line on the rolling URL triggers a protocol re-diff
  against the implemented surfaces before any claim of conformance to the new revision (the 2026-07-09 pass is
  recorded in `tempdocs/W2.6-SECDSA-V2-DIFF.md`).

The paper frames "sole control" through the certification regime rather than new cryptography: CIR (EU)
2024/2981 wallet certification, the Common Criteria protection profiles EN 419221-5 (the wallet-provider HSM)
and EN 419241-2 (SCAL2 sole-control assurance for server signing), FIPS 140-3 mode constraints (FIPS mode
forbids the `CKD_NULL` derivation some building blocks use), and ISO/IEC 29115 — the ITU-T X.1254 twin text —
as the assurance framework behind eIDAS High. This library implements the WSCA-side mathematics those
certifications assume; PKCS#11/HSM integration and any certification obligations sit with the consuming
deployment, per the Scope section above.
