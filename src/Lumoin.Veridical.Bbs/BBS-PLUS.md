# BBS+ on BLS12-381

This document describes the BBS+ multi-message signature scheme as
implemented in `Lumoin.Veridical.Bbs`. It is written for someone
who has read the code and wants the algebraic shape made explicit;
the IETF draft `draft-irtf-cfrg-bbs-signatures-10` is the wire-
format authority.

## § 1 Protocol overview

BBS+ is a multi-message digital signature scheme: a signer's secret
key produces a single signature `(A, e)` over a vector of `L`
application messages plus a contextual `header`. The signature is
80 bytes (a 48-byte G1 point and a 32-byte scalar), independent of
how many messages it covers.

What distinguishes BBS+ from one-message signatures (ECDSA, Ed25519)
is selective disclosure: a holder of a signature can produce a
zero-knowledge proof that they hold a valid signature over `L`
messages while revealing only some of them. The verifier learns
the revealed messages and learns that the prover knows a signature
over both the revealed and the hidden ones — but learns nothing
about the hidden messages or the underlying signature.

This sub-batch ships the proof half (GenerateProof / VerifyProof)
alongside KeyGen, Sign, and Verify from the prior sub-batch. The
proof byte length is variable: `272 + 32 · U` bytes where `U` is
the number of undisclosed messages, ranging from 272 bytes when
every message is disclosed up to 272 plus 32 bytes per hidden
message otherwise.

## § 2 Operations

The five operations the library currently exposes.

**KeyGen** lives on `BbsCiphersuite` as the receiver. The signer's
secret key is a scalar `SK` in the BLS12-381 scalar field; the
public key is the G2 point `PK = SK · BP2` where `BP2` is the G2
base point. `SK` is derived deterministically from a secret
`key_material` (entropy source, ≥ 32 bytes) and an optional
`key_info` (a domain-separation string that lets the same entropy
material derive multiple keys) per IETF Section 3.4.1.

**Sign** lives on `BbsSecretKey`. Sign produces `(A, e)` over a
`header` and `L` messages. Sign is deterministic: the same inputs
always produce the same signature, which is a desirable property
for testing and a reasonable property for cryptography given the
care taken in deriving `e` from the entropy of `SK`. The algorithm
is IETF Section 3.5.1 (Sign) ↦ 3.6.1 (CoreSign).

**Verify** lives on `BbsPublicKey`. Verify returns a `bool`; it
does not throw on malformed inputs (a tampered signature simply
returns `false`). The algorithm is IETF Section 3.5.2 (Verify) ↦
3.6.2 (CoreVerify).

**GenerateProof** lives on `BbsSignature`. Given the signature,
the public key, the header, a presentation header, the full
message vector, and a subset of indices to disclose, it produces
a `BbsProof` proving knowledge of a valid signature over all
messages while revealing only those at the disclosed indices. The
algorithm is IETF Section 3.5.3 (ProofGen) ↦ 3.6.3 (CoreProofGen),
with the proof subroutines `ProofInit` (3.7.1), `ProofFinalize`
(3.7.2), and `ProofChallengeCalculate` (3.7.4). Each call consumes
`5 + U` random scalars from the supplied `ScalarRandomDelegate`;
two calls with identical inputs but different randomness produce
byte-different proofs that both verify — this is the unlinkability
foundation.

**VerifyProof** lives on `BbsPublicKey`. Given a proof, the
header, the presentation header, the disclosed messages, and the
disclosed indices, it returns `bool`. The proof's
`UndisclosedMessageCount` plus `disclosedIndices.Length` gives the
total message vector length; the verifier does not pass that
length separately. As with `Verify`, malformed proof bytes return
`false` rather than throwing. The algorithm is IETF Section 3.5.4
(ProofVerify) ↦ 3.6.4 (CoreProofVerify) with the
`ProofVerifyInit` subroutine (3.7.3).

### Decode-error contract

`Verify` and `VerifyProof` are exception-safe for malformed
canonical bytes. Both `ArgumentException` (length mismatches,
count inconsistencies) and `InvalidOperationException`
(algebraic-structure failures: off-curve points, wrong subgroup,
non-canonical scalars surfaced by the backend during MSM or
pairing) are caught at the operation boundary and translated to a
`false` return. Callers may rely on this: malformed inputs do not
propagate exceptions out of the verify operations. A future
maintainer working in `BbsVerificationExtensions` or
`BbsProofVerificationExtensions` must keep both clauses — narrowing
to `ArgumentException` only would break the contract for length-
valid-but-algebraically-invalid inputs.

`KeyGen`, `Sign`, and `GenerateProof` are not exception-safe in
this way. They throw `ArgumentException` on invalid arguments,
since invalid producer inputs are caller bugs, not protocol-level
invalid data, and surfacing them as exceptions is the right
default at that boundary.

### Deserialization validation

`Verify`, `VerifyProof`, and `GenerateProof` validate every
deserialized point per the IETF deserialization procedures before
using it: `octets_to_signature` (Section 4.2.4.3) for the signature
point `A`, `octets_to_proof` (Section 4.2.4.5) for the proof points
`Abar`, `Bbar`, and `D`, and `octets_to_pubkey` (Section 4.2.4.6,
whose steps 2 to 5 are the public-key validity check) for the public
key `W`. Each point must decode onto
its curve, must not be the identity, and must lie in the
prime-order subgroup; scalar canonicity (range and non-zero) is
enforced earlier, at container construction. Both BLS12-381 groups
have non-trivial cofactors, so an on-curve point is not
automatically a subgroup member.

`GenerateProof` validates the Prover's own signature rather than
trusting the Signer: an `A` outside the prime-order subgroup
carries a cofactor component that survives blinding into `Abar`
and `Bbar`, handing a malicious Signer a covert channel that
breaks proof unlinkability. The verifier surfaces reject the same
inputs with a `false` return per the decode-error contract above.

The validation predicates travel as backend delegates
(`G1IsOnCurveDelegate`, `G1IsInPrimeOrderSubgroupDelegate`, and
their G2 counterparts) alongside the arithmetic delegates. The
reference subgroup check is `[r] P == O` by a full scalar
multiplication per point; endomorphism-based acceleration
(Bowe 19 / Scott 21) is a known deferred-performance item under
the project's correctness-first rule. The checks run on public
data only, so they carry no constant-time requirement.

## § 3 Ciphersuites

Two ciphersuites are shipping, per IETF Sections 7.2.1 and 7.2.2:

| Ciphersuite            | api_id                                                  | expand_message      | hash      |
|------------------------|---------------------------------------------------------|---------------------|-----------|
| BLS12-381-SHAKE-256    | `BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_`        | `expand_message_xof` | SHAKE-256 |
| BLS12-381-SHA-256      | `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_`          | `expand_message_xmd` | SHA-256   |

Both share BLS12-381 group arithmetic, pairing, and the
RFC 9380 SSWU + 11-isogeny + h_eff cofactor hash-to-curve
pipeline; they differ only in the hash and the `expand_message`
variant (RFC 9380 §5.3.1 for XMD; §5.3.2 for XOF).

The api_id decomposes as `ciphersuite_id || "H2G_HM2S_"` where
`ciphersuite_id` names the RFC 9380 hash-to-curve suite and
`"H2G_HM2S_"` names the BBS+ Interface (create_generators and
messages_to_scalars per Sections 4.1 and 4.2).

Every per-operation domain-separation tag is the api_id
concatenated with an ASCII suffix listed in
`WellKnownBbsDomainSeparationTags`:

| Operation                  | DST suffix                       |
|----------------------------|----------------------------------|
| KeyGen                     | `KEYGEN_DST_`                    |
| hash_to_scalar (Sign's `e`, CoreVerify's `domain`, ProofChallengeCalculate) | `H2S_`                           |
| messages_to_scalars        | `MAP_MSG_TO_SCALAR_AS_HASH_`     |
| create_generators (seed)   | `SIG_GENERATOR_SEED_`            |
| create_generators (output) | `SIG_GENERATOR_DST_`             |
| initial generator seed     | `MESSAGE_GENERATOR_SEED` (no trailing underscore) |

The DST suffixes are ciphersuite-agnostic (the same suffix bytes
work for both); only the api_id prefix differs per ciphersuite.

**Ciphersuites are not interoperable.** A signature or proof
produced under one ciphersuite does not verify under the other —
the verifier reconstructs different message scalars, a different
domain, and different generators, so the pairing equation cannot
match. Selecting between the two ciphersuites is an
application-level decision: SHA-256 is the most widely deployed
choice; SHAKE-256 is the right pick for environments with a
SHA-3 dependency already wired or for new applications that
prefer the XOF construction.

## § 4 Wire format

| Object        | Bytes        | Layout                                              |
|---------------|--------------|-----------------------------------------------------|
| Secret key    | 32           | Canonical big-endian BLS12-381 scalar < r           |
| Public key    | 96           | Canonical compressed G2 point                       |
| Signature     | 80           | `A` (48-byte compressed G1) ‖ `e` (32-byte scalar)  |
| Proof         | `272 + 32·U` | `Abar` ‖ `Bbar` ‖ `D` (3 G1 points = 144 bytes) ‖ `e^` ‖ `r1^` ‖ `r3^` (3 scalars = 96 bytes) ‖ `m^_j1`…`m^_jU` (U scalars) ‖ `c` (32-byte challenge scalar) |

`U = UndisclosedMessageCount`. The proof's byte length is recovered
from the buffer length per the spec's `octets_to_proof`
deserialisation (`U = (length - 272) / 32`); the count is not
stored separately.

The `Bls12Curve381Sha256` constant in `WellKnownBbsCiphersuites` and
`BbsCiphersuite` uses underscores in place of the IETF spec's
hyphens because hyphens are not valid in C# identifiers; the
underscores are load-bearing for matching the spec, suppressed
analyser warnings notwithstanding.

## § 5 IETF interoperability

The IETF Appendix A test vectors are the load-bearing
interoperability gate at every layer, for both ciphersuites:

- **KeyGen** — byte-identical secret key and public key output for
  the canonical key-derivation inputs.
- **Sign** — byte-identical 80-byte signature output for all
  valid (signer, header, messages) vectors; deterministic-Sign
  guarantees no randomness in this direction.
- **Verify** — byte-identical `bool` result (`true` for valid
  vectors, `false` for tampered/wrong-key vectors).
- **GenerateProof** — byte-identical proof output for all valid
  vectors *when fed the mocked random-scalar source* defined in
  IETF Section 7.4 (Mocked Random Scalars). The mocked source
  expands a canonical SEED (hex encoding of "3.14159…" — the
  first 30 digits of π) through the ciphersuite's
  `expand_message` variant with a ciphersuite-specific DST and
  reduces each 48-byte chunk modulo the scalar field order.
- **VerifyProof** — byte-identical `bool` result for all vectors,
  whether the case is constructed as valid or as one of the
  invalid presentations (different presentation header, wrong
  public key).

SHA-256 ships 1 KeyGen + 10 signature + 5 proof vectors;
SHAKE-256 ships 1 KeyGen + 3 signature + 3 proof vectors covering
single-message, multi-message, and one negative case in each
shape. Per-primitive auxiliary coverage also lands for both
ciphersuites — one vector each for `hash_to_scalar`,
`messages_to_scalars` (10 cases per vector), generator derivation
(`P_1` plus `Q_1` and 10 message generators), and the mocked
random-scalars source (10-scalar sequence). The auxiliary
primitives exercise each underlying operation in isolation so a
regression there pinpoints the broken primitive directly instead
of leaving a multi-step Sign or VerifyProof byte diff to debug.

The vectors live as typed C# constants under
`test/Lumoin.Veridical.Tests/Bbs/IetfVectors/` (one file per
ciphersuite per operation, with `Sha256/` and `Shake256/`
sub-directories). Per-primitive test classes live under
`test/Lumoin.Veridical.Tests/Bbs/Primitives/`. Tests consume the
vectors via `[DynamicData]` reading from each class's `All`
static.

Note that draft-irtf-cfrg-bbs-signatures-10 publishes only a
subset of these cases as formal Appendix A subsections (the first
two signature cases and the first three proof cases per
ciphersuite, plus the auxiliary primitives). The remaining
vectors exercise additional invalid and edge cases beyond what
the draft formalises; this library adopts the broader set to
maximise interop coverage.

Production callers of `GenerateProof` wire any
`ScalarRandomDelegate` of their choice; only the test surface uses
the mocked source. See `MockedRandomScalars.cs` in the BBS+ test
project.

## § 6 Test data and mocked randomness

### Mocked-RNG vs production RNG

The `MockedRandomScalars.FromSeed` helper produces a deterministic
scalar sequence from a fixed seed; it is the test-side
`ScalarRandomDelegate` used to reproduce IETF Appendix A proof
vectors byte-for-byte. Production callers pass a different
delegate backed by the OS RNG. The two have the same delegate
signature but different semantics: production calls are stateless
and order-independent, while the mocked variant carries implicit
per-instance call ordering via captured state (a `Counter` that
advances on each call into the precomputed sequence). Test code
that constructs proofs is sensitive to that call order;
production code is not. The asymmetry is a property of the test
setup, not a property of the delegate type — both halves of BBS+
proof generation (`ProofInit`'s `5 + U` scalar draws) consume the
sequence in the same fixed order on the test side and any order
on the production side.

## § 7 Closed

`Lumoin.Veridical.Bbs` ships at the closing commit of sub-batch
BBS+.3 with both ciphersuites byte-faithful against the canonical
upstream fixtures, the full per-primitive auxiliary coverage in
place, and the architectural friction items from BBS+.2 (pool-
renting and the symmetric verify catch) resolved. The library is
ready for consumption by higher-level credential or proof systems.

Future BBS+ work is independent of this shipped surface:
additional ciphersuites, performance work (multi-pairing,
compressed G_T, accelerated G_1/G_2 backends, the batched-MSM
delegate refactor), the managed BLAKE3 backend if a third
ciphersuite needs it, and the `MockedRandomScalars` terminology
review the reviewer has flagged for a later batch each belong to
their own sub-batches.
