# Bulletproofs range proof

The codebase's logarithmic-size range gadget (Bünz, Bootle, Boneh, Poelstra,
Wuille, Maxwell, *Bulletproofs: Short Proofs for Confidential Transactions
and More*, IEEE S&P 2018): proves that a Pedersen-committed value `v` lies in
`[0, 2^n)` without revealing it. The intended consumer shape is "commitment
and proof as stored artifacts, value never published" — a selective-disclosure
predicate over a committed attribute (an age bound, a balance bound) where the
verifier learns only the range membership.

The family is built out in four layers, each a strict generalisation of the
last over the same `RangeProof` wire container and the same generator key:

| Layer | Type | Proves | Cost |
|-------|------|--------|------|
| Single (§4.2) | `BulletproofRange{Prover,Verifier}` | one value in `[0, 2^n)` | `2·log₂n + O(1)` proof |
| Aggregated (§4.3) | `AggregatedBulletproofRange{Prover,Verifier}` | `m` values, one proof | `2·log₂(nm) + O(1)` proof |
| Batched verify (§6.1) | `BatchBulletproofRangeVerifier` | `p` single-value proofs, one MSM | shared generators amortised |
| Batched aggregated | `BatchAggregatedBulletproofRangeVerifier` | `p` aggregated proofs, one MSM | shared generators amortised |

## The pieces

- **`RangeProofKey`** — the public key material: two independent generator
  families `G_0…G_{n−1}`, `H_0…H_{n−1}` (one slot per bit), the value
  generator `g`, the blinding generator `h`, and the inner-product generator
  `u`, all derived deterministically from a seed via RFC 9380 hash-to-curve
  (two domain-separated `HyraxCommitmentKey` derivations). Prover and
  verifier re-derive byte-identical keys from the same seed; nothing is
  transmitted. The key carries `CommitValue` (`V = v·g + γ·h`) and the
  prover-side range guard. Bit widths are powers of two in `[2, 64]` (the
  inner-product argument folds by halving).
- **`BulletproofRangeProver` / `BulletproofRangeVerifier`** — the protocol.
  Prover: bit-decomposition vectors `a_L, a_R = a_L − 1` committed with
  blinding (`A`), blinding vectors (`S`), challenges `y, z`, the `t(X)`
  coefficient commitments `T₁, T₂`, challenge `x`, then the revealed
  aggregates `τ_x, μ, t̂ = ⟨l, r⟩` and the two-vector inner-product argument
  on `(l, r)` over `(G, H′)` with `H′_i = y^{−i}·H_i`. Verifier: replays the
  schedule, checks `t̂·g + τ_x·h == z²·V + δ(y,z)·g + x·T₁ + x²·T₂` with
  `δ(y,z) = (z − z²)·⟨1, y^n⟩ − z³·⟨1, 2^n⟩`, rebuilds the reduced
  commitment with the `H′`-basis weights expressed directly on `H_i`
  (`w_i = z + z²·2^i·y^{−i}`), and verifies the inner-product argument.
  The verifier is exception-safe: malformed proof bytes reject, never throw.
- **`TwoVectorInnerProductArgument`** — Bulletproofs Protocol 2, the
  two-secret-vector sibling of the Hyrax opening's public-vector
  `InnerProductArgument`: proves `c = ⟨a, b⟩` against
  `P = ⟨a, G⟩ + ⟨b, H⟩ + c·U` in `log₂(n)` rounds of `(L, R)` cross terms.
  Blinding is handled by the range proof (it removes `μ·h` from `P` before
  the argument), exactly as Protocol 1 reduces to Protocol 2.
- **`RangeProof`** — the flat wire container: `A, S, T₁, T₂` (four points),
  `τ_x, μ, t̂` (three scalars), the IPA round pairs and final scalar pair.
  The layout is a pure function of `(bitWidth, curve)`, no length prefixes;
  `FromBytes` rehydrates a stored or transmitted proof. Proof size at
  `n = 64` on BLS12-381: `4·48 + 3·32 + 6·2·48 + 2·32 = 928` bytes.
- **`WellKnownBulletproofRangeLabels`** — the pinned Fiat-Shamir operation
  labels. The transcript's *domain* label is the consumer's to choose, and
  the consumer must bind the transcript to its statement context before
  proving/verifying — the proof binds the commitment `V` (absorbed first),
  but the application-level statement ("this commitment is the `age`
  attribute of credential X") is the consumer's transcript discipline.

## Aggregation (§4.3)

`AggregatedBulletproofRange{Prover,Verifier}` prove `m` values in one
argument of `2·log₂(nm)` round pairs plus the constant header — logarithmic
in the aggregate where `m` separate proofs grow linearly. The bit
decompositions concatenate into one `n·m`-length vector pair (slot `j·n + b`
is bit `b` of value `j`); the per-value terms enter through ascending powers
of `z` (value `j` carries `z^{2+j}` where the single-value protocol carries
`z²`); one shared blinding polynomial covers every value; the constant
generalises to `δ = (z − z²)·⟨1, y^{nm}⟩ − Σ_j z^{3+j}·⟨1, 2^n⟩` and the
`H`-basis weight at index `i = j·n + b` becomes `z + z^{2+j}·2^b·y^{−i}`.

The wire container is `RangeProof` **itself** at vector length `n·m` — the
aggregated layout *is* the single-value layout at that length, so
`RangeProof.BitWidth` reads the IPA vector length, not the per-value width;
the verifier checks the `(bitWidth, valueCount)` factorisation explicitly.
The transcript prepends the aggregation count and absorbs every value
commitment, so single and aggregated proofs can never be confused over the
same statement context. The per-value `z` powers bind each commitment to its
slot — swapping two commitments breaks verification. The generator-vector
cap is `4096` (a 64-value aggregation at full 64-bit width); a single-value
proof keeps its own `n ≤ 64` cap and refuses an aggregation-length key, so
the two entry points stay unambiguous.

## Verifier batching (§6.1)

`BatchBulletproofRangeVerifier` (single-value) and
`BatchAggregatedBulletproofRangeVerifier` (aggregated) verify `p` proofs that
share one key in **one** multi-exponentiation instead of `p` independent
fold-based verifications. Each proof's `t̂` consistency check and its
inner-product check are collapsed to single-MSM identities — the IPA's
per-round generator fold replaced by the closed-form *s-vector*
`s_i = ∏_j w_j^{±1}` (the sign by the bit pattern of `i`, the round challenges
`w_j`) — and the identities are combined under two fresh random weights per
proof, squeezed from the batch transcript so they bind every proof's
challenges. A random linear combination of point identities is the group
identity exactly when all of them are, except on a weight set of measure
`≤ 2p/|F|` (Schwartz–Zippel), so a single forged proof poisons the combined
MSM. The shared generators (`g, h, U` and the `2·n·(m)` bit generators)
appear once with accumulated coefficients and — through the caching
multi-exponentiation backend — decode once for the whole batch, so the
per-proof marginal cost is dominated by its own `A, S, T₁, T₂`, value
commitments, and `2·log₂` round points. The single-proof batch is gated to
accept exactly what the fold-based verifier accepts, pinning the s-vector
orientation. Measured speedup over individual verification grows with the
batch: ~13× at `p = 2`, ~42× at `p = 32` (BLS12-381, 32-bit, dev host).

## Security flavor

Computational soundness from the discrete-log assumption over the wired
curve (the standard Bulletproofs analysis); the proof is zero-knowledge —
`V`, `A`, `S`, `T₁`, `T₂` are perfectly-hiding Pedersen commitments and the
revealed aggregates are blinded by `τ₁, τ₂, α, ρ` and the `s`-vectors, fresh
per proof (two proofs of the same statement differ). This matches the
pairing path's overall flavor (computational ZK rooted in DLOG); see
`../Spartan/SPARTAN-ZK-DESIGN.md` §9 for the cross-stack map. Not
post-quantum: a discrete-log adversary can equivocate the commitment.

The corresponding `ProofSystem.Bulletproofs` identifier (in
`Lumoin.Veridical.Core`) names this system in artifact tags and
interop metadata.

## Cost

Prover and verifier are `O(n)` group operations dominated by the MSMs and the
per-round IPA folds; proof size is `O(log n)` (`O(log nm)` aggregated). The
implementation is correctness-first reference arithmetic per the repository's
stance, but the MSM-bound paths ride the bucket-method (Pippenger)
multi-exponentiation with a decoded-point cache, and the round computations
route through the lane-interleaved batch-multiply seam where present.

Recorded follow-ons, not built (all minor): batching aggregated proofs of
*differing* `(bitWidth, valueCount)` via prefix generators; collapsing the
two per-proof batch weights into one via challenge powers (a micro-saving,
arguably a clarity downgrade over two independent weights).

## Memory ownership

No layer allocates a commitment buffer: every prover takes the commitment
*destination* as a caller-supplied `Span<byte>`, so a consumer rents it from
a pool (or `stackalloc`s it) by their own choice and the API never forces a
`new[]`. Working buffers are pool-rented internally; the only library
allocations that outlive a call are the one-time backings of long-lived
objects (the key's generator families, the foldable code's build-once
inverse cache), which are deliberately *not* pooled.
