# Spartan2 — protocol implementation reference

This file documents the Spartan2 sumcheck-based SNARK as implemented
in this folder. It pins the protocol flow, the zero-knowledge property,
the transcript schedule, and the wire-format proof layout so an
external verifier or a different runtime can interoperate with proofs
this prover produces.

## 1. Protocol overview

Spartan2 is a SNARK for R1CS satisfiability: given an instance
`(A, B, C, public_inputs)` and a hidden witness `w`, the prover convinces
the verifier that `(A·z) ∘ (B·z) = (C·z)` where `z = (1, public_inputs, witness)`
is the full assignment vector and `∘` is the componentwise product.

The high-level construction reduces R1CS satisfaction to a single
witness MLE evaluation through two nested sumchecks, then opens that
evaluation against a Hyrax commitment to the witness. Soundness rests
on discrete-log hardness over BLS12-381 G1 plus the random-oracle
assumption on the Fiat-Shamir transcript. The mathematical foundation
is the 2020 paper "Spartan: Efficient and general-purpose zkSNARKs
without trusted setup" by Srinath Setty.

## 2. Protocol flow

Inputs:

- An R1CS instance with `m = rows` and `n = columns`, both padded to
  powers of two. `A`, `B`, `C` are sparse-COO matrices over the
  BLS12-381 scalar field.
- A witness vector `w` of length `n − 1 − public_input_count`.

The prover assembles `z = (1, public_inputs, witness)` of length `n`
and works through these steps:

1. **Setup.** Both parties seed their transcript with the Spartan2
   domain label and the empty seed bytes. The R1CS instance binding
   happens via the absorbs in step 2; the seed is pure domain
   separation.
2. **Instance absorb.** Absorb dimensions, the three matrices `A`,
   `B`, `C`, and the public inputs.
3. **Witness commitment.** Build the witness MLE `z_W` — the witness
   placed at its column positions, zeros at non-witness positions,
   length `n`. Commit `z_W` under Hyrax. Absorb the commitment.
4. **Squeeze τ.** Squeeze `τ ∈ F^{log m}`. τ binds the outer-sumcheck
   eq factor.
5. **Outer sumcheck.** Run a degree-3 sumcheck proving
   `Σ_{x ∈ {0,1}^{log m}} eq(τ, x) · [(Az)(x) · (Bz)(x) − (Cz)(x)] = 0`.
   Yields challenges `r_x ∈ F^{log m}` and three terminating claims
   `(claim_Az, claim_Bz, claim_Cz)` — the row-side evaluations of
   `(Az)~`, `(Bz)~`, `(Cz)~` at `r_x`.
6. **Absorb outer claims.** Absorb the three terminating claims as
   one 96-byte block.
7. **Squeeze `r`.** Squeeze the batching scalar `r ∈ F`.
8. **Inner sumcheck.** Compute the column slice
   `ABC(y) = A~(r_x, y) + r · B~(r_x, y) + r² · C~(r_x, y)`. Run a
   degree-2 sumcheck proving
   `claim_Az + r · claim_Bz + r² · claim_Cz = Σ_{y ∈ {0,1}^{log n}} ABC(y) · z(y)`.
   Yields challenges `r_y ∈ F^{log n}`.
9. **Witness MLE evaluation.** Evaluate `eval_W = z_W~(r_y)` and absorb.
10. **Open the Hyrax commitment** at `r_y`. The opening proof is
    embedded in the SpartanProof's trailing bytes.

The verifier reconstructs the protocol's checks by replaying the
transcript, recomputing the matrix MLE evaluations `A~(r_x, r_y)`,
`B~(r_x, r_y)`, `C~(r_x, r_y)` directly from the sparse-COO matrices,
deriving `eval_PublicAndOne = (1, public_inputs, 0, …)~(r_y)` from the
known public inputs, computing
`eval_Z = eval_W + eval_PublicAndOne` (multilinear extensions are
linear, so the sum splits cleanly), and checking the inner sumcheck's
terminating identity
`final_running_claim == [A~(r_x, r_y) + r · B~(r_x, r_y) + r² · C~(r_x, r_y)] · eval_Z`
along with the Hyrax opening's correctness.

## 3. Zero-knowledge characterization

The witness MLE is committed via Hyrax. Hyrax provides perfect hiding
through its Pedersen-style blinding factors and unconditional binding
through the discrete-log assumption.

The sumcheck round polynomials are sent in cleartext. Each round
polynomial is a degree-3 (outer sumcheck) or degree-2 (inner sumcheck)
univariate function. The polynomial's coefficients are bounded linear
combinations of evaluations of `(Az, Bz, Cz)` at the round's folded
boolean hypercube. Over the full proof, the prover reveals
`O((log m + log n) · degree)` field elements that are deterministic
functions of the matrices `A`, `B`, `C` and the witness `z`. The
witness elements themselves are never directly revealed.

An adversary with the proof cannot recover witness elements without
breaking the discrete logarithm problem over BLS12-381 G1. The proof
is zero-knowledge in the random-oracle model with this hardness
assumption. The base prover does not hide the per-round sumcheck
messages or the terminating evaluations; stronger ZK over those
artifacts is available via the separate `MaskedSpartanProver` type
described in §10, which wraps this prover with statistical
sum-of-univariates round masks (SM.7b). Over the Hyrax path the
masked variant stays in the same security category as the rest of
the stack (computational ZK in the random-oracle model rooted in
the discrete-log assumption — the openings are Pedersen/IPA); over
the full-ZK BaseFold provider the same construction yields the
statistical-in-ROM flavor. See the cross-stack lineage section in
`SPARTAN-ZK-DESIGN.md` for the full map.

## 4. Transcript schedule

Pinned for interoperability. Domain label is `veridical.spartan2.v1`.

| Step | Operation | Label                                  | Bytes                                  |
|------|-----------|----------------------------------------|----------------------------------------|
| 0    | Init      | (domain)                               | seed = empty bytes                     |
| 1    | Absorb    | `r1cs.instance.dimensions`             | 6 × 4-byte BE                          |
| 1    | Absorb    | `r1cs.instance.matrix.{A,B,C}`         | matrix bytes                           |
| 1    | Absorb    | `r1cs.instance.publicInputs`           | public-input bytes                     |
| 1    | Absorb    | `spartan.witness.commitment`           | Hyrax commitment bytes                 |
| 2    | Squeeze   | `spartan.outer.tau` (× log m)          | one scalar per squeeze                 |
| 3a   | Absorb    | `sumcheck.round.polynomial` (× log m)  | compressed round polynomial bytes      |
| 3b   | Squeeze   | `sumcheck.round.challenge` (× log m)   | one scalar per round                   |
| 4    | Absorb    | `spartan.outer.claimed_evaluations`    | 3 × 32 = 96 bytes                      |
| 5    | Squeeze   | `spartan.inner.combination`            | one scalar `r`                         |
| 6a   | Absorb    | `sumcheck.round.polynomial` (× log n)  | compressed round polynomial bytes      |
| 6b   | Squeeze   | `sumcheck.round.challenge` (× log n)   | one scalar per round                   |
| 7    | Absorb    | `spartan.witness.evaluation`           | 32 bytes (`eval_W`)                    |
| 8    | (Hyrax)   | (inner Hyrax transcript schedule)      | pinned in batch E                      |

The outer and inner sumchecks reuse `sumcheck.round.polynomial` and
`sumcheck.round.challenge` for their per-round absorbs and squeezes.
The squeeze count discriminates them within a single transcript, so
the same label pair is safe to reuse.

## 5. Proof byte layout

The `SpartanProof` leaf type packs the wire-format bytes into one
pool-rented buffer, in order:

```
[ witness commitment      : <commitmentRowCount> × 48 bytes ]
[ outer sumcheck rounds   : log m × 3 × 32 = 96 · log m bytes ]
[ claim_Az : 32 ] [ claim_Bz : 32 ] [ claim_Cz : 32 ]
[ inner sumcheck rounds   : log n × 2 × 32 = 64 · log n bytes ]
[ eval_W                  : 32 bytes ]
[ Hyrax opening proof     : variable, sized by IpaRoundCount ]
```

The leading witness commitment is the prover's Hyrax commitment to
the witness MLE. Its row count is
`HyraxCommitmentDimensions.ForVariableCount(log n).RowCount`. Each
outer-sumcheck round is a `CompressedRoundPolynomial` of degree 3
(linear-term elided, 3 field elements stored). Each inner-sumcheck
round is degree 2 (2 field elements stored).

The total wire size is
`commitment_size + 96 · log m + 96 + 64 · log n + 32 + HyraxOpeningProof.GetBufferSizeBytes(ipa_rounds)`.

## 6. Verifier flow

The verifier replays the transcript, decompresses and checks each
sumcheck round polynomial against the running claim, independently
evaluates the three matrix MLEs at the squeezed points, and verifies
the Hyrax opening of the witness commitment at the inner-sumcheck
final point. The implementation is exception-safe against malformed
proof bytes; corrupted bytes that fail decoding cause a false return,
not a thrown exception.

Verifier check sequence:

1. Argument validation. Reject null arguments, mismatched curve,
   mismatched dimensions between the proof and the verifying key.
   These paths throw because they indicate caller bugs.
2. Replay transcript steps 1–1b: absorb the R1CS instance, then the
   embedded witness commitment.
3. Squeeze τ.
4. Run the outer sumcheck verifier. For each of log m rounds,
   reconstruct the round polynomial from the proof's compressed bytes
   against the running claim, absorb the compressed bytes, squeeze
   the round challenge, and Horner-evaluate the polynomial at the
   challenge to update the running claim.
5. Absorb the three outer claimed evaluations.
6. Squeeze the inner-combination scalar `r`.
7. Compute the inner sumcheck's initial joint claim
   `joint = claim_Az + r · claim_Bz + r² · claim_Cz`.
8. Run the inner sumcheck verifier (log n rounds, degree-2).
9. Absorb `eval_W` from the proof.
10. Reconstruct the Hyrax opening proof from the proof's trailing
    bytes; run Hyrax verify against the embedded commitment, the
    inner sumcheck challenges, and `eval_W`.
11. Compute `eval_PublicAndOne(r_y)` from the instance's public
    inputs, then `eval_Z = eval_W + eval_PublicAndOne` by MLE
    linearity.
12. Compute the three matrix MLE evaluations
    `A~(r_x, r_y)`, `B~(r_x, r_y)`, `C~(r_x, r_y)` independently from
    the R1csInstance.
13. Check the outer terminating identity:
    `outer_final_claim == eq(τ, r_x) · (claim_Az · claim_Bz − claim_Cz)`.
14. Check the inner terminating identity:
    `inner_final_claim == [A~ + r · B~ + r² · C~] · eval_Z`.
15. Return `true` iff steps 10, 13, and 14 all hold.

## 7. Interop

The protocol is the construction from Setty 2020 and is mathematically
compatible with other Spartan2 implementations at the protocol level.
Wire-format byte compatibility is a separate matter — see §8.

## 8. Wire format vs. protocol compatibility

The protocol is the Spartan2 construction from Setty 2020: outer and
inner sumcheck structure, Hyrax for the witness commitment, and a
Fiat-Shamir transcript discipline.

Veridical's wire format is its own. The proof byte layout (described
in §5), the witness MLE convention, the Hyrax commitment key seed,
and the transcript label conventions are Veridical's choices.
Different Spartan2 implementations make different choices in each of
these areas; there is no universal Spartan2 wire format at the time
of writing. A proof produced by Veridical is accepted by Veridical's
verifier; proofs produced by other implementations are accepted by
their own verifiers; cross-implementation proofs are mathematically
compatible at the protocol level but not byte-compatible at the wire
level.

Veridical's witness MLE places the witness at its column positions in
a vector of length n (the constraint system's variable count) with
zeros elsewhere. The verifier reconciles this against the public-
input contribution at verify time via MLE linearity.

## 9. Architectural notes

`SumcheckRoundComputation` is a static class of pure helper functions
with no transcript dependency. Round-polynomial computation is a
function of `(Az, Bz, Cz)` slices and the current folding variable
only. This purity is the structural property that lets the prover
compose round-polynomial computation with the transcript driver
without coupling them.

`OuterSumcheckProver` and `InnerSumcheckProver` are internal static
drivers that compose the pure round-polynomial computation with the
Fiat-Shamir transcript's absorb and squeeze operations. They are not
on the public API surface; consumers reach the prover through
`SpartanProver` and `SpartanProverExtensions.Prove`.

`OuterSumcheckVerifier`, `InnerSumcheckVerifier`, and
`EvalPublicAndOneComputation` mirror that discipline on the verifier
side. They are internal; consumers reach the verifier through
`SpartanVerifier` and `SpartanVerifierExtensions.Verify`.

### 9.1 Polynomial-commitment surface

The prover and verifier do not name a commitment scheme. They commit,
open, and verify against a `PolynomialCommitmentProvider` — a bundle of
three operations (`Commit`, `Open`, `VerifyEvaluation`) plus the scheme
and curve identity — and carry artifacts as the scheme-agnostic
`PolynomialCommitment`, `PolynomialOpening`, and `PolynomialCommitmentBlind`
leaf types. The proving and verifying keys hold the provider; the only
place a concrete scheme is named is the construction layer, where
`HyraxPolynomialCommitmentScheme.Create(...)` builds the Hyrax-backed
provider. This mirrors Microsoft Research's Spartan2 `PCSEngineTrait`
(structural inspiration only; no code dependency). A future scheme
(BaseFold, WHIR, …) drops in by supplying a different provider — Spartan
construction code is untouched. The provider re-derives the Hyrax matrix
shape at the boundary (from the polynomial's variable count when proving,
the evaluation point's length when verifying), so the broad leaf types
stay shape-free.

The proof types remain Hyrax-shaped in their byte layout: a commitment is
one compressed-G1 point per matrix row, an opening is `C_f` plus the IPA
round pairs and three trailing scalars. They describe those sections in
curve-generic byte-length terms rather than by naming the Hyrax types; a
scheme that assembles a differently-shaped proof brings its own layout.

### 9.2 Byte-identity and cross-validation discipline

Making the surface scheme-generic was a structural change with **zero
behaviour change**: the proof bytes are identical before and after. The
regression gate is the committed-proof fixture suite — `SpartanFixtureTests`,
`MaskedSpartanFixtureTests`, and `FoldChainFixtureTests` pin exact proof
bytes for fixed inputs and a deterministic RNG. Any future change to the
commitment surface (a new provider, a layout refactor) must keep these
green, alongside the prove→verify round-trip and indistinguishability
suites.

Cross-validation against the reference Rust Spartan2 is **precluded by
design**, not omitted by oversight: per §8, Veridical's wire format is its
own and there is no universal Spartan2 wire format, so neither byte
equality nor mutual proof acceptance against the Rust implementation is
achievable. The discipline is therefore Veridical-internal — before/after
byte-identity (the fixtures) and round-trip soundness — with no external
Rust fixtures.

## 10. Masked variant

The `MaskedSpartanProver` type wraps the base prover with the
statistically-masked Category A ZK construction (SM.7b, design v3
of `ZK-STATMASK-DESIGN.md`). The construction hides the
per-round sumcheck messages and the terminating evaluations beyond
what the base prover's Hyrax witness commitment already hides —
and unlike the earlier multilinear mask, the masking is
*statistical* per round message: every revealed round coefficient,
including the top one, is uniform given the mask's degrees of
freedom. Over the Hyrax path the end-to-end flavor remains
computational zero-knowledge in the random-oracle model (the
openings are Pedersen/IPA); over the full-ZK BaseFold provider
(`ProveZkBaseFold`) the same construction yields the
statistical-in-ROM flavor.

### 10.1 Construction

For each of the two sumchecks (outer and inner), the prover
samples a fresh sum-of-univariates mask of the round format's
degree (Libra §4.1): the outer cubic
`g_outer(x) = a_0 + Σ_j (a_j·x_j + b_j·x_j² + c_j·x_j³)` with
`3·log_2(rows) + 1` coefficients, the inner quadratic with
`2·log_2(columns) + 1`. The mask's coefficient vector, extended by
random *filler* to the policy-resolved width `2^ℓ₂`
(`WellKnownStatisticalMaskParameters`; every non-coefficient
coordinate is laundering entropy), is committed as a vector via the
provider's `CommitVector` — a single Pedersen row over Hyrax. The
prover absorbs `com(C*)`, the mask sum `σ = Σ_b g(b)` (closed form
over the basis), and the filler sum `σ_F` for both masks BEFORE the
blending scalars are squeezed.

The verifier (via Fiat-Shamir) issues a blending scalar `ρ` per
sumcheck. The sumcheck then runs on the blended polynomial
`F + ρ · g` instead of just `F` (where `F` is the base
construction's polynomial: `eq(τ, x) · (Az·Bz − u·Cz − E)` for
outer, `ABC · z` for inner). The per-round computation in the
existing `SumcheckRoundComputation` produces the base round
polynomial; the masked driver adds the mask's closed-form round
shares — `MonomialBasisMask.AddRoundBlend`, constant share into
`c_0`, quadratic into `c_2`, cubic into `c_3` (outer), the linear
share landing in the chain-elided `c_1` — scaled by `ρ`, before
absorbing the blended polynomial onto the transcript. No mask
coefficient passes through unmasked.

A variable-order convention connects the two layers: the kernel
binds variables high-first (the BaseFold fold order) while
Spartan's MLE folds bind the low eval-table bit first, so kernel
variable `X_j` is Spartan variable `x_{d+1−j}`, Spartan round `i`
blends at kernel variable `d − i`, and the kernel's terminal point
is the REVERSED challenge vector. The sum-of-univariates basis is
invariant under the relabeling; `MaskedSpartanAlgorithm`
centralises it for both sides.

At each sumcheck's terminating challenge the verifier derives
`g(r)` algebraically by inverting the terminating-identity
equation from the sumcheck's final running claim, then checks ONE
weighted opening of `C*` against the claim `v = g(r) + σ_F` under
the public weights `(basis monomials at the reversed challenges ‖
1…1 on the filler)` via the provider's `VerifyWeightedSum` — the
v3 binding. The all-ones filler weights add the precommitted `σ_F`
to the claim and launder the weighted opening's cleartext reveals.

The construction lineage: the mask shape is Libra's (Xie et al,
"Libra: Succinct Zero-Knowledge Proofs with Optimal Prover
Computation", CRYPTO 2019, §4.1), degree-matched per CFS (Chiesa,
Forbes, Spooner, "A Zero Knowledge Sumcheck and its Applications",
IACR ePrint 2017/305); the binding is the filler-laundered
weighted opening of `../Commitments/BaseFold/ZK-STATMASK-DESIGN.md` v3 — `O(d)`
mask cost where CFS's faithful Construction 6.6 would pay
`3^d`/`4^d`.

### 10.2 Transcript schedule

The masked variant's schedule extends the base schedule with the
masking-polynomial steps interleaved between the witness
commitment and `τ`, with the masking-polynomial openings landing
after `eval_W`. Domain label is `veridical.spartan2.v1` (same as
the base).

| Step  | Operation | Label                                       | Bytes                                  |
|-------|-----------|---------------------------------------------|----------------------------------------|
| 0     | Init      | (domain)                                    | seed = empty bytes                     |
| 1     | Absorb    | `r1cs.instance.*` and `spartan.witness.commitment` | (same as the base prover's §4 lines 1) |
| 1c    | Absorb    | `…masking-polynomial.outer-commitment`      | vector commitment bytes (one G1 row)   |
| 1d    | Absorb    | `…masking-polynomial.inner-commitment`      | vector commitment bytes (one G1 row)   |
| 1e    | Absorb    | `…masking-polynomial.outer-sum`             | 32 bytes (`σ_outer`)                   |
| 1f    | Absorb    | `…masking-polynomial.inner-sum`             | 32 bytes (`σ_inner`)                   |
| 1g    | Absorb    | `…masking-polynomial.outer-filler-sum`      | 32 bytes (outer `σ_F`)                 |
| 1h    | Absorb    | `…masking-polynomial.inner-filler-sum`      | 32 bytes (inner `σ_F`)                 |
| 1i    | Squeeze   | `…masking-polynomial.outer-blending`        | one scalar (`ρ_outer`)                 |
| 1j    | Squeeze   | `…masking-polynomial.inner-blending`        | one scalar (`ρ_inner`)                 |
| 2     | Squeeze   | `spartan.outer.tau` (× log m)               | one scalar per squeeze                 |
| 3a    | Absorb    | `sumcheck.round.polynomial` (× log m)       | blended degree-3 round polynomial      |
| 3b    | Squeeze   | `sumcheck.round.challenge` (× log m)        | one scalar per round                   |
| 4a    | Absorb    | `spartan.outer.claimed_evaluations`         | 3 × 32 = 96 bytes                      |
| 4b    | Absorb    | `spartan.outer.error_evaluation`            | 32 bytes (`E(r_x)`)                    |
| 5     | Squeeze   | `spartan.inner.combination`                 | one scalar (`r`)                       |
| 6a    | Absorb    | `sumcheck.round.polynomial` (× log n)       | blended degree-2 round polynomial      |
| 6b    | Squeeze   | `sumcheck.round.challenge` (× log n)        | one scalar per round                   |
| 7     | Absorb    | `spartan.witness.evaluation`                | 32 bytes (`eval_W`)                    |
| 8a    | (opening) | error opening sub-protocol at `r_x`         |                                        |
| 8b    | (opening) | outer mask WEIGHTED opening sub-protocol    |                                        |
| 8c    | (opening) | inner mask WEIGHTED opening sub-protocol    |                                        |
| 8d    | (opening) | witness opening sub-protocol at `r_y`       |                                        |

The new labels are pinned in
`WellKnownMaskedSpartanTranscriptLabels`. The per-round absorb /
squeeze labels (`SumcheckRoundPolynomial`,
`SumcheckRoundChallenge`) are reused from
`WellKnownSpartanTranscriptLabels` because the masked sumcheck
rounds occupy the same per-round transcript slot as the base
sumcheck rounds, just carrying blended polynomial bytes.

### 10.3 Wire format

The `MaskedSpartanProof` leaf type packs the wire-format bytes
into one pool-rented buffer:

```
[ witness commitment           : witnessCommitmentRowCount × 48 bytes ]
[ outer mask vector commitment : 1 × 48 bytes (one Pedersen row over C*_outer) ]
[ inner mask vector commitment : 1 × 48 bytes (one Pedersen row over C*_inner) ]
[ σ_outer                      : 32 bytes ]
[ σ_inner                      : 32 bytes ]
[ outer σ_F                    : 32 bytes ]
[ inner σ_F                    : 32 bytes ]
[ outer sumcheck rounds        : OuterRoundCount × 3 × 32 = 96 · log m bytes ]
[ claim_Az | claim_Bz | claim_Cz : 96 bytes ]
[ E(r_x)                       : 32 bytes ]
[ inner sumcheck rounds        : InnerRoundCount × 2 × 32 = 64 · log n bytes ]
[ eval_W                       : 32 bytes ]
[ error opening proof          : sized by ErrorIpaRoundCount ]
[ outer mask weighted opening  : sized by OuterMaskIpaRoundCount = ℓ₂(outer) ]
[ inner mask weighted opening  : sized by InnerMaskIpaRoundCount = ℓ₂(inner) ]
[ witness Hyrax opening proof  : sized by WitnessIpaRoundCount ]
```

The mask vector commitments and the witness commitment share the
same Hyrax key; the prover and verifier require the key's
`VectorLength` to be at least the larger of the witness
Hyrax-decomposition column count and the masks' policy-resolved
vector widths `2^ℓ₂`. The blending scalars `ρ_outer` and
`ρ_inner` are not embedded — the verifier squeezes them from the
same transcript state as the prover. The mask values
`g_outer(r_x)` and `g_inner(r_y)` are not embedded — the verifier
derives them algebraically from each sumcheck's final running
claim (§10.5) and checks each weighted opening against
`v = g(r) + σ_F`.

### 10.4 Composability

The base prover is byte-untouched. The masked prover composes
with the existing base prover via `MaskedSpartanAlgorithm` —
internal-only helpers that mirror the base sumcheck drivers'
structure but blend the masking-polynomial contribution into the
per-round computation. The pure round-polynomial computation in
`SumcheckRoundComputation` is the boundary the masked driver
wraps; the existing XML doc on that type already anticipated this
extension point. No internal-visibility widenings were needed.

The base `SpartanProver` / `SpartanVerifier` continue to work
with the base `SpartanProof` shape. The masked
`MaskedSpartanProver` / `MaskedSpartanVerifier` work with
`MaskedSpartanProof`. The two pairs are independent at the type
level; callers pick the right pair for the property they need.

### 10.5 Security claim

The round-message channel is statistically masked: a degree-`k`
mask carries `k·d + 1` coefficients while the rounds and `σ`
reveal exactly `k·d + 1` constraints (degree-3 outer: `3d + 1`;
degree-2 inner: `2d + 1`), so by Libra Theorem 3's counting the
revealed round coefficients — including the top ones the earlier
multilinear mask left bare — are jointly uniform given the mask's
degrees of freedom. The terminal binding spends no extra mask
DOF: the weighted opening's claim is shifted by the precommitted
filler sum `σ_F`, and the filler block (sized by the policy's
ledger, `WellKnownStatisticalMaskParameters`) launders the
opening's cleartext functional reveals (the IPA's final folded
scalar plus `σ_F` itself over the Hyrax path; the lifted rounds
over BaseFold — design v3 and its Appendix A ledger lemma).

The end-to-end flavor follows the commitment scheme. Over Hyrax,
the witness commitment is perfectly hiding, the mask vector
commitment is a perfectly-hiding Pedersen row, and the
opening arguments are computationally hiding (the IPA's `L`/`R`
points are unblinded DLOG-hard group elements), so the proof is
computational zero-knowledge in the random-oracle model rooted in
the discrete-log assumption — as before SM.7b, but with the
previously-detectable round-coefficient residual removed. Over
the full-ZK BaseFold provider the same construction composes with
the statistical-in-ROM opening to give the statistical flavor
end-to-end. Soundness is unchanged: every mask artifact
(`com(C*)`, `σ`, `σ_F`) is absorbed pre-`ρ`, so the CFS blend
argument applies, and the weighted opening binds the derived
terminal value.

### 10.6 Stronger guarantees and the lineage

The statistical round-mask upgrade this section previously
reserved for CFS 2017's faithful Construction 6.6 landed in SM.7b
via the sum-of-univariates kernel at `O(d)` mask cost
(Construction 6.6's full mask is `3^d`/`4^d` coefficients — the
road not taken, recorded by the reserved
`SpartanProofVariant.MaskedCfs2017Strong` discriminator). What
remains computational over the Hyrax path is the opening layer
itself, which is inherent to Pedersen/IPA; the statistical
end-to-end flavor is available today by proving over the full-ZK
BaseFold provider (`ProveZkBaseFold`).

The cross-stack ZK-flavor lineage section in
`SPARTAN-ZK-DESIGN.md` records the upgrade paths available for
each primitive currently in the codebase and the observation
that end-to-end statistical ZK requires every primitive in the
composition to provide statistical ZK individually — upgrading
only the Spartan layer while leaving BBS+ and the base
commitments unchanged does not strengthen the overall property.
