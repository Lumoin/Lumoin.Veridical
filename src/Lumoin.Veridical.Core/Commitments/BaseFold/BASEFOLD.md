# BaseFold — transparent multilinear polynomial commitment

BaseFold (Zeilberger, Chen, Fisch, CRYPTO 2024, IACR ePrint 2023/1705) is a
transparent, hash-based, post-quantum-style polynomial commitment scheme for
multilinear polynomials. It needs no trusted setup and no elliptic-curve
operations — only a random foldable linear code, Merkle commitments, and field
arithmetic. In Veridical it is the post-quantum-flavoured sibling of the
pairing-based Hyrax commitment, behind the same scheme-agnostic
`PolynomialCommitmentProvider` surface.

This document is the orientation map for the `Commitments/BaseFold/` layer and
its Spartan integration. (The validation sweep and the comprehensive
soundness-parameter write-up are completed in batch AB.6.)

## Layers (batch AB)

- **AB.1 — random foldable codes** (`FoldableCode`, `FoldableCodeExtensions`).
  `Encode` maps a coefficient message to a codeword; `Fold` collapses a codeword
  one layer under a challenge. Wired shape: inverse rate `c = 8`, base dimension
  `k0 = 1` (the `[8,1,8]` repetition base code). Type-2 (paper) fold ordering.
- **AB.2 — Merkle commitment** (`MerkleTree`, `MerkleRoot`,
  `MerkleAuthenticationPath`). BLAKE3, 32-byte digests, binary tree.
- **AB.3 — IOPP** (`BaseFoldIoppProver`/`Verifier`, `BaseFoldQueryPhase`). The
  proof of proximity: commit each fold layer, fold under squeezed challenges to
  the base codeword, and query random positions with Merkle openings. Query
  count is derived from the soundness bound (`WellKnownBaseFoldIoppParameters`,
  default 273 for the 128-bit list-decoding regime).
- **AB.4 — the multilinear PCS** (`BaseFoldEvaluationProver`/`Verifier`,
  `BaseFoldPolynomialCommitmentScheme`). The evaluation protocol (paper §5 /
  Fig 3) interleaves a sumcheck for `Σ_b f(b)·eq_z(b) = y` with the IOPP — the
  sumcheck round challenge **is** the IOPP fold challenge. Commit interpolates
  the MLE's evaluations to coefficients (`BaseFoldInterpolation`) and encodes;
  the binding order is high-bit-first to match `Encode`/`Fold`. Behind the
  provider surface: commit → Merkle root; open/verify → the serialized
  evaluation proof.
- **AB.5 — Spartan integration** (this batch). See below.
- **SM.1 — weighted openings** (batch SM). The evaluation protocol's `eq_z`
  multiplier generalised to an arbitrary *public* multiplier multilinear `W`:
  `ProveWeightedSum`/`ProveWeightedSumHiding`/`VerifyWeightedSum` prove
  `Σ_b f(b)·W(b) = v` — any public linear functional of the committed
  hypercube evaluations. An evaluation opening is the special case `W = eq_z`
  (byte-identical, test-gated). The verifier computes `W(r)` by folding the
  public multiplier table under the squeezed challenges. This is the binding
  primitive of the statistical-mask construction
  (`ZK-STATMASK-DESIGN.md` levels 2 and 3).

## Spartan over BaseFold (AB.5)

The Spartan prover/verifier *algorithm* is commitment-scheme-agnostic — it
drives the provider's `Commit`/`Open`/`VerifyEvaluation` and carries the broad
`PolynomialCommitment`/`PolynomialOpening`/`PolynomialCommitmentBlind` leaf
types. Only the proof *container* is scheme-shaped. AB.5 adds BaseFold-shaped
sibling containers and thin prover/verifier entry points:

- `BaseFoldSpartanProof` / `BaseFoldMaskedSpartanProof` — siblings of the
  Hyrax-shaped `SpartanProof` / `MaskedSpartanProof`. They carry 32-byte Merkle
  roots for commitments and serialized BaseFold evaluation proofs for openings,
  and share the scheme-independent middle via `SpartanSumcheckProofPart`.
- `SpartanProver.ProveBaseFold` / `SpartanVerifier.VerifyBaseFold` and the masked
  `MaskedSpartanProver.ProveBaseFold` / `MaskedSpartanVerifier.VerifyBaseFold`.
  They reuse the one scheme-neutral orchestration core each side; the Hyrax
  entries are byte-identical to before (the committed fixtures gate this).

The error commitment of a raw instance is built by committing the zero error
vector through the provider (`RawR1csInstance.Prepare(pcs, pool)`), giving a
deterministic BaseFold root that prover and verifier reproduce — rather than the
pairing-group identity the Hyrax path uses.

## Two boundaries

1. **Hiding (masked variant) — closed by batch ZK-BF.** As batch AB shipped it,
   BaseFold's commitment was a Merkle root over the codeword — binding but **not
   hiding** — so masked-Spartan-over-BaseFold was a sound argument of knowledge
   that did **not** achieve the witness privacy its name implies. Batch **ZK-BF**
   supplies the missing hiding BaseFold and closes this boundary; see
   *Zero-knowledge BaseFold* below. For the concrete demonstration of what the
   original leakage meant — three experiments showing the plain commitment is a
   deterministic, recoverable fingerprint of the witness, and how the hiding
   variant flips that — see `../../../Analysis/BaseFoldLeakage/BASEFOLD-LEAKAGE.md`
   (batches AC and ZK-BF).

2. **Folding (fold chain).** Nova-style folding combines error and cross-term
   commitments *homomorphically* (`C_folded = C_acc + r·C_cross + r²·C_in`),
   which requires an additively-homomorphic commitment. BaseFold's Merkle
   commitment has no such structure, so a fold chain **cannot** run over BaseFold
   — the incompatibility is in the accumulation, not in hiding.
   `PolynomialCommitmentProvider.IsAdditivelyHomomorphic` records the capability
   (true for Hyrax, false for BaseFold), and `FoldChain.Start` rejects a
   non-homomorphic provider with a clear error. BaseFold serves the direct
   (non-folded) prove/verify paths instead; see `Spartan/FOLDING.md`.

## Zero-knowledge BaseFold (batch ZK-BF)

Batch ZK-BF turns BaseFold into a hiding, zero-knowledge polynomial commitment, so
masked-Spartan-over-BaseFold finally delivers the witness privacy boundary 1 used
to disclaim. An honest BaseFold opening leaks the witness through three channels;
each is closed in turn, all under the same `PolynomialCommitmentProvider` surface.

- **ZK.1 — hiding commitment** (`ZkBaseFoldPolynomialCommitmentScheme.Create`).
  Every fold-layer Merkle tree is built over *salted* leaves `hash(value ‖ salt)`
  with secret uniform salts (`MerkleTree.BuildSalted`), so the commitment root and
  every in-proof fold root reveal nothing about the codeword. Fold-consistency is
  still checked on the cleartext values, the query count is unchanged, and binding
  is preserved. `PolynomialCommitmentProvider.IsHiding` becomes `true`.
- **ZK.2b.1 — query and base-oracle hiding via a dimension lift**
  (`CreateZeroKnowledge`). The queried codeword entries and the cleartext base
  oracle `π_0` are still deterministic in `f`. Masking `f`'s own coefficients is
  *unsound* for a commit-then-open PCS (the evaluation point is chosen after
  commit). The fix is to commit the real `d`-variable witness `f` as the `Y = 0`
  slice of a `(d + t)`-variable `f'` whose `Y ≠ 0` block is entropy, and to
  evaluate every opening at the protocol-fixed point `(z, 0^t)`. By the multilinear
  `eq` factorisation `f'(z, 0^t) = f(z)` for *any* mask — the randomness lives in
  real variables the evaluation never ranges over — and `f'` is an honest codeword
  of the same code at `d + t` layers, so BaseFold's knowledge soundness and the
  distance bound apply verbatim (no `FoldableCode` change, no distance re-proof).
- **SM.3 — statistical sumcheck round-polynomial mask** (`CreateFullZeroKnowledge`;
  supersedes the original ZK.2b.2 lockstep-multilinear mask, whose degree-1
  rounds left the `c_2` coefficient bare — the recorded computational-ZK
  residual). The mask is the Libra sum-of-univariates
  `s = a_0 + Σ(a_j·x_j + b_j·x_j²)` (`MonomialBasisMask`), blended closed-form
  into every round coefficient — including `c_2`. Its coefficient vector plus
  laundering filler is committed salted-and-lifted (`com(C*)`), absorbed with
  `σ = Σ_b s(b)` and the filler sum `σ_F` before `ρ` is squeezed; each sent
  round polynomial becomes `h_k + ρ·s_k`. The verifier derives
  `s(r) = (claim − f(r)·eq_z(r))·ρ⁻¹` from the masked chain and checks ONE
  nested hiding **weighted opening** (SM.1) of `C*` against `s(r) + σ_F` under
  publicly derived weights — no mask codeword, no lockstep folding. Shapes are
  the deterministic policy `WellKnownStatisticalMaskParameters`; design and the
  DOF-ledger argument: `ZK-STATMASK-DESIGN.md` §2 v3 / §3.
  (`BaseFoldEvaluationProver.ProveZeroKnowledge` /
  `BaseFoldEvaluationVerifier.VerifyZeroKnowledge`; the proof's mask side is
  `BaseFoldMaskOpening`, gated by `BaseFoldOpeningMode.ZeroKnowledge`.)

**Masked Spartan over the ZK provider (ZK.3, mask side upgraded by SM.7b).**
`MaskedSpartanProver.ProveZkBaseFold` / `MaskedSpartanVerifier.VerifyZkBaseFold`
assemble a `ZkBaseFoldMaskedSpartanProof` (the full-ZK sibling of
`BaseFoldMaskedSpartanProof`), reusing the scheme-neutral orchestration core. The
witness opening is a full-ZK evaluation opening through `pcs.VerifyEvaluation`;
the two Spartan-level masks are themselves statistical sum-of-univariates kernels
(SM.7b) whose coefficient vectors are committed salted-and-lifted via the
provider's `CommitVector` and bound by **hiding weighted openings**
(`OpenWeightedSum`/`VerifyWeightedSum`) at their policy-resolved lifted shapes —
the v3 filler laundering replaced the earlier recursive full-ZK mask openings,
shrinking the proof. One subtlety: the public **zero-error** vector's commitment
is *recomputed* by the verifier (not transmitted), so it must stay a plain
deterministic commitment; these entries take an `errorPcs` (a plain BaseFold
provider over the same code parameters). The proof is mixed-size — a plain error
opening, two hiding mask weighted openings, and one full-ZK witness opening.

**ZK flavor — statistical in the ROM (the ledger lemma is
`ZK-STATMASK-DESIGN.md` Appendix A; the empirical validation record is its
Appendix B and `BASEFOLD-LEAKAGE.md`).** The original
lockstep-multilinear mask was degree-1 per round and left the round polynomial's
degree-two coefficient a deterministic function of `f·eq_z` — computational ZK
only, with the byte-distribution chi-squared able to detect the residual. The
SM.3 statistical mask blends all three round coefficients with exact
degrees-of-freedom coverage (Libra Theorem 3 plus the filler-laundering ledger,
design doc §3), targeting statistical zero knowledge in the random-oracle
model: salted-leaf hiding is statistical in the ROM, the lift's
bounded-independence budget is machine-enforced, and the mask reveals are
budgeted DOF spends. The bounded-independence hiding budget
(`(2^t − 1)·2^d ≥ Q*`) is **enforced in code**: the lift providers refuse an
under-budget commit or open with an `InvalidOperationException` naming the smallest
sufficient `t`, where `Q*` is bounded by `queryCount·(d + t + 1)` (two top-layer
entries plus one new sibling per lower layer, per query) plus the cleartext base
oracle. `ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount` sizes
the lift; `MeetsHidingBudget` checks a chosen one. The budget is additionally
validated empirically. See `Spartan/SPARTAN-ZK-DESIGN.md` for the
construction lineage and `../../../Analysis/BaseFoldLeakage/BASEFOLD-LEAKAGE.md` for
the empirical flip.

## Cross-validation discipline

There is no Spartan-shaped BaseFold reference producer (Microsoft Research's
Spartan2 ships only Hyrax and IPA), so BaseFold correctness is established by
property and round-trip tests, the IOPP/PCS tie tests, and — for the Spartan
integration — end-to-end prove→verify plus tamper rejection, not by byte-for-byte
equivalence against an external implementation. The structural reference for the
codes/IOPP is `hadasz/plonkish_basefold` (which uses a bit-reversed Type-1
ordering Veridical deliberately does not copy).

## Validation (AB.6)

The test coverage establishing the above, by layer:

- **Codes (AB.1)** — `FoldableCodeTests`: encode/fold round-trips, the
  `Enc_{d-1}(m_l + α·m_r)` fold identity, parameter validation.
- **Merkle (AB.2)** — `MerkleTreeTests`: build/open/verify round-trips, tamper
  rejection.
- **IOPP (AB.3)** — `BaseFoldIoppTests`: honest codewords verify (incl. a CsCheck
  sweep), random far words are rejected, and tampering the commitment / a fold
  root / an authentication path / the query count breaks verification; the query
  count derivation matches the regime formulas.
- **IOPP soundness (AB.6)** — `BaseFoldIoppSoundnessTests`: a **malicious prover**
  that commits an intermediate oracle which is not the honest fold (valid Merkle
  openings, self-consistent transcript) is rejected by the per-layer
  fold-consistency relation — the direct test of that relation, with an honest
  control proof verifying alongside; plus an informational sweep confirming random
  far words are always rejected.
- **PCS / evaluation protocol (AB.4)** — `BaseFoldInterpolationTests` (the
  Möbius transform), `BaseFoldEvaluationTests` (the evaluation protocol tie:
  claimed value equals an independent MLE evaluation, plus wrong-value / wrong-point
  / tampered-root rejection), `BaseFoldPolynomialCommitmentSchemeTests` (the
  byte-surface commit→open→verify and tampers).
- **PCS validation (AB.6)** — `BaseFoldValidationTests`: determinism (committing
  and opening the same inputs is byte-identical — no non-determinism leaks into
  the transparent prover), the full 128-bit list-decoding query count (≈273)
  exercised once, a larger variable count (d = 8), and a documented usage example.
- **Spartan integration (AB.5)** — `BaseFoldSpartanRoundtripTests`,
  `BaseFoldMaskedSpartanRoundtripTests` (prove→verify + tamper for the unmasked
  and masked variants), `BaseFoldFoldChainGuardTests` (the fold chain rejects a
  non-homomorphic provider). The Hyrax byte-identity fixtures
  (`SpartanFixtureTests`, `MaskedSpartanFixtureTests`, `FoldChainFixtureTests`)
  gate that the integration left the Hyrax wire format untouched.

Byte-pinned BaseFold fixtures (analogous to the Hyrax `*FixtureTests`) are not
committed: the unmasked path is byte-deterministic and could be pinned, but the
value over the determinism test is marginal until a second conformant producer
exists to pin against.
