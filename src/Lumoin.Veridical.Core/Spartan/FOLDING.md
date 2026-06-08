# Folding (Category B fold-with-randomness)

This document describes the as-built Nova-style folding layer that
aggregates a sequence of satisfied R1CS statements into a single
zero-knowledge proof. It is the *Category B* construction of
`SPARTAN-ZK-DESIGN.md` — fold-with-randomness ZK — realised on top of
the unified relaxed-R1CS Spartan prover. For the architectural rationale
and how Category B relates to the round-message-mask Category A, read
`SPARTAN-ZK-DESIGN.md` § 4 first; this document is the implementation
reference.

The pieces:

- `RelaxedR1csFold.Fold` (in `Lumoin.Veridical.Core.ConstraintSystems`) —
  the single Nova fold step.
- `RelaxedR1csAccumulator` (same namespace) — the running
  `(instance, witness, error-opening-witness)` bundle.
- `FoldChain` (in `Lumoin.Veridical.Core.Spartan`) — the consumer-facing
  `Start` / `Step` / `Finalize` driver.
- `WellKnownFoldingTranscriptLabels` — the pinned Fiat-Shamir labels.

Nova is Kothapalli, Setty, Tzialla, "Nova: Recursive Zero-Knowledge
Arguments from Folding Schemes" (CRYPTO 2022, IACR ePrint 2021/370). The
random-instance-as-hiding technique is NovaBlindFold, from Kothapalli and
Setty, "HyperNova" (CRYPTO 2024).

## The relaxed R1CS relation

Folding operates on *relaxed* R1CS. A relaxed instance carries the three
coefficient matrices `A`, `B`, `C`, the public inputs, a relaxation
scalar `u`, and a Hyrax commitment to an error vector `E`. With the full
assignment `z = (u, public, witness)` the satisfaction condition is

```
(A·z) ∘ (B·z) = u · (C·z) + E
```

where `∘` is the component-wise (Hadamard) product. The constant slot
`z[0]` is `u`, not literal `1` — the Nova convention that makes the fold
a clean linear combination. Standard R1CS is the special case `u = 1`,
`E = 0`, for which `z[0] = 1` and the condition reduces to
`(A·z) ∘ (B·z) = (C·z)`. A raw instance is mapped to this special case by
`RawR1csInstance.Prepare` (identity error commitment, zero error vector).
The relaxed satisfaction check is `RelaxedR1csInstance.CheckSatisfiedBy`;
it checks the relaxed identity against the explicit `E` in the witness
and does **not** verify the error commitment — that is a separate Hyrax
operation.

## The fold step

`RelaxedR1csFold.Fold` combines a left (accumulator) pair and a right
(incoming) pair, both over the same `A`, `B`, `C`, into a new satisfied
relaxed pair under a Fiat-Shamir challenge `r`:

```
u₃ = u₁ + r · u₂
z₃ = z₁ + r · z₂          (public and witness fold component-wise)
E₃ = E₁ + r · T + r² · E₂
```

where the cross-term

```
T = (A·z₁) ∘ (B·z₂) + (A·z₂) ∘ (B·z₁) − u₁ · (C·z₂) − u₂ · (C·z₁)
```

captures the bilinear interaction. The identity
`(A·z₃) ∘ (B·z₃) = u₃ · (C·z₃) + E₃` then holds *as a polynomial identity
in `r`*: expanding the left side produces exactly
`[true error of side 1] + r·T + r²·[true error of side 2]`, so when both
inputs are satisfied (their stored `E` equals their true error), the
folded pair is satisfied too — and can be folded again. If an input is
*not* satisfied (its stored `E` differs from its true error), the folded
pair is unsatisfied by the same `r²`-weighted residual; the discrepancy
is caught downstream at compression (see Soundness).

### Homomorphic error commitment

The prover commits the cross-term `T` under Hyrax over the row variables
(`log₂ m`), producing `Comm(T)` and its opening witness `r_T`. The folded
error commitment and its opening witness then combine homomorphically —
no recommitment of `E₃`:

```
Comm(E₃) = Comm(E₁) + r · Comm(T) + r² · Comm(E₂)
r_{E₃}   = r_{E₁}   + r · r_T      + r² · r_{E₂}
```

so `Comm(E₃)` opens to `E₃` under `r_{E₃}`. `Fold` returns the folded
instance, the folded witness, and `r_{E₃}` (a `HyraxOpeningWitness`); the
caller owns disposal of all three.

### Fold transcript schedule

`Fold` absorbs into the transcript, in order, under the pinned labels of
`WellKnownFoldingTranscriptLabels`:

1. `LeftParameters` — the accumulator's `{u, public inputs, error commitment}`.
2. `RightParameters` — the incoming statement's `{u, public inputs, error commitment}`.
3. `CrossTermCommitment` — `Comm(T)`.

then squeezes the fold challenge `r` under `Challenge`. The coefficient
matrices `A`, `B`, `C` are **not** absorbed here: they are constant
across a fold chain and are bound once, at compression time, when the
masked prover absorbs the folded instance. This is intentional and is
documented on `WellKnownFoldingTranscriptLabels`.

## The blinding instance — the ZK contribution

The fold step is a deterministic algebraic combination; it is not itself
hiding. Zero knowledge comes from one instance in the chain being a fresh
random satisfied relaxed instance. Following NovaBlindFold, `FoldChain`
places this **blinding instance** as the chain's initial accumulator and
folds the real statements into it.

`FoldChain.Start` builds it over the template circuit's `A`, `B`, `C`:

- sample a random relaxation scalar `u`;
- zero the public inputs (the blinding accumulator carries no statement of
  its own — hiding comes from the random `u`, witness, and error
  blinding, none of which are public);
- sample a random witness;
- with `z = (u, 0, witness)`, set the error vector to
  `E = (A·z) ∘ (B·z) − u · (C·z)`. By construction the relaxed identity
  holds, so the accumulator is a *valid satisfied* relaxed instance for
  any random `u` and witness;
- commit `E` under Hyrax with fresh random per-row blinding, yielding the
  error commitment carried in the instance and the opening witness
  carried in the accumulator.

Because the blinding instance's witness and `u` are uniform and its error
commitment is hiding, every fold mixes the real statements into a
uniformly random accumulator. The folded accumulator is uncorrelated with
the real statements in everything the verifier observes; any property of
the originals recoverable from the accumulator was already recoverable
from the accumulator's relation alone — which is exactly the relation the
compression proves.

## The chain

`FoldChain` drives the lifecycle:

```
FoldChain chain = FoldChain.Start(template, commitmentKey, foldTranscript, …);
chain.Step(instance₁, witness₁, errorOpeningWitness₁, …);   // fold statement 1
chain.Step(instance₂, witness₂, errorOpeningWitness₂, …);   // fold statement 2
…
MaskedSpartanProof proof = chain.Finalize(prover, compressionTranscript, …);
// verify against chain.Accumulator.Instance
```

- `Start` seeds the chain with the blinding accumulator and retains the
  commitment key and the fold transcript (both non-owning).
- `Step` folds one incoming satisfied statement into the accumulator and
  disposes the superseded accumulator. Incoming statements are prepared
  relaxed instances (`u = 1`, `E = 0`, identity error commitment, zero
  error-opening witness via `HyraxOpeningWitness.CreateZero`) or any prior
  relaxed instance over the same constraint system. The incoming triple is
  left intact for the caller to dispose; the fold copies what it needs.
- `Finalize` compresses the final accumulator (see below). The chain is
  left intact, so `chain.Accumulator.Instance` — the final folded
  instance — remains available as the public statement the verifier
  checks against, until the chain is disposed.

`RelaxedR1csAccumulator` is the `(Instance, Witness, ErrorOpeningWitness)`
bundle that travels through the chain; it owns disposal of its three
members. The chain owns its current accumulator; a consumer that reads
`Accumulator.Instance` for verification must not dispose it.

## Compression

There is **no separate folded-proof type.** A folded relaxed instance is
just a relaxed instance, and the unified Spartan prover proves relaxed
instances natively. `FoldChain.Finalize` calls

```
MaskedSpartanProver.Prove(accumulator.Instance, accumulator.Witness,
    accumulator.ErrorOpeningWitness, freshTranscript, …)
```

and returns the resulting `MaskedSpartanProof`. The masked prover runs the
relaxed outer sumcheck on `(A·z) ∘ (B·z) − u · (C·z) − E`, opens `E(r_x)`
against the instance's error commitment under the folded opening witness,
and applies the Category-A multilinear masking — so the compressed proof
is itself zero-knowledge over the folded witness. The base
`SpartanProver.Prove` also accepts a folded instance; `MaskedSpartanProver`
is the ZK default for the compressed proof.

The verifier checks the proof against the **final folded instance**
(`chain.Accumulator.Instance`), which `Finalize` re-absorbs into the
compression transcript exactly as `MaskedSpartanVerifier.Verify` replays
it. The folded instance carries the fold challenges' effect in its `u`,
public inputs, and error commitment.

### Independent transcripts

The chain holds **one** fold transcript across every `Step`, so the fold
challenges `r₁, r₂, …` chain and are non-malleable across the sequence.
Compression uses a **separate, fresh** transcript. The verifier replays
the compressed proof against the final folded instance only — it does
**not** re-derive the fold challenges. Re-deriving them would be
incremental-verification (IVC), which is out of scope here: this layer is
a zero-knowledge *aggregation*, not a verifiable-computation chain. The
fold challenges are already baked into the folded instance, so the
fold-transcript and the compression-transcript are independent.

### Commitment-key consistency

A single `HyraxCommitmentKey` — or byte-identical derivations of it
(`HyraxCommitmentKey.Derive` is deterministic in its vector length, seed,
curve, and hash-to-curve) — must back every error, cross-term, and
witness commitment across the chain and the compression, so the
homomorphically-folded error commitment opens under the same basis the
compression prover uses. The key's `VectorLength` must cover the largest
Hyrax column count in play: the witness MLE is over the column variables
(`log₂ n`), the error and cross-term commitments over the row variables
(`log₂ m`); for `n ≥ m` the witness column count dominates.

## Ownership and disposal

`Fold` returns three owned disposables; `FoldChain.Step` transfers them
into a new accumulator and disposes the previous one. `FoldChain` disposes
only its accumulator — the commitment key and both transcripts are
caller-owned. The pool is threaded from the caller through every
operation. A fold step requires both sides over the same curve,
dimensions, and public-input count; `Fold` validates and throws
`ArgumentException` otherwise.

## Security properties

- **Completeness.** Folding `k` satisfied statements into the blinding
  accumulator yields a satisfied folded instance that compresses to a
  proof which verifies against that instance. Gated by
  `FoldChainTests` and `FoldChainRoundtripTests` (one-multiply chains of
  1/2/3 and a two-multiply chain of 2).
- **Soundness.** The fold step performs no satisfaction check — it folds
  the *claimed* error vectors algebraically. An unsatisfied incoming
  statement leaves the accumulator's stored error inconsistent with its
  true error by the `r²`-weighted incoming residual, so the masked
  prover's satisfaction check at compression throws
  `R1csNotSatisfiedException`. Gated by `FoldChainSoundnessTests`. A
  compressed proof also does not verify against a different final folded
  instance (`FoldChainFailureTests`).
- **Zero knowledge.** The blinding accumulator randomises the folded
  witness, `u`, and error; the masked prover then hides the folded
  witness in the compressed proof. `FoldChainIndistinguishabilityTests`
  checks (via a per-byte chi-squared homogeneity test on the proof's
  blinded sections, across statements folded under a shared blinding
  seed) that the compressed proof does not reveal which statement was
  folded. The masked prover's own witness-indistinguishability is gated
  separately by `MaskedSpartanIndistinguishabilityTests`; this leg checks
  the end-to-end fold-then-compress composition.
- **Determinism.** Under a fixed `ScalarRandomDelegate` seed threaded
  through `Start → Step → Finalize`, the compressed proof is byte-stable
  (`FoldChainFixtureTests`).

## Consumer shape

The intended consumer is `Lumoin.Verisync` (the Fast CASPaxos / PIC
integration). Each accepted command in a canonical sequence corresponds
to one R1CS instance attesting that the command was validly applied to
the predecessor state; `Step` folds one such statement per accepted
command, on the hot path between consensus append and state-machine
apply, and `Finalize` produces an audit proof on demand (at checkpoints,
on operator request, or on cross-trust-plane verification). Compression
amortises across many fold steps. `SPARTAN-ZK-DESIGN.md` § 4.5 has the
full consumer rationale.

## What changed from the design doc

`SPARTAN-ZK-DESIGN.md` § 4 was written before implementation and projects
a `FoldedSpartanProof` wrapper carrying the relaxed-instance bytes plus a
base proof. As built there is **no such type**: compression produces a
plain `MaskedSpartanProof`, and the final folded `RelaxedR1csInstance` is
surfaced by the chain (`Accumulator.Instance`) as the public statement —
the verifier takes the instance and the proof separately, the same shape
the base and masked verifiers already use. The fold step is the static
`RelaxedR1csFold.Fold` (which also returns the folded error-opening
witness and absorbs the cross-term commitment internally), not the
projected `FoldStepDelegate`. See § 4.8 of the design doc.

## Commitment-scheme requirement: additively-homomorphic only

The fold step combines the accumulator's error commitment, the cross-term
commitment, and the incoming error commitment *homomorphically* —
`C_folded = C_acc + r·C_cross + r²·C_in`, computed with the group's add and
scalar-multiply on the commitment bytes (`RelaxedR1csFold.CombineCommitment`).
This requires an **additively-homomorphic** commitment, which the Pedersen-based
Hyrax provider is.

A hash-based commitment (BaseFold, FRI) is **not** additively homomorphic — a
Merkle root over a codeword has no algebraic structure that lets two roots be
combined into a root of the linear combination. Such a scheme therefore cannot
back a fold chain at all: the incompatibility is in the *accumulation* (the
fold), not merely in hiding. `FoldChain.Start` enforces this up front, throwing
when `provider.IsAdditivelyHomomorphic` is false, rather than failing deep inside
the first fold.

BaseFold (added in batch AB) serves the **direct** Spartan prove/verify paths
instead — `SpartanProver.ProveBaseFold` / `MaskedSpartanProver.ProveBaseFold`
and their verifier counterparts — which never combine commitments and so have no
homomorphism requirement. Aggregating many BaseFold statements would need a
different accumulation technique (e.g. a hash-based accumulation scheme), which
is out of scope. See `BASEFOLD.md`.
