# Spartan ZK transformation architecture

This document describes the architecture under which zero-knowledge
transformations attach to the base Spartan2 prover in
`Lumoin.Veridical.Core.Spartan`. It is prescriptive about the shape
future implementations must fit; it is not a status report on what
currently ships. The base prover is described in `SPARTAN2.md`; the
broader Spartan posture, including the wire-format-interoperability
story, is in `README.md`.

## § 1 Purpose and reading order

The base Spartan prover provides limited zero-knowledge by way of
the Hyrax witness commitment, which hides the witness MLE bytes but
does not hide the per-round sumcheck messages or the terminating
matrix evaluations. Several use cases the project anticipates
require strictly stronger ZK: statistical hiding of all round
messages within a single proof, and hiding of the full history of
folded steps in an incremental composition. The constructions that
provide these properties differ enough in shape that a single
"`MaskedSpartanProver`" type cannot represent them simultaneously
without compromising either category.

The document below partitions the design space into two architectural
categories, names the existing-code boundaries each category attaches
to, sketches the delegate signatures each category needs, and shows
how proofs from the two categories coexist in the type system. The
intended readers are future agents implementing a specific ZK
construction, reviewers evaluating whether a proposed ZK upgrade
preserves the architecture, and application developers wiring a
specific ZK property into their use case.

The document is forward-looking. The base prover's preservation
across all future ZK constructions is the architecture's principal
constraint, and that constraint is stated explicitly so it does not
drift across batches.

## § 2 The two categories

ZK transformations attach to the base Spartan prover in two
architecturally distinct ways. The distinction is not a spectrum
between weaker and stronger ZK; it is a structural difference in
where the transformation sits relative to the protocol's internal
boundaries and what kind of proof object it produces.

**Category A is round-message-mask ZK.** A category-A transformation
operates inside the sumcheck driver: it replaces each cleartext round
polynomial in the prover's sumcheck schedule with a transformed
round message that the verifier can validate against the round's
algebraic identity without learning the polynomial's coefficients.
The transformation sits between the pure round-polynomial computation
that `SumcheckRoundComputation` produces and the transcript-driven
absorb step that `OuterSumcheckProver` and `InnerSumcheckProver`
currently perform. A category-A construction produces a single proof
of a single statement; the proof's structure is the base proof shape
augmented with the per-round side data the transformation needs.

**Category B is fold-with-randomness ZK.** A category-B transformation
operates above the single-proof boundary: it folds a sequence of
R1CS instance–witness pairs into a running accumulator across a
randomness source, and a final compression step turns the accumulated
relation into one proof. ZK comes from a random instance folded in
at a fixed step before compression; once that step is taken, the
accumulator hides the history of the folded instances. The
transformation does not modify the inner sumcheck rounds at all —
the base prover is run, possibly many times, against a sequence of
instances, and the fold step composes the results.

The two categories differ in four properties that future
constructions inherit from whichever category they belong to:

- *What gets hidden.* Category A hides the round messages and
  terminating evaluations of one proof. Category B hides the
  history of folded instances in an incremental composition. A
  single category-B proof on its own — one fold step, one
  compression — provides ZK over the trivial composition of one
  instance; the value is in the chain.
- *Where the boundary sits.* Category A boundaries are inside the
  sumcheck driver, between per-round computation and per-round
  absorb. Category B boundaries are between proof invocations,
  inside the IVC layer that composes them.
- *Composition pattern.* Category A produces one proof object per
  statement. Category B produces a sequence of running accumulator
  states that compress to one proof at the end. A consumer that
  wants both — per-statement ZK and per-chain ZK — wires the two
  together by feeding category-A-masked instances into a category-B
  fold; the two transformations layer naturally.
- *Security flavor.* Both categories admit constructions that
  yield statistical or computational ZK in the random-oracle model.
  The property does not distinguish the categories. The category
  is determined by where the transformation attaches and what shape
  of proof it produces, not by which security definition it meets.

The literature has examples of each category. Setty 2020 §8 (Setty,
"Spartan: Efficient and general-purpose zkSNARKs without trusted
setup", IACR ePrint 2019/550) describes a category-A construction
for the original Spartan: send each sumcheck round message as a
Pedersen commitment with auxiliary equality, product, and knowledge
proofs so the verifier checks the round identity without seeing the
cleartext message. The same paper's open-source descendant, the
`microsoft/Spartan2` Rust crate, ships a category-B construction
instead: the prover's verifier-circuit-of-the-base-Spartan-verifier
witness is folded through a NIFS-style scheme and the folded
accumulator is the final ZK object. Both are valid Spartan ZK
upgrades; they sit at different layers and produce different proof
shapes.

A further example, also category B, is documented in the Vega paper
(Kaviani and Setty, "Vega: Low-Latency Zero-Knowledge Proofs over
Existing Credentials", IACR ePrint 2025/2094) §2.1.2 under the name
NovaBlindFold: the prover encodes the verifier's algebraic checks of
the non-ZK SplitSpartan / SplitNeutronNova prover as an R1CS
instance, folds that instance into a random committed-relaxed R1CS
companion via Nova's folding scheme, and the folded accumulator is
the ZK proof. The NovaBlindFold technique is the same fold-with-
randomness shape as the `microsoft/Spartan2` mechanism; it is
documented separately because Vega is the clearest published
description of the technique applied to Spartan-shaped verifiers.

The architecture below treats both categories as first-class. The
choice of which category implements first is the reviewer's per
the architecture's recommendation in §6 and the project's medium-term
priorities, and is not settled in this document.

## § 3 Category A: Round-message-mask ZK

### § 3.1 What it is

A category-A transformation is a map `T_A` from a cleartext sumcheck
round polynomial to a transformed round message and some bookkeeping
state. The transformation has two properties:

1. **Hiding.** A consumer of the transformed round message cannot
   recover the cleartext round polynomial's coefficients without
   breaking an underlying hardness assumption (computational ZK) or
   without learning information that is unconditionally unrecoverable
   (statistical ZK).
2. **Algebraic identity preservation.** The verifier can perform the
   round's identity check — that the round polynomial evaluated at
   the squeezed challenge equals the running claim's expected value
   — using only the transformed round message and a verifier-side
   transformation `T_A^V`. The verifier does not need the cleartext
   round polynomial.

`T_A` and `T_A^V` are jointly the category-A construction. Each
construction has its own definition of "transformed round message"
and "bookkeeping state"; they share only the attachment point and
the property contract.

### § 3.2 Boundary in the existing prover

`SumcheckRoundComputation` (in
`src/Lumoin.Veridical.Core/Spartan/SumcheckRoundComputation.cs`)
contains pure functions that compute a round's `Polynomial` from
the current folded MLE state. The functions have no transcript
dependency, no operation-label constant, no commitment-key
parameter. They take MLE bytes and algebraic delegates and return a
univariate `Polynomial` of degree 3 (outer) or 2 (inner).

`OuterSumcheckProver` and `InnerSumcheckProver` (siblings in the
same directory) compose that purity with transcript absorbs and
squeezes. Each driver, per round, calls
`SumcheckRoundComputation.ComputeOuter…RoundPolynomial` to obtain
the cleartext polynomial, compresses it via
`Polynomial.Compress`, absorbs the compressed bytes onto the
transcript under
`WellKnownSpartanTranscriptLabels.SumcheckRoundPolynomial`, and
squeezes the next challenge under
`SumcheckRoundChallenge`.

Category A attaches at the seam between these two layers. Each
driver's per-round step becomes: compute the cleartext round
polynomial via `SumcheckRoundComputation`, hand it to the category-A
transformation along with the construction's bookkeeping state and
the transcript, receive back the transformed round message, absorb
the round message bytes, squeeze the next challenge. The verifier
mirrors this: reconstruct the round message from the proof bytes,
run `T_A^V` to derive the cleartext-equivalent identity check,
absorb the round message bytes, squeeze the next challenge.

The base driver's existing internal shape supports this attachment
without rewriting the round loop. The driver's per-round
absorb-and-squeeze becomes parameterised over the transformation's
round-message type, while the loop control flow and the folded MLE
state machinery stay unchanged. The category-A specific code lives
in a new sibling driver (`MaskedOuterSumcheckProver` and so on) that
delegates the per-round computation to the existing pure functions
and substitutes its own absorb step.

### § 3.3 Delegate signature

A new delegate type, `SumcheckRoundMaskingDelegate`, captures the
prover-side transformation `T_A`. Its shape is approximately:

```csharp
public delegate SumcheckRoundMessage SumcheckRoundMaskingDelegate(
    Polynomial cleartextRoundPolynomial,
    MaskingState state,
    FiatShamirTranscript transcript,
    FiatShamirHashDelegate hash,
    FiatShamirSqueezeDelegate squeeze,
    ScalarReduceDelegate scalarReduce,
    // plus algebraic delegates the specific construction needs
    SensitiveMemoryPool<byte> pool);
```

`SumcheckRoundMessage` is the new polymorphic type carrying whatever
the construction sends in a round. For an identity transformation
(no masking) it wraps the existing `CompressedRoundPolynomial`. For
a masking-polynomial construction it wraps the blended compressed
polynomial plus any commitment-opening proof material the per-round
absorb needs to include. For a Hyrax-style commit-and-prove
construction it wraps a Pedersen commitment plus the dot-product /
equality / product proofs the per-round check relies on.

`MaskingState` is the construction's per-prover-instance bookkeeping
state — the masking polynomial coefficients, the Hyrax opening
witness, or whatever the construction carries across rounds.

The verifier side has a parallel delegate
`SumcheckRoundMaskingVerifyDelegate` that takes the round message
bytes, the running claim, and the construction's verifier-side
state, and returns the post-round running claim along with the new
verifier-side state.

The exact field names, the precise shape of `SumcheckRoundMessage`,
and the bookkeeping types are settled per construction. The document
pins the *shape* — a polymorphic round message, a stateful
transformation, an algebraic-delegate-parameterised signature — not
the literal signatures.

### § 3.4 Worked example: masking-polynomial ZK sumcheck

The masking-polynomial construction is the cleanest category-A
example because it adds no new Core primitives beyond the existing
Hyrax surface and the existing scalar-random delegate. The standard
reference for ZK sumcheck via masking polynomial is Chiesa, Forbes,
and Spooner, "A Zero Knowledge Sumcheck and its Applications" (IACR
ePrint 2017/305); the same technique appears in subsequent work such
as the HyperPlonk ZK sumcheck (Chen, Bünz, Boneh, Zhang, EUROCRYPT
2023).

The construction parameterises over a single sumcheck invocation
with round-polynomial degree `d`. The prover samples a multivariate
masking polynomial `g(X_1, ..., X_n)` of total degree `d`, designed
so that the sum `Σ_{x ∈ {0,1}^n} g(x) = s` is a value the prover
sends to the verifier as part of the setup for the ZK sumcheck. The
prover commits to `g`'s coefficient vector via the existing Hyrax
PCS surface (`HyraxCommitmentKey.CommitMultilinearExtension` or an
analogue for the coefficient representation, depending on which
polynomial encoding `g` uses).

The setup absorbs the commitment to `g` onto the transcript and
the prover-sent sum `s`. The verifier squeezes a blending scalar
`ρ` under a new transcript label and the sumcheck runs on the
blended polynomial `Q + ρ · g`, where `Q` is the polynomial the
base prover's sumcheck would otherwise run on. The blended round
polynomial in round `i` is the sum of two contributions: the base
construction's per-round computation applied to the folded `Q` state
plus `ρ` times the per-round computation applied to the folded `g`
state. Both contributions are degree `d`, so the blended polynomial
is degree `d`.

At the sumcheck's terminating challenge `r`, the prover opens the
masking-polynomial commitment to reveal `g(r)`. The verifier reads
the opening from the proof, runs the Hyrax verifier on it, and
recovers the cleartext base claim via
`Q(r) = (Q + ρ·g)(r) − ρ·g(r)`.
The base claim then enters whatever subsequent identity the base
verifier was going to check.

The transformation hides `Q`'s round polynomial because the blended
round polynomial is `Q_i + ρ·g_i` for a fresh random `g`; any
hypothetical observer who tries to recover `Q_i` would need to
isolate the masking term, which is information-theoretically
impossible given the verifier sees only the blended polynomial and
later one opening of `g`. The construction's security is statistical
zero-knowledge in the random-oracle model.

For the Spartan-specific application, the construction is applied
twice — once to the outer (degree-3) sumcheck with a masking
polynomial of total degree 3 and matching variable count `log m`,
and once to the inner (degree-2) sumcheck with degree 2 and variable
count `log n`. The two masking polynomials are sampled independently
from one another. The setup absorbs both commitments and squeezes
two blending scalars `ρ_outer` and `ρ_inner` in the appropriate
positions of the transcript schedule. The outer terminating
evaluations `(claim_Az, claim_Bz, claim_Cz)` enter the verifier's
outer terminating identity check after `ρ_outer · g_outer(r_x)` is
subtracted from the outer sumcheck's terminating running claim.
The inner terminating identity has the analogous adjustment.

### § 3.5 Worked example: Hyrax-style commit-and-prove

The other published category-A construction for Spartan is the one
the original Setty 2020 paper describes in its §8 implementation
notes: send each sumcheck round message as a Pedersen commitment to
the round polynomial's coefficients, and accompany the commitment
with the zero-knowledge subprotocols the Hyrax paper (Wahby,
Tzialla, shelat, Thaler, Walfish, "Doubly-Efficient zkSNARKs Without
Trusted Setup", IACR ePrint 2017/1132) introduces for proving
equality, product, and knowledge relationships under Pedersen
commitments. The verifier reproduces the round's identity check
against the committed polynomial via these auxiliary proofs without
seeing the cleartext coefficients. Computational ZK from DLOG.

The construction is documented here because it appears in the
literature as Spartan's original ZK upgrade and a future codebase
agent might be tempted to implement it directly from Setty 2020. The
codebase does not currently expose the Hyrax-paper subprotocols at
the per-round granularity required (`Lumoin.Veridical.Core.Commitments`
provides Hyrax-PCS commitment, opening witness, and IPA opening; it
does not provide standalone proofs of equality, product, or
knowledge as separate primitives). Implementing this construction
therefore requires adding three new commitment-layer primitives —
a per-round proof of equality, a per-round proof of product, and a
per-round proof of knowledge — before the per-round message
transformation can compose. The roadmap in §6 reflects this
dependency.

### § 3.6 Wire format implications

Category-A constructions produce a single statement's proof with
per-round side data that varies by construction. The wire format
shape is therefore construction-specific: the masking-polynomial
construction's proof has a base proof prefix plus two masking-
polynomial commitments and two openings; the Hyrax-style commit-
and-prove construction's proof has a base proof structure where
each per-round entry is augmented with per-round commitment and
proof material. The two shapes are incompatible.

The architecture commits to the parallel-proof-types approach
rather than extending `SpartanProof` with polymorphic round-message
sections. Each category-A construction gets its own sibling proof
type — `BcsMaskedSpartanProof` (the masking-polynomial construction
of §3.4), `HyraxMaskedSpartanProof` (the commit-and-prove
construction of §3.5), and so on for any further constructions —
and each sibling has its own byte layout, its own
`*SpartanProof.Build` factory, and its own
`*SpartanVerifier` companion. The base `SpartanProof` and the
base `SpartanVerifier` stay byte-untouched and method-signature-
untouched.

The architectural rationale is the constraint stated in §1: the
base prover is preserved unchanged across every future ZK
construction. Adding polymorphic round-message sections to
`SpartanProof` would break that constraint at the wire-format level
because every wire-format byte offset becomes dependent on the
construction-variant tag. Sibling proof types preserve the base
wire format while still allowing each construction its full
expressive freedom.

### § 3.7 Limitations and composition

A category-A proof attests one statement. Composing many statements
ZK-ly across an incremental sequence requires layering a category-B
transformation on top. The two transformations layer cleanly: each
inner statement that enters the category-B fold is a base R1CS
instance plus a witness, and whether that R1CS instance was proven
ZK-ly in isolation is independent of whether the fold provides ZK
over the chain. A consumer that wants both per-statement and
per-chain ZK feeds category-A-masked R1CS instances into the
category-B fold step; the fold step does not need to know that the
inner statements are themselves ZK.

The composition is described in §4.7 from the category-B side.

## § 4 Category B: Fold-with-randomness ZK

> **As built (Batch S.3).** § 4.1–§ 4.8 below are the pre-implementation
> architecture. The construction shipped in Batch S.3; the authoritative
> as-built reference is `FOLDING.md` in this directory, and § 4.9
> reconciles the projected surfaces with the implemented types. The main
> divergence: there is no `FoldedSpartanProof` wrapper — compression
> produces a plain `MaskedSpartanProof` over the folded
> `RelaxedR1csInstance`, which the chain surfaces separately as the
> public statement.

### § 4.1 What it is

A category-B transformation is a map `T_B` from a sequence of
committed R1CS instance–witness pairs and a randomness source to a
single folded instance–witness pair such that the folded instance
hides information about the individual inputs. A subsequent
compression step turns the folded instance into a final proof; the
compression step inherits the hiding property from the fold's
randomness contribution.

Three properties define the category:

1. **Multi-step folding.** The fold step combines two
   instance–witness pairs into one of the same shape. Repeated
   application reduces a sequence of `k` pairs to a single pair in
   `k − 1` fold steps. The folded pair satisfies the same kind of
   constraint system as the inputs — for example, Nova folds two
   relaxed R1CS instances into one relaxed R1CS instance.
2. **Randomness as hiding source.** The fold step consumes a
   verifier-chosen randomness that, when combined with at least one
   random committed-relaxed-R1CS instance in the chain, produces a
   folded accumulator that hides the original inputs. The exact
   procedure varies by construction; the Nova-style approach folds
   a random instance into the chain at the final step before
   compression, while NovaBlindFold puts the random instance at the
   start and folds the actual statements into it. The architectural
   shape is the same: random instance plus actual instances plus
   fold steps yields a hiding accumulator.
3. **Final compression.** The folded accumulator on its own is not
   the proof; the proof comes from running a SNARK (in this
   architecture, the base Spartan prover) over the relation that
   the folded accumulator satisfies. The compression step is the
   bridge from the category-B accumulator to a wire-format proof.

`T_B` and the compression step are jointly the category-B
construction.

### § 4.2 Boundary in the existing prover

The current codebase has no public IVC layer. The base
`SpartanProver` and `SpartanVerifier` operate on a single R1CS
instance per invocation. The internal infrastructure that would
support a fold step exists in pieces — `R1csInstance` is a
first-class type, `R1csWitness` is a first-class type, the
`R1csMatrix` family handles sparse-COO matrix operations, the
Hyrax surface handles witness commitments — but no fold step
operation is exposed and no relaxed R1CS variant is documented as
a public type.

A category-B implementation introduces three new public surfaces:

- A new leaf type for the folded relation. Nova-style folding works
  on *relaxed* R1CS, where each instance carries an additional
  scalar `u` and an error commitment `E` such that
  `(Az) ∘ (Bz) = u · (Cz) + E`. A category-B implementation needs
  a `RelaxedR1csInstance` (and possibly `RelaxedR1csWitness`) type
  with byte layouts and validators. These types live in
  `Lumoin.Veridical.Core.ConstraintSystems` alongside the existing
  `R1csInstance`.
- The fold step operation as a public delegate-shaped surface.
  Input is two relaxed instance–witness pairs (the running
  accumulator and one new statement to fold in) plus a randomness
  source plus a transcript. Output is the new running accumulator.
- The compression operation as a public delegate-shaped surface.
  Input is the final running accumulator. Output is a
  `FoldedSpartanProof` carrying the accumulator's bytes plus a
  base Spartan proof over the accumulator's R1CS relation.

The base prover is unchanged; the compression step calls
`SpartanProverExtensions.Prove` on the accumulator's R1CS relation,
which means the architecture's preservation constraint from §1 is
respected.

### § 4.3 Delegate signature

The fold step delegate:

```csharp
public delegate (RelaxedR1csInstance Folded, RelaxedR1csWitness FoldedWitness)
    FoldStepDelegate(
        RelaxedR1csInstance left,
        RelaxedR1csWitness leftWitness,
        RelaxedR1csInstance right,
        RelaxedR1csWitness rightWitness,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate scalarReduce,
        // plus the scalar and group delegates the fold needs
        SensitiveMemoryPool<byte> pool);
```

The compression delegate:

```csharp
public delegate FoldedSpartanProof FoldCompressDelegate(
    RelaxedR1csInstance accumulatorInstance,
    RelaxedR1csWitness accumulatorWitness,
    FiatShamirTranscript transcript,
    // plus the full base-prover delegate set
    SensitiveMemoryPool<byte> pool);
```

The compression delegate is a thin wrapper around the base prover —
it constructs the accumulator's R1CS shape, hands it to
`SpartanProver.Prove`, and packages the result into a
`FoldedSpartanProof`.

The randomness source is the existing `ScalarRandomDelegate`, the
same delegate the Hyrax blinding factors use. No new delegate type
is needed for the randomness contribution; the fold step consumes
randomness through the standard scalar-random delegate, which
production callers wire to an OS RNG and test callers wire to the
deterministic source.

As with §3.3, the exact field names and the precise shapes are
settled per construction. The shapes above are the architecture's
view of what the boundary needs.

### § 4.4 Worked example: Nova-style fold-with-randomness

The Nova-style construction is the cleanest category-B example
because it has the longest published track record and an existing
reference implementation in `microsoft/Spartan2`'s `spartan_zk.rs`.
The primary reference is Kothapalli, Setty, and Tzialla, "Nova:
Recursive Zero-Knowledge Arguments from Folding Schemes" (CRYPTO
2022, IACR ePrint 2021/370). The ZK-specific variant the codebase
under consideration uses is documented as NovaBlindFold in
Kothapalli and Setty, "HyperNova: Recursive arguments for
customizable constraint systems" (CRYPTO 2024) and is the
construction Vega (cited in §2 above) describes most clearly.

The relaxed R1CS form replaces the original R1CS condition
`(Az) ∘ (Bz) = (Cz)` with the homogenised form
`(Az) ∘ (Bz) = u · (Cz) + E`, where `u` is a scalar and `E` is an
"error" vector. The base R1CS instance maps to a relaxed instance
with `u = 1` and `E = 0`. Folding two relaxed instances
`(u_1, E_1)` and `(u_2, E_2)` under a verifier-chosen scalar `r`
yields the folded instance with
`u_3 = u_1 + r · u_2` and
`E_3 = E_1 + r · cross + r² · E_2`,
where `cross` is the prover-supplied cross-term that captures the
componentwise product interactions between the two instances. The
folded relation is again a relaxed R1CS instance and can be folded
again with a third instance, and so on.

The fold step itself is not the ZK contribution; it is a
deterministic algebraic combination of the inputs. The ZK comes
from one specific instance in the chain being a fresh random
committed-relaxed-R1CS instance whose witness is uniform random in
the relation. NovaBlindFold places this random instance as the
running accumulator's initial state and folds the actual statements
into it. After the fold completes, the running accumulator is
information-theoretically uncorrelated with the actual statements
in the way the verifier observes; any property of the original
statements that could be recovered from the accumulator must have
been recoverable from the accumulator's relation alone, which is
the relation a SNARK proves in the final compression step.

The compression step in the present architecture is a call to the
base Spartan prover. The accumulator's R1CS shape is constructible
from the accumulator's `(u, E)` parameters and the original
instances' matrices; the base prover proves that the accumulator's
witness satisfies the accumulator's relation; the resulting
`SpartanProof` plus a small wrapper carrying the folded accumulator
bytes is the `FoldedSpartanProof`.

The `microsoft/Spartan2` Rust source is informant for the
construction's mechanics but is not a byte-faithful target. The
codebase's design freedom on wire format, transcript schedule, and
delegate signatures applies to the category-B implementations the
same way it applies to the base prover, per §5 of `SPARTAN2.md`
and the corresponding section of `README.md`. A category-B proof
produced by Veridical is verified by Veridical; cross-implementation
byte interop is not a goal.

### § 4.5 The Verisync consumer

The named consumer driver for the category-B architecture is
`Lumoin.Verisync`, the project's Fast CASPaxos integration that
provides canonical-sequence verification of consensus log entries.
Each accepted command in the canonical sequence corresponds to one
R1CS instance attesting that "this command was validly applied to
the predecessor state given the predecessor's commitment". The
running fold step accumulates the entire sequence into one
verifiable relation; the compression step produces an audit proof.

The Verisync surface consumes the category-B operations through
their public delegate shapes:

- `FoldStep` is called once per accepted command, between the
  consensus engine's append and the next state-machine apply. Input
  is the current running accumulator and the new command's
  instance–witness pair; output is the new running accumulator.
  The fold step is on the hot path of consensus processing and its
  per-call cost matters; the architecture commits to a
  per-fold-step cost that is the dominant term in the fold loop's
  asymptotic, not the compression's, so a Verisync deployment can
  amortise compression across many fold steps.
- `FoldCompress` is called on demand — at scheduled checkpoints,
  on operator request, or on cross-trust-plane verification
  events. Input is the running accumulator at the moment of
  compression; output is a `FoldedSpartanProof` that audit
  consumers verify with the category-B verifier.

The same surface backs the PIC bridge invariants: cross-trust-plane
authority preservation in Verisync uses fold-and-compress over the
chain of authority delegations, producing one proof per audit
window. The architectural commitment is that PIC and CASPaxos
consume the same `FoldStep` and `FoldCompress` operations; they
differ in what predicate the inner R1CS instances encode, not in
the folding machinery.

Verisync's internal consumption pattern — how its state machine
shapes per-command instances, how it interfaces with the consensus
engine, what its checkpoint schedule looks like — is Verisync's
own design work. The architecture pins the public surface Verisync
sees; it does not specify Verisync's internals.

The naming of Verisync as a concrete consumer here is the
architectural justification for category B existing as a first-
class category in this document. Without a named consumer, the
category could reasonably defer until a use case materialises. With
a named consumer in the project's medium-term roadmap, the surface
needs to be drafted now so the implementation it depends on is on
the right architectural footing.

### § 4.6 Wire format implications

A category-B implementation produces three wire-format object
shapes:

- The `RelaxedR1csInstance` byte layout, used both as the input
  to fold steps and as the intermediate running accumulator.
  Layout: the underlying R1CS shape parameters plus the `u`
  scalar (32 bytes), the error commitment bytes (a single G1
  point under Hyrax, 48 bytes for BLS12-381), and a transcript
  state snapshot if the construction needs cross-step transcript
  continuity. The exact layout is the implementation's call;
  the architecture pins the layout's components.
- The `RelaxedR1csWitness` byte layout, the prover-side complement
  to the instance. Layout: the underlying witness bytes plus the
  error vector bytes. As with the witness in the base prover, this
  type is never serialised on the wire; it lives only in the
  prover.
- The `FoldedSpartanProof` byte layout, produced by the
  compression step and verified by the category-B verifier.
  Layout: the relaxed instance bytes (so the verifier can
  reconstruct the relation), followed by a base `SpartanProof`
  over that relation. The base proof's byte layout is unchanged.

The category-B verifier deserialises the relaxed instance,
reconstructs the relation, and hands the embedded `SpartanProof` to
the base `SpartanVerifier`. The relaxed instance's bytes plus the
base proof's bytes are all the verifier sees; the running
accumulator's history is gone by the time the proof is on the
wire.

### § 4.7 Composition with Category A

A category-B fold chain whose inner statements are themselves
category-A-masked is the strongest ZK composition the architecture
provides. Each inner statement is a category-A `*SpartanProof`,
which means each inner statement hides its witness from the
verifier independently of the fold. The fold accumulates the chain
into a category-B accumulator, which hides the history of folded
statements. The two transformations layer; neither weakens the
other.

The implementation pattern: a consumer that wants both per-
statement and per-chain ZK runs the category-A prover for each
statement, but rather than emitting the per-statement proof bytes
the consumer holds the per-statement R1CS instance–witness pair
(which is the input the category-A prover already operates on
internally) and feeds those pairs into the category-B fold step.
The category-A masking applies inside the category-A prover's
internal sumchecks; the category-B fold composes the per-statement
relations regardless of whether they were proven ZK-ly in
isolation.

The composition is documented here without designing it; the
specific consumer pattern is the consumer's call. The category-A
and category-B constructions do not need to be co-designed for
this composition to work, provided each independently respects the
base prover preservation constraint from §1.

### § 4.8 The threshold-quorum consumer

A secondary category-B consumer is the threshold-quorum sliver
combination predicate used in the project's whistleblower / sliver-
verification work. The predicate is "k mutually consistent slivers
exist for the same secret"; each sliver is one R1CS instance
attesting "this sliver opens to a value consistent with the shared
secret commitment"; the fold accumulates contributors until
threshold k is reached; the compressed proof attests the threshold
without revealing the contributing slivers' bytes.

The threshold-quorum surface uses the same `FoldStep` and
`FoldCompress` operations as Verisync. The difference is what the
inner R1CS instances encode, not the folding machinery. The
architectural shape carries.

### § 4.9 As built (Batch S.3)

The construction landed on top of the unified relaxed-R1CS Spartan
prover (Batch S). `FOLDING.md` is the implementation reference; this
subsection maps the projected surfaces of § 4.2–§ 4.6 to the
implemented types and records where they diverge.

Implemented surfaces:

- **Folded relation.** `RelaxedR1csInstance` and `RelaxedR1csWitness`
  in `Lumoin.Veridical.Core.ConstraintSystems`, exactly as § 4.2
  projects. `RelaxedR1csAccumulator` bundles a relaxed
  `(instance, witness, error-opening-witness)` triple.
- **Fold step.** The static `RelaxedR1csFold.Fold`, not the projected
  `FoldStepDelegate`. It takes the scalar/group delegates the fold needs
  and returns a *third* element beyond § 4.3's projection — the folded
  error-commitment opening witness `r_{E₃}` — and absorbs the
  prover-supplied cross-term commitment into the transcript internally
  (the projected signature omitted both). The fold transcript schedule is
  pinned in `WellKnownFoldingTranscriptLabels`.
- **Chain.** `FoldChain.Start` / `Step` / `Finalize` (in
  `Lumoin.Veridical.Core.Spartan`) is the consumer driver. `Start` builds
  the NovaBlindFold blinding instance (the § 4.4 random initial
  accumulator); `Step` folds a real statement in; `Finalize` compresses.
- **Compression.** A call to `MaskedSpartanProver.Prove` (or the base
  `SpartanProver.Prove`) on the folded instance, producing a
  `MaskedSpartanProof` — *not* a `FoldedSpartanProof`.

The divergence from § 4.2–§ 4.6 / § 5: **there is no `FoldedSpartanProof`
type and no `FoldedSpartanVerifier`.** A folded relaxed instance is just a
relaxed instance, and the unified prover proves relaxed instances
natively, so the compressed proof is a plain `MaskedSpartanProof` and the
final folded `RelaxedR1csInstance` is surfaced separately
(`FoldChain.Accumulator.Instance`) as the public statement — the same
instance-plus-proof shape the base and masked verifiers already use.
Verification does not re-derive the fold challenges (no IVC): the
fold-step transcript and the fresh compression transcript are
independent, and the verifier checks the final folded instance only. This
also realises the § 5 note that "Category B folding does not get its own
variant" — a folded proof carries `Unmasked` / `MaskedMultilinear`.

## § 5 How they coexist

The proof type system after both categories ship has four distinct
proof types:

- `SpartanProof` — the base prover's output. One statement, limited
  ZK from Hyrax witness commitment hiding only.
- A category-A proof type per construction
  (`BcsMaskedSpartanProof`, `HyraxMaskedSpartanProof`). One
  statement, full ZK over the prover's messages and terminating
  evaluations.
- A category-B (folded) proof — **no dedicated type** (as built, § 4.9):
  a chain of statements is compressed by running the unmasked or masked
  prover over the folded relaxed instance, so it is a `SpartanProof` /
  `MaskedSpartanProof` carrying `Unmasked` / `MaskedMultilinear`. ZK over
  the chain history comes from the blinding accumulator, not a wrapper
  type.
- The § 4.7 composition — category-B folding over category-A-masked inner
  statements — likewise produces a `MaskedSpartanProof` over the folded
  instance, not a distinct type; ZK over both per-statement and per-chain.

The type system enforces verifier dispatch: each proof type has
exactly one verifier type that consumes it
(`SpartanVerifier` for `SpartanProof`, `MaskedSpartanVerifier` for
`MaskedSpartanProof`, and so on; a folded proof carries no dedicated
type, so it is verified by the verifier matching its compression —
`MaskedSpartanVerifier` — against the surfaced folded instance). There is no polymorphic
verifier that accepts any of the four; callers pick the right
verifier for the proof they hold. Mismatch is a type error at the
call site.

The algebraic-identity-tag discriminator is a `SpartanProofVariant`
record-struct in `Spartan/`, with the variants:

- `SpartanProofVariant.Unmasked` — the base, unmasked proof over a
  relaxed R1CS instance (standard R1CS is the `u = 1`, `E = 0` case).
- `SpartanProofVariant.MaskedStatistical` — category A, the
  statistically-masked construction (SM.7b): degree-matched
  sum-of-univariates kernel masks with the filler-laundered
  weighted-opening binding. Supersedes the batch-N multilinear mask.
- `SpartanProofVariant.MaskedCfs2017Strong` — reserved; faithful CFS
  2017 Construction 6.6, largely superseded by `MaskedStatistical`
  (which achieves the statistical round masking at `O(d)` cost).
- `SpartanProofVariant.MaskedHyrax` — reserved; category A
  commit-and-prove.
- Category B folding does not get its own variant: a folded proof is
  produced by running the unmasked or masked prover over the folded
  relaxed instance, so it carries `Unmasked` / `MaskedStatistical`.
- Further entries append as constructions land.

Each proof type's `AlgebraicTag` carries the corresponding variant
entry alongside the existing `(AlgebraicRole.ZkProof,
CurveParameterSet)` pair. A consumer that needs to inspect a
proof's variant at runtime reads the tag; the runtime is the
fallback for cases where the static type isn't sufficient. The
typical case is static-type dispatch and the variant tag is the
self-documenting marker.

## § 6 Implementation roadmap

The architecture's view of which implementations make sense in which
order, informational rather than binding.

The first implementation to land is a category-A construction
because category-A constructions are smaller in scope than
category-B constructions. Within category A, the masking-polynomial
construction from §3.4 lands before the Hyrax-style commit-and-prove
construction from §3.5 because the former needs no new Core
primitives — the existing Hyrax PCS surface and the existing
scalar-random delegate are sufficient — while the latter needs three
new commitment-layer primitives (per-round proofs of equality,
product, and knowledge) that do not currently exist in
`Lumoin.Veridical.Core.Commitments`. The masking-polynomial
implementation establishes the category-A boundary in real code,
shakes out the round-message abstraction, and produces the first
sibling `*SpartanProof` type. The Hyrax-style construction then
follows the same pattern with the new commitment-layer primitives.

The second implementation to land is the category-B construction
described in §4.4. The dependency stack is larger than category A's:
the `RelaxedR1csInstance` type, the fold step operation, the
compression boundary. The named Verisync consumer makes this
implementation the project's medium-term priority; the architecture
does not propose deferring it past category A's first construction.
This construction landed in Batch S.3 as `RelaxedR1csFold.Fold` plus
the `FoldChain` driver, on top of the Batch S relaxed-R1CS prover
unification; see § 4.9 and `FOLDING.md`.

The third implementation to land is the composition from §4.7 — a
category-B fold over category-A-masked inner statements. The
composition does not require new primitives beyond what categories
A and B individually provide, so this implementation is a
straightforward wiring task rather than a new construction. The
composition implementation likely lands as part of the consumer
batch that needs it (Verisync's PIC bridge being the most likely
first need) rather than as its own batch.

The reviewer makes per-batch decisions and the architecture
informs them. Nothing in this section binds the project to a
specific implementation order; the recommendations reflect the
dependencies the architecture exposes, and changes to project
priorities can override them without compromising the architecture.

The first category-A construction landed in batch N as
`MaskedSpartanProver` with a multilinear Libra-style mask — the
masking polynomial was multilinear in the sumcheck's variable
count rather than degree-matched per-variable, leaving each round
polynomial's top coefficient bare (computational ZK in the ROM).
Batch SM.7b upgraded the masks to degree-matched sum-of-univariates
kernels (`3d + 1` coefficients for the outer cubic, `2d + 1` for
the inner quadratic) bound by filler-laundered weighted openings
(design v3 of `../Commitments/BaseFold/ZK-STATMASK-DESIGN.md`), so the
round-message channel is now statistically masked; the variant
discriminator is `SpartanProofVariant.MaskedStatistical`. The
end-to-end flavor follows the commitment scheme — computational
over the Hyrax (Pedersen/IPA) path, statistical in the ROM over
the full-ZK BaseFold provider. See `SPARTAN2.md` §10 for the
implemented construction and the §9 lineage section below for the
cross-stack ZK-flavor posture.

## § 7 What this document doesn't decide

The following decisions are deferred to per-construction
implementation efforts:

- Which specific category-A construction implements first.
  §6 recommends the masking-polynomial construction on dependency-
  stack grounds; the reviewer makes the per-batch call.
- The exact delegate signatures for `SumcheckRoundMaskingDelegate`,
  `SumcheckRoundMaskingVerifyDelegate`, `FoldStepDelegate`, and
  `FoldCompressDelegate`. The shapes in §3.3 and §4.3 are the
  architecture's view of what the boundaries need; the literal
  parameter lists are settled per implementation.
- The wire-format byte layouts for each new proof type. §3.6 and
  §4.6 pin the structure (parallel sibling proof types, what
  components each contains); the byte-level layout is the
  implementation's call.
- The project boundary. §6 recommends that category-A
  implementations stay in the existing `Spartan/` subfolder
  alongside the base prover, on the grounds that they are additive
  over the base and benefit from co-location with the base's
  internal types. A future project surface large enough to warrant
  splitting into `Lumoin.Veridical.Spartan.Zk` (or similar) is
  possible if the surface grows; the decision is not pre-made.
- The Verisync API consumption pattern. §4.5 specifies the surface
  Verisync sees from the category-B implementation; the consumer
  pattern itself — how Verisync's state machine shapes per-command
  instances, how the consensus engine interfaces with `FoldStep`,
  what the checkpoint schedule is — is Verisync's own design
  work.
- The Hyrax-style commit-and-prove construction's new commitment-
  layer primitives. §3.5 names the three primitives (per-round
  proofs of equality, product, knowledge) as a dependency; the
  primitives themselves are designed and implemented as later
  work.

## § 8 Notes on attribution and prior work

The constructions and ideas in this document trace to the
following sources. The citations were verified against the PDFs
collected in `tempdocs/Spartan/` (gitignored) and against the
`microsoft/Spartan2` Rust source where the architecture refers to
existing implementations.

Setty, "Spartan: Efficient and general-purpose zkSNARKs without
trusted setup", IACR ePrint 2019/550 (CRYPTO 2020), is the base
construction the rest of this design extends. §5.1 of that paper
contains the public-coin succinct interactive argument that the
codebase's `SpartanProver` and `SpartanVerifier` implement directly;
§8 contains the category-A commit-and-prove ZK upgrade summarised
in §3.5 above. The codebase implements the §5.1 construction; the
§8 ZK upgrade is described above but is not currently in the
codebase, by the design decision recorded in §3.5 and §6.

Chiesa, Forbes, and Spooner, "A Zero Knowledge Sumcheck and its
Applications", IACR ePrint 2017/305, is the standard reference for
the masking-polynomial ZK sumcheck technique described in §3.4. The
same technique is reused in several subsequent constructions
including HyperPlonk (Chen, Bünz, Boneh, Zhang, EUROCRYPT 2023);
the Chiesa–Forbes–Spooner reference is the cleanest standalone
treatment of the technique applied to a general sumcheck-based
IOP.

Wahby, Tzialla, shelat, Thaler, and Walfish, "Doubly-Efficient
zkSNARKs Without Trusted Setup", IEEE S&P 2018 (IACR ePrint
2017/1132), is the Hyrax paper. The codebase's
`Lumoin.Veridical.Core.Commitments` surface implements the Hyrax
polynomial commitment scheme from this paper. The per-round
zero-knowledge subprotocols Setty 2020 §8 cites are also from this
paper.

Kothapalli, Setty, and Tzialla, "Nova: Recursive Zero-Knowledge
Arguments from Folding Schemes", IACR ePrint 2021/370 (CRYPTO
2022), is the primary reference for the fold-with-randomness
mechanism on relaxed R1CS that §4.4 describes. The Nova paper is
the source of both the relaxed R1CS form and the multi-step fold
construction.

Kothapalli and Setty, "HyperNova: Recursive arguments for
customizable constraint systems", CRYPTO 2024, contains the
NovaBlindFold technique referenced in §4.4 — the specific
arrangement of fold steps and random instances that turns a Nova-
style fold into a ZK transformation. The technique applies to
constraint systems beyond R1CS; the §4.4 application is to R1CS.

Kothapalli and Setty, "NeutronNova: Folding everything that reduces
to zero-check", IACR ePrint 2024/1606, describes a related folding
scheme for zero-check relations that the architecture would
accommodate as a category-B variant without modification. The
construction is mentioned for context as the architecture's
extension point rather than as a specific implementation
recommendation.

Kaviani and Setty, "Vega: Low-Latency Zero-Knowledge Proofs over
Existing Credentials", IACR ePrint 2025/2094, contains the
clearest published description of NovaBlindFold applied to a
Spartan-shaped verifier (§2.1.2 of the paper). Vega is cited as the
secondary reference for the §4.4 worked example because the
construction's prose treatment there is more accessible than the
HyperNova paper's abstract treatment of the same technique.

Bagad, Dao, Domb, and Thaler, "Speeding Up Sum-Check Proving",
IACR ePrint 2025/1117, is an efficiency paper for the sumcheck
prover that the architecture does not consume directly. The paper
is noted here because the codebase's sumcheck implementation could
adopt some of its techniques in a future optimisation batch; that
adoption is independent of the ZK architecture this document
describes.

The `microsoft/Spartan2` Rust source (the `Spartan2-main`
codebase) is informant rather than reference target throughout
this document. Its `src/spartan_zk.rs` implements a category-B
construction along the lines of §4.4; its `src/zk.rs` contains the
verifier circuit that NovaBlindFold folds into the running
accumulator; its `src/sumcheck.rs` contains a
`prove_cubic_with_additive_term_zk` function that integrates the
verifier circuit with the outer sumcheck. The C# codebase's
category-B implementation will share the construction's
mathematical content with the Rust source while making its own
wire-format, transcript-schedule, and delegate-signature choices.

## § 9 Cross-stack ZK-security-flavor lineage

The library's posture on zero-knowledge security flavors is
explicit: over the pairing path every ZK primitive provides
**computational zero-knowledge in the random-oracle model**,
rooted in the discrete-logarithm assumption over BLS12-381. This
applies to BBS+ Schnorr-style proofs, the base Spartan2 prover's
Hyrax-witness-hiding property, and the masked Spartan variant
over Hyrax. Two statistical-in-ROM claims exist on the hash path:
the ZK-BaseFold opening (batch SM, design v3 + the Appendix A
ledger lemma) and masked Spartan proven over the full-ZK BaseFold
provider (SM.7b — the statistically-masked rounds composed with
the statistical opening).

Stronger ZK variants exist in the literature for each primitive
but require infrastructure the codebase does not currently have.
The table below maps each primitive to its current flavor, the
literature's stronger variant, and the supporting primitives
that would have to land before the upgrade becomes possible.

| Primitive                | Current flavor                | Stronger variant from the literature                                     | Required additions                                                                                                       |
|--------------------------|-------------------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| BBS+ signatures          | Computational ZK from DLOG    | No standard statistical-ZK BBS+ analogue                                 | Construction itself is fundamentally computational; PQ-secure analogues (lattice blind signatures) are research-stage    |
| Hyrax witness commitment | Computational ZK from DLOG    | Statistical-hiding via Pedersen with perfectly-hiding parameters (small) | Hyrax's perfect-hiding mode is available; the binding becomes computational. Tradeoff is local to the commitment scheme. |
| Base Spartan2            | Computational ZK from DLOG    | (Replaced by next row's masked variant)                                  | The base prover does not aim to hide round messages; the masked variant is the upgrade path.                             |
| Masked Spartan (SM.7b)   | Statistically-masked rounds; end-to-end computational over Hyrax, statistical in ROM over full-ZK BaseFold | The Hyrax-path residual is the Pedersen/IPA opening layer itself | Inherent to Pedersen/IPA; the statistical end-to-end flavor exists today via `ProveZkBaseFold`                           |
| Category B (future)      | Computational ZK from DLOG    | Statistical-ZK folding (research)                                        | Production statistical-ZK folding schemes are not well-established at this time                                          |

A cross-stack observation that is load-bearing for any future
strong-ZK upgrade decision: **end-to-end statistical ZK requires
every primitive in the composition to provide statistical ZK
individually**. A system that uses BBS+ for signature, Hyrax for
witness commitment, and the masked Spartan variant for proving
R1CS satisfaction is bounded by the weakest layer; upgrading only
the Spartan layer to its strong-PZK variant while leaving BBS+
and Hyrax in their current flavors does not strengthen the
overall property. The upgrade is only meaningful when the rest
of the stack moves with it.

The library's current ZK primitives all rely on the discrete-
logarithm assumption, which is not post-quantum secure. Post-
quantum zero-knowledge proof systems are an active area of
research (lattice-based zk-SNARKs in the Banquet / Picnic /
LANES family; the lattice-adapted Aurora and Ligero variants).
Standardisation is substantially earlier than for post-quantum
signatures (where ML-DSA, SLH-DSA, and FN-DSA have landed in NIST
FIPS). The library does not currently provide post-quantum ZK; a
post-quantum upgrade would likely involve a separate library
namespace because the cryptographic structure differs
substantially. The post-quantum trajectory is stated here without
a timeline commitment.

This lineage map is living documentation. It should be updated
when new primitives land, when stronger variants of existing
primitives become available in the codebase, or when the field's
standards shift meaningfully. The map is not a roadmap commitment;
it is an honest record of where the library sits in the
cryptographic-flavor landscape at any given time.

## BaseFold backing and the hiding caveat (batch AB)

Spartan can run over BaseFold — a transparent, hash-based, post-quantum-style
polynomial commitment — as well as over Hyrax, through the same
`PolynomialCommitmentProvider` surface. The prover/verifier algorithm is
identical; only the proof container differs (`BaseFoldSpartanProof` /
`BaseFoldMaskedSpartanProof` are BaseFold-shaped siblings of the Hyrax-shaped
proofs, sharing the scheme-independent `SpartanSumcheckProofPart`).

**Hiding caveat for the masked variant over BaseFold.** The masked construction
(this document's Category A) achieves zero-knowledge by committing masking
polynomials and the witness under a *hiding* commitment and blending the
round polynomials. Hyrax/Pedersen commitments are perfectly hiding. BaseFold's
commitment is a Merkle root over the codeword — computationally *binding* but
**not hiding** (given a candidate witness an adversary recomputes the root). So
`MaskedSpartanProver.ProveBaseFold` produces a sound argument of knowledge but
does **not** deliver the witness privacy the "masked" name implies. Achieving ZK
with BaseFold requires a *hiding* BaseFold variant (a blinded codeword), which
batch AB does not provide. Until then, masked-over-BaseFold should be read as
"the masked transcript shape, run over a transparent commitment" — useful for a
post-quantum *soundness* story, not a privacy one.

The fold chain (Category B) cannot run over BaseFold at all — folding needs an
additively-homomorphic commitment; see `FOLDING.md`.

## Hiding BaseFold and genuine ZK (batch ZK-BF)

Batch ZK-BF closes the hiding caveat above: it makes BaseFold a hiding,
zero-knowledge polynomial commitment, so masked Spartan over it is genuinely
zero-knowledge — not merely sound. The construction closes the three channels
through which an honest BaseFold opening leaks the witness, all behind the same
`PolynomialCommitmentProvider` surface (full detail in
`../Commitments/BaseFold/BASEFOLD.md`, *Zero-knowledge BaseFold*):

1. **Hiding commitment (ZK.1)** — salted Merkle leaves `hash(value ‖ salt)`, so the
   commitment and every fold root reveal nothing about the codeword.
2. **Query / base-oracle hiding (ZK.2b.1)** — a *dimension lift*: commit the real
   `d`-variable witness `f` as the `Y = 0` slice of a `(d + t)`-variable `f'` whose
   `Y ≠ 0` block is entropy, and evaluate at the protocol-fixed `(z, 0^t)`. The
   randomness lives in real variables the evaluation never ranges over, so
   `f'(z, 0^t) = f(z)` and BaseFold's soundness applies verbatim — no code change.
3. **Round-polynomial mask (ZK.2b.2)** — the Category A masking-polynomial ZK
   sumcheck of this very document (§3.4), applied to BaseFold's *internal* `f·eq_z`
   sumcheck: a masking multilinear `s` committed as its own salted BaseFold codeword
   and folded in lockstep, with the round polynomials blended `h_i + ρ·s_i`.

**Masked Spartan wiring (ZK.3).** `MaskedSpartanProver.ProveZkBaseFold` /
`MaskedSpartanVerifier.VerifyZkBaseFold` assemble a `ZkBaseFoldMaskedSpartanProof`
over `ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge`, reusing the
scheme-neutral masked orchestration core unchanged. The witness and the two masking
polynomials are committed under the hiding provider; the **public zero-error
vector** keeps a *plain deterministic* commitment, because the verifier recomputes
it rather than receiving it (a hiding commitment would diverge between the two
sides). These entries therefore take an `errorPcs` — a plain BaseFold provider over
the same code parameters — used only for the error.

**ZK flavor (ZK.4, corrected by batches SM and SM.7b).** At ZK.4 the masks at
both layers were multilinear (degree one per round), leaving each round
polynomial's top coefficient bare — computational ZK in the ROM. Batch SM
upgraded the BaseFold-internal opening mask to the degree-matched
sum-of-univariates kernel with the filler-laundered weighted-opening binding
(design v3 of `../Commitments/BaseFold/ZK-STATMASK-DESIGN.md`, Appendix A ledger lemma),
making the opening **statistical** ZK in the ROM; batch SM.7b applied the same
construction to the Spartan-level masks (degree-3 outer, degree-2 inner). SM.6
additionally found ZK.4's byte-distribution chi-squared invalid on this proof
structure (intra-proof byte duplication breaks its iid assumption; it rejected
witness-independent labelings) — with the corrected label-permutation null, all
three leakage experiments report *not detected* against the full-ZK provider.
A literal real-versus-simulated transcript test (the simulator of the design's
§5) would still need a *programmable* Fiat-Shamir oracle; the production
transcript is a real BLAKE3 hash, so the measurable claim is
witness-independence across real witness populations.
