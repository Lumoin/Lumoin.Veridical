# Security-bits ledger — per-proof-path knowledge-soundness accounting

This note explains the computed ledger `WellKnownSecurityLevels` produces and the
claims each Spartan proof path in this library can support. It unifies the
boundaries that previously lived apart — the Ligero opened-column derivation
(`Ligero/WellKnownLigeroParameters`), the BaseFold IOPP query derivation
(`BaseFold/WellKnownBaseFoldIoppParameters`), the ZK-BaseFold hiding budget
(`ZkBaseFoldPolynomialCommitmentScheme`) and the statistical-mask ledger
(`BaseFold/WellKnownStatisticalMaskParameters`, `ZK-STATMASK-DESIGN.md`) — into
one per-path bottleneck figure.

## The model

A Fiat-Shamir-compiled Spartan proof fails soundness only if one of a small set
of bad events occurs. Each event carries a bound on its probability; expressed
in bits (`−log2`), the path's **effective knowledge-soundness level is the
minimum term**, because a forger attacks the cheapest event and can grind the
Fiat-Shamir transcript at one hash evaluation per attempt. An effective level of
`λ` bits therefore means about `2^λ` expected hash evaluations to forge — which
is why a nominally parameterised proof that *realises* only 24 bits (see the
clamp below) is a practical target while 128 bits is not.

The terms per path:

| Term | Event | Bound |
| --- | --- | --- |
| Proximity | The committed word is far from the code yet every opened column / query repetition checks out | Ligero: `openedColumns · −log2(1 − δ)`; BaseFold: `queryCount · −log2(1 − δ)` |
| Sumcheck | A forged round polynomial survives the random evaluation point in both Spartan phases | `(3·outerRounds + 2·innerRounds)/r` |
| Field low-order | Random-linear-combination collisions, decode gaps, BaseFold commit-phase events | `poly(shape)/r`, deliberately over-weighted (see below) |

`r` is the scalar-field order; every field term uses the conservative floor
`log2(r) ≥ BitLength(r) − 1` (254 for BLS12-381, 253 for BN254). The low-order
weights are intentionally loose — cubic in the codeword length for Ligero,
`(8/3)·d` for BaseFold — chosen to dominate the polynomial factors of the
published error bounds rather than to be tight; their role in the ledger is to
show they sit hundreds of bits above the proximity bottleneck for every shape
this library commits, and they should not be quoted as tight bounds.

## The per-column/per-query bits and the regimes

For a code of rate `ρ = 1/c`, one opened column (Ligero) or query repetition
(BaseFold) contributes `−log2(1 − δ)` bits, where the proximity parameter `δ`
depends on the regime. The support behind a regime differs by code family:
Ligero's row code is Reed-Solomon, where the correlated-agreement literature is
strongest; BaseFold's wired code is the random foldable code, where several
RS-only results do not transfer.

- **Unique decoding** (`(1 − ρ)/2`, Ligero; `δ_min/2`, BaseFold). For Ligero's
  Reed-Solomon rows this is fully proven (Ben-Sasson, Carmon, Ishai, Kopparty,
  Saraf, FOCS 2020 / J.ACM 2023). For BaseFold's random foldable code,
  correlated agreement at half the minimum distance is an **open conjecture**
  for general linear codes (Diamond, Posen, IACR CiC 1(1) 2024, Conjecture 1);
  the uncontested classical general-code radius is `δ_min/3`. BaseFold query
  counts under this regime rest on that conjecture.
- **Johnson list decoding** (`1 − √ρ`, Ligero; doubly-applied Johnson
  `J(J(δ_min))`, BaseFold) — what the Reed-Solomon proximity-gap theorem
  respectively the BaseFold paper's Theorem 3 proves (the latter over foldable
  codes, via Ben-Sasson–Kopparty–Saraf correlated agreement for arbitrary
  linear codes plus the loss-free mutual upgrade of WHIR Lemma 4.10). **This is
  the wired default everywhere.**
- **One-and-a-half Johnson** (`1 − (1 − δ_min)^(1/3)`, BaseFold only) — the
  radius proven for **every linear code**, including the wired random foldable
  code, by Zeilberger, "Khatam: Proximity Gaps For Multilinear Evaluation For
  All Linear Codes" (IACR ePrint 2024/1843, CRYPTO 2026), with the same radius
  reached independently by Gao, Kan, Li (IACR ePrint 2024/1810). Per-query bits
  price the theorem's `ε, η → 0` limit (same convention as the Johnson pricing
  below); the slack-controlled commit-phase error `3d/(εη·|F|)` is a separate
  field-side term — at the wired slacks `ε = η = 2^-55` it stays near `2^-137`
  for every shape this library commits
  (`WellKnownSecurityLevels.BaseFoldOneAndAHalfJohnsonCommitTermBits`). At the
  wired distance (0.728) the radius (≈0.352) lies inside the unique-decoding
  ball (0.364), so the commitment binds a unique multilinear polynomial and no
  cross-opening list ambiguity arises; the crossover where this radius passes
  `δ_min/2` is `δ_min ≈ 0.764`. The theorem covers the folding IOPP and binds
  the final oracle to the committed polynomial at the folding point; the
  interleaved sumcheck composes per the BaseFold paper (its `~2d/|F|` term is
  negligible here), and the library opens each polynomial in its own IOPP
  invocation, so no batched-opening term arises.
- **Conjectured capacity** (`min(1 − ρ, δ_min)`) — **the underlying
  proximity-gaps-to-capacity conjectures are refuted in their plain form** for
  Reed-Solomon codes (Crites, Stewart, IACR ePrint 2025/2046; Krachun, Kazanin,
  Haböck, IACR ePrint 2026/782), and no capacity-regime analysis exists for
  random foldable codes at all. The BaseFold figure is additionally clamped to
  the code's distance (`δ_min = 0.728 < 1 − ρ = 0.875` for the wired shape).
  Retained for parameter comparison only; no soundness claim may rest on it.

At rate 1/4, Johnson gives `−log2(√ρ) = 1` bit per opened column; at rate 1/16
it gives 2. (The capacity figures are 2 and 4 — quote them only with the
refuted-as-stated conjecture named.)

A Reed-Solomon instantiation of the BaseFold IOPP would unlock the RS-only
list-decoding analysis of Haböck (IACR ePrint 2024/1571): soundness at
`θ = 1 − (1 + 1/(2m))·√ρ`, about 86 repetitions at rate 1/8 for 128 bits at
the analysis' multiplicity parameter `m = 64` (small `m` prices more — 101 at
`m = 3`) — roughly a third of the wired count. That requires swapping the commitment code
(an FFT-domain Reed-Solomon encoder over the scalar field), not a parameter
change, and is out of scope for the foldable-code parameter sets documented
here.

**Pricing convention (the η technicality).** The proximity-gap theorem proves
the list-decoding statement for `δ ≤ 1 − √ρ − η` with an error term polynomial
in `1/η`; at the radius itself (`η = 0`) nothing is literally proven. This
library — like the reference Ligero deployments it interoperates with — prices
the per-column bits **at the Johnson radius**, i.e. the `η → 0` limit. At any
concrete `η` the provable per-column figure is marginally lower and the
`η`-dependent error is a separate field-size term: for the wired CLI shape,
`η = 2^-12` costs about 0.1 of the 128 proximity bits (≈ 127.9) while the
theorem's `η`-error term stays near `2^-150`. Quote the wired set as "≈ 128-bit
(Johnson-radius pricing)" when strict-theorem precision matters.

## The clamp — why a small circuit silently under-realises its query count

A Ligero opening cannot reveal more columns than the code's **extension width**
`(c − 1)·2^⌊d/2⌋` for a `d`-variable polynomial; the opened count is
`min(queryCount, extensionWidth)`. The requested query count is therefore a
*target*, not a guarantee: a 6-variable polynomial at rate 1/4 has only
24 extension columns, so *any* query count ≥ 24 realises 24 columns × 1 bit =
**24 bits** under Johnson — regardless of whether 32, 128 or 1000 columns were
requested. Raising the query count past the width is a no-op; the lever that
actually helps a small circuit is the **rate**: at rate 1/16 the same
6-variable polynomial has 120 extension columns at 2 bits each, so 64 opened
columns realise the full 128-bit Johnson target.

`WellKnownSecurityLevels.ThrowIfLigeroSoundnessClamped` turns the clamp into a
loud failure; the `veridical prove`/`verify` tool calls it on both embedded
openings (the error opening over the row variables and the witness opening over
the column variables) at prove *and* verify time.

BaseFold's IOPP repetitions are independent index draws with no width clamp, so
its query count realises its target for every polynomial size.

## Per-path claims

- **Spartan over Ligero (unmasked)** — `ComputeSpartanOverLigero`. Binding,
  **not hiding** (deterministic Merkle root, cleartext opened columns).
  Transparent, hash-based. The CLI's wired set (BLS12-381, rate 1/16,
  64 columns, BLAKE3-32) realises proximity `64 × 2 = 128` bits (Johnson);
  sumcheck and field terms sit near 249 and 220+ bits for its circuit sizes, so
  the effective level is 128 bits.
- **Spartan over BaseFold (plain)** — `ComputeSpartanOverBaseFold`. Binding,
  not hiding. The wired 128-bit Johnson query count is ≈ 273 repetitions
  (`WellKnownBaseFoldIoppParameters.ClassicalSecurityDefaultQueryCount`). The
  named one-and-a-half-Johnson preset
  (`ClassicalSecurityOneAndAHalfJohnsonQueryCount`, ≈ 205 repetitions) realises
  the same 128-bit target under the CRYPTO 2026 foldable-code theorem with
  about a quarter smaller openings; it is a distinct parameter set — its proof
  bytes differ from the default's — and the ledger prices its commit-phase
  slack term separately (see the regimes section above).
- **Masked Spartan over ZK-BaseFold** — `ComputeMaskedSpartanOverZkBaseFold`.
  Same soundness shape at the lifted variable count `d + t`; **statistically
  hiding** under the enforced hiding budget (the lift `t`) with the statistical
  sumcheck mask (`ZK-STATMASK-DESIGN.md`). The hiding axis is reported as a
  `HidingKind`, not as bits — the budget and mask ledger are constructions with
  their own enforced conditions, not a single-number bound.
- **Masked Spartan over Hyrax** — computationally hiding (Pedersen under
  discrete log); its binding is computational (DL), so the hash-grinding model
  above does not transfer verbatim and no ledger factory is provided for it
  here.
- **WHIR (plain)** — `Whir/WhirParameterSchedule.Create` computes the full WHIR
  round-by-round soundness ledger (the initial and main-loop folding,
  out-of-domain, shift-query, final-randomness, and constraint-batching error
  families) at derivation and throws when the worst row misses the target;
  `WellKnownSecurityLevels.WhirProximitySoundnessBits` and
  `ThrowIfWhirSoundnessClamped` surface the same figure to consumers. Unique
  decoding is the wired default and is fully proven; the Johnson list-decoding
  regime prices its mutual-correlated-agreement error from the proven BCHKS25
  Theorem 1.5 bound (IACR ePrint 2025/2055, mutual form per Haböck ePrint
  2025/2110), so both offered regimes are theorem-backed; the capacity regime is
  refused for soundness claims. Binding, **not hiding** (deterministic Merkle
  root, cleartext final polynomial and opened coset blocks).
- **Hiding WHIR (HVZK)** — `Whir/WhirZkParameters.Create` prices the
  zero-knowledge soundness ledger: the masked-sumcheck fold rows (the identity
  term carries the mask message length and both decoding lists), one mask
  spot-check row per mask group at the derived spot-check count, and the same
  loud under-target clamp. The honest-verifier zero-knowledge distance — the
  private out-of-domain admissibility union — is reported as the separate
  `PrivacyErrorBits` figure: like ZK-BaseFold's hiding axis above, privacy
  bounds a different adversary and is never folded into the soundness minimum.
  **Statistically hiding**: every scheduled opening is simulatable within the
  enforced per-oracle encoding-randomness budgets (the codeword-slack fit guard
  refuses any shape whose opened set could saturate a limb), and the
  witness-free transcript simulator in `Lumoin.Veridical.Analysis` exercises
  the simulation argument end to end.

## What this ledger does not cover

Zero-knowledge/hiding distances, key security of the curves themselves,
post-quantum margins (see `SECURITY.md`'s ledger), and the soundness of
statement *construction* (a proof attests the described circuit is satisfiable;
whether the description is the claim a relying party needs is an application
concern).
