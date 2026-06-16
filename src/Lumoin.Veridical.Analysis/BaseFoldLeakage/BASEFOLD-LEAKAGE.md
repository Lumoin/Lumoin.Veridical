# BaseFold-masked is sound but not zero-knowledge — a concrete look

`BASEFOLD.md` records a boundary in one sentence: the masked Spartan variant over
BaseFold is a sound argument of knowledge but **not** zero-knowledge, because
BaseFold's commitment is binding but not hiding. This document makes that
concrete — what "not hiding" buys an adversary, demonstrated by three
experiments of increasing strength.

## The boundary

A polynomial commitment is **binding** if a prover cannot open it to two
different polynomials, and **hiding** if the commitment (and its openings) reveal
nothing about which polynomial was committed beyond what is intentionally
disclosed. Zero-knowledge needs hiding: the proof must be simulatable from the
public statement alone, so it cannot carry witness-specific information.

BaseFold's commitment is a **Merkle root over the codeword** `Enc(coeffs)`. The
encoding is deterministic in the polynomial, and the Merkle root is deterministic
in the codeword. So the commitment is a deterministic function of the witness —
the opposite of hiding. The masked Spartan variant adds masking polynomials that
blind the *sumcheck round messages*, but the witness *commitment* it embeds is
still this non-hiding root. Masking the round messages does not hide the witness
when the commitment beside them already pins it.

## The three experiments

The experiments live in `Lumoin.Veridical.Analysis/BaseFoldLeakage` and run over
the BaseFold polynomial-commitment layer (commit + open at a point) — the layer
where the non-hiding commitment originates and which the masked Spartan proof
embeds unchanged. Each fixes one random evaluation point and samples many
witnesses, then asks whether the public proof bytes reveal something about the
witness.

### 1. Byte-distribution (`BaseFoldByteStatisticsExperiment`)

Split witnesses into two classes by a one-bit property (the low bit of the first
evaluation). Aggregate every proof's byte values into a 256-bin histogram per
class and compare by a chi-squared homogeneity statistic. The crudest probe — it
asks only whether the *distribution of byte values* differs by class.

> **Methodology correction (batch SM).** The original analytic chi-squared
> p-values below are overstated: proof bytes are heavily dependent *within* one
> proof (repetition-word base oracles, shared upper-tree Merkle digests), which
> breaks the test's independence assumption — during batch SM the analytic test
> was shown to reject even labelings *independent of the witness* (index parity,
> first-half-versus-last-half) at p < 10⁻²⁴. The experiment now assesses the
> statistic against a **label-permutation null**, which is valid under arbitrary
> intra-proof dependence. For the plain provider the *direction* of the original
> finding stands (the proof is literally deterministic in the witness), but its
> p-value should not be quoted.

**Finding (d = 3, 200 witnesses, the valid permutation-null test): not
detected**, permutation p ≈ 0.40. The pre-correction analytic test had reported
*detected* at p ≈ 10⁻⁷⁵ — see the methodology correction above for why that
figure was an artifact. The post-correction result is itself instructive: the
plain provider's proof bytes are *literally deterministic* in the witness
(experiment 3 recovers it outright), yet this aggregate byte-histogram probe —
under a valid null — cannot see it. The honest claim for the plain provider is
the structural one; this coarse statistic is simply too blunt to quantify a
leak that lives in structure rather than in marginal byte frequencies.

### 2. Classifier (`BaseFoldClassifierExperiment`)

Label each witness by the same bit; featurize each proof as its bytes normalised
to `[0, 1]`; train a logistic regression on a 70 % split and score it on the
held-out 30 %. This asks whether a *simple, linear* attack can recover the bit.

**Finding (d = 3, 200 witnesses): not detected**, ≈ 42 % accuracy (chance 50 %,
p ≈ 0.20). The naive linear model does no better than chance. This is expected:
the witness-to-proof relationship runs through a hash (the Merkle root) and the
encoding, both highly non-linear, and a linear model over a high-dimensional
proof with few samples cannot recover it. The honest reading is that this
particular weak attack fails — **not** that no attack succeeds. A structurally
aware adversary does far better, which is the next experiment.

### 3. Commitment recoverability (`BaseFoldCommitmentRecoverabilityExperiment`)

The structural attack. The proof carries the witness commitment; the commitment
is a deterministic fingerprint of the witness. So given a candidate set, the
witness behind a proof is recovered by recomputing each candidate's commitment
and matching.

**Finding: structurally certain.** Recovery succeeds every time — the experiment
recovers the secret witness from its commitment alone, among the candidates, by
recomputation. This is the definitive sense of "not hiding": an adversary who can
enumerate (or guess) candidate witnesses confirms the real one against the
commitment. For low-entropy witnesses — exactly the case privacy is supposed to
protect — this breaks zero-knowledge outright, no statistics required.

> This experiment realises the originally proposed "Merkle-path-correlation" idea through
> the commitment root rather than the per-query authentication-path bytes. The
> root is the binding commitment the whole codeword (hence every queried path) is
> derived from, so it is the cleanest deterministic fingerprint, and unlike the
> per-query revealed entries it is a first-class public artifact that needs no
> commitment-scheme-internal parsing to read. The structural conclusion is the
> same and strictly stronger.

## What the spectrum says

The three results line up as a spectrum, and — since the batch-SM methodology
correction — the spectrum is even starker than first written:

- The leak is **structurally certain** (experiment 3): the commitment pins the
  witness.
- It is **invisible to a crude aggregate probe** (experiment 1): under the
  valid permutation-null form, the byte-histogram test reports *not detected*
  even against a proof that is literally deterministic in the witness.
- It is **not recovered by a naive attack** (experiment 2): a simple linear
  classifier scores at chance.

The lesson for an educational reader: *absence of evidence from a weak attack is
not evidence of zero-knowledge.* Experiments 1 and 2 both "fail to detect"
leakage that experiment 3 proves is certainly present. A scheme is
zero-knowledge because its proofs are simulatable, not because particular
statistics happened to surface nothing.

## Implication for users

The leak above is a property of the **plain** BaseFold provider
(`BaseFoldPolynomialCommitmentScheme.Create`). If you need the witness to stay
private you have two hiding options: the Hyrax-masked path, whose Pedersen
commitment is perfectly hiding, or — new in batch ZK-BF — the hiding BaseFold
provider that keeps BaseFold's transparent, post-quantum-style soundness story. The
next section covers the latter.

## The hiding variant now exists (batch ZK-BF)

Batch ZK-BF supplies the hiding BaseFold the original write-up deferred:
`ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge` salts every Merkle
leaf, commits the witness through a dimension lift, and masks the sumcheck round
polynomials (see `Commitments/BaseFold/BASEFOLD.md`, *Zero-knowledge BaseFold*).
Pointing the same harness at it (`ZkBaseFoldHidingValidationTests`) shows the
spectrum move:

- **Commitment recoverability (experiment 3) flips to *not detected*.** The salted
  commitment is no longer a deterministic fingerprint of the witness, so
  recomputing a candidate's commitment no longer matches — the structural,
  certain leak is closed. This is the discriminating, guaranteed result, and the
  whole point of the hiding variant.
- A new **witness-independence** two-sample test
  (`BaseFoldProofWitnessIndependenceExperiment`, a Kolmogorov-Smirnov test on a
  per-proof metric across the two witness classes) reports *not detected* at this
  projection (at scale: KS D ≈ 0.12, p ≈ 0.45 at 200 samples), with a positive
  control confirming the test has power.
- **Byte-distribution (experiment 1) reports *not detected*** under the
  permutation-null form of the test (at scale: permutation p ≈ 0.77 at 200
  samples; the classifier also scores at chance, 45 %, p ≈ 0.44). The history is
  instructive: the original lockstep mask was *multilinear* and left the round
  polynomial's degree-two coefficient bare (computational ZK only), and the
  analytic chi-squared reported *detected* — but that verdict was at least
  partly the methodology artifact above, since the invalid test rejected
  witness-independent labelings too. Batch SM replaced both halves: the mask is
  now the sum-of-univariates statistical mask (every round coefficient blended,
  terminal bound by a filler-laundered weighted opening —
  `ZK-STATMASK-DESIGN.md`), and the test is valid.

The reading that matters: the *structural* leak (experiment 3), the one that
breaks privacy outright for low-entropy witnesses, is gone; the round-polynomial
residual the original multilinear mask left is closed by the batch-SM
statistical mask; and the empirical probes — under valid statistics — surface
nothing. So "masked over hiding BaseFold" targets statistical zero knowledge in
the random-oracle model (the design doc's ledger argument states the claim and
its conditions); "masked over plain BaseFold" remains "the masked transcript
shape over a transparent commitment," not privacy.

## Reproducing

`BaseFoldLeakageExperimentRunner.RunAll(harness, variableCount, sampleCount)` runs
all three; the per-experiment classes run them individually. The small-scale runs
are exercised in `BaseFoldLeakageTests` and `ZkBaseFoldHidingValidationTests`;
the at-scale figures above come from the two `[TestCategory("Slow")]` cases —
`BaseFoldLeakageTests.RunAllAtScaleReportsFindings` (plain provider, d = 3, 200
witnesses) and
`ZkBaseFoldHidingValidationTests.StatisticalExperimentsAtScaleReportFindings`
(full-ZK provider, d = 2, 200 witnesses; opt-in via
`VERIDICAL_AT_SCALE_LEAKAGE=1` since its ~5 minutes of full-ZK openings would
otherwise dominate the suite) — re-run after batch SM.7b. Findings
are machine- and seed-independent in kind, though the exact p-value and
accuracy vary with the sample.
