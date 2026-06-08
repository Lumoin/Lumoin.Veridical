# The statistical-ZK sumcheck mask — design and ledger

The statistical sumcheck-mask construction the codebase ships in two places:
the ZK-BaseFold evaluation opening
(`BaseFoldEvaluationProver.ProveZeroKnowledge` /
`BaseFoldEvaluationVerifier.VerifyZeroKnowledge`) and the masked Spartan2
prover's protocol-level masks (`MaskedSpartanProver`, see `SPARTAN2.md` §10).
It upgrades the earlier multilinear (Libra-style degree-1) masks — whose
blended round polynomials left the top coefficient a deterministic function of
the summand, computational ZK in the ROM — to **statistical zero knowledge in
the random-oracle model** for the round-message channel, with the end-to-end
flavor following the commitment scheme.

This document records the construction (v3), the correction trail that led to
it, the degrees-of-freedom ledger and its lemma (Appendix A), and the
per-consumer ledgers (Appendix C). The section structure preserves the design
history deliberately: the superseded v1/v2 constructions and the reasons they
fail are kept as do-not-resurrect records.

## References

- **CFS 2017** — Chiesa, Forbes, Spooner, *A Zero Knowledge Sumcheck and its
  Applications*, IACR ePrint 2017/305. The original ZK sumcheck: mask with a
  random polynomial of the same individual degrees, blended by a
  verifier-squeezed `ρ`. Their Construction 6.6 realises the mask as a full
  `m`-variate degree-`d` oracle — at our shape a degree-2-per-variable
  `d`-variate mask has `3^d` coefficients, infeasible for general `d`.
- **Libra 2019** — Xie, Zhang, Zhang, Papamanthou, Song, IACR ePrint
  2019/317, §4.1 Construction 1 + **Theorem 3**. The cheap mask:
  `g(x_1…x_ℓ) = a_0 + g_1(x_1) + … + g_ℓ(x_ℓ)` with each `g_i` univariate of
  the summand's per-variable degree `d`. Counting: `g` has exactly `ℓd + 1`
  random coefficients; across all rounds the verifier receives
  `ℓ(d+1) − (ℓ−1) = ℓd + 1` independent linear constraints on the blended
  coefficients; the two linear systems are **identically distributed** → the
  round messages are statistically (perfectly) simulatable. Cost `O(dℓ)`.
  Caveat: Libra binds/opens `g(r)` with their pairing-based zkVPD — not
  available to a hash-based path without downgrading its post-quantum
  soundness to DLOG.

## § 1 The gap the construction closes

The BaseFold-internal sumcheck (over `f'·eq_z`, per-round degree 2) sends per
round the compressed pair `(c_0, c_2)` with `c_1` chain-elided. A multilinear
mask `s` has degree-1 round contributions: `c_0, c_1` blend uniform, `c_2`
stays bare. Statistical ZK needs the mask's round contribution to be degree 2
— i.e. per-variable degree 2, which a multilinear cannot be, and which
BaseFold cannot commit directly (its codeword and fold structure are
multilinear-specific; a full degree-2 mask is `3^d` coefficients — CFS 6.6's
cost). The same shape recurs one level up: masked Spartan's outer (cubic) and
inner (quadratic) sumchecks need degree-3 and degree-2 masks respectively.

DOF accounting for the wire format: `d` rounds × `k` coefficients + `σ` =
`kd + 1` revealed constraints at per-round degree `k`. The Libra mask with
degree-`k` `g_i`'s has exactly `kd + 1` coefficients — the exact match that
makes Theorem 3's identical-distribution argument go through, **with zero
slack**. Anything else the protocol reveals about the mask coefficients (and a
hash-based binding mechanism must reveal something) breaks the exact match.
The construction therefore (a) adopts the Libra mask shape for the rounds,
(b) builds an in-stack binding for `s(r)`, and (c) proves the ZK claim with a
**degrees-of-freedom ledger** instead of Libra's exact count.

The reframe that unlocks (c): a mask is pure entropy, independent of the
witness. Revealing a functional of the mask is not itself a leak; it only
*spends* mask DOF. The requirement is that the witness-dependent reveals (the
round coefficients) remain jointly uniform **conditioned on** every
mask-functional revealed elsewhere — a rank condition on the combined reveal
matrix, over-provisioned and proven, not balanced exactly.

## § 2 The construction (v3; see the correction trail at the end of this section)

> **CORRECTION (v3, found while making the parameter policy deterministic).**
> v2 below has two defects. (1) Its small-`d` route is **under-provisioned**:
> at production query counts the weighted opening's rounds reveal
> `≈ 2ℓ_2' + 1 ≈ 30+` functionals of the mask coefficients (the lift floors
> `ℓ_2'`), but for `d ≤ 3` the entire degree-≤2 mask space has only
> `3^d ≤ 27` DOF — the level-2 rounds pin the mask and retroactively unmask
> the outer rounds. (2) Its weight-bearing pad lives *inside the mask
> polynomial*, capacity-capped by `d`. v3 moves the laundering entropy out of
> the mask polynomial entirely:
>
> **v3 = precommitted-filler laundering.** `C* = (mask coefficients ‖ random
> filler F ‖ lift)`. The filler is given **all-ones weights** in the weighted
> opening and its sum `σ_F = Σ filler` is absorbed alongside `com(C*)` and `σ`
> **before `ρ`**. At the terminal the verifier derives `s(r)` from the masked
> chain (`claim = f(r)·eq_z(r) + ρ·s(r)`), and verifies ONE weighted opening of
> `C*` against the claim `v := s(r) + σ_F` under the weights
> `w⁺ = (mask weights ‖ 1…1 ‖ 0…0)`. Soundness: `com(C*)`, `σ`, `σ_F` are all
> pre-`ρ`, so the CFS blend argument applies unchanged. ZK: the level-2 round
> functionals have nonzero coefficients on the filler block, whose
> `F ≥ 2ℓ_2' + 2 + λ_rank` DOF launder them for **every** `d` — the mask
> polynomial stays the plain Libra sum-of-univariates (`kd + 1` coefficients,
> the closed forms of `MonomialBasisMask`), with no pad pairs, no
> annihilators, no basis split, and the filler is nearly free (it lives inside
> the power-of-two rounding of `|C*|`). `σ_F` itself spends one filler
> functional — counted.
>
> The §3 ledger and rank lemma keep their block-elimination shape with
> "filler" in the role v2 gave "pad". The `MonomialBasisMask` kernel remains
> the right object: basis = the sum-of-univariates subset; the pad-pair
> factory stays available but the v3 wiring does not need it.

## § 2-v2 The superseded v2 construction (kept for the correction record)

> **CORRECTION (v2).** The original three-level design below-the-line had a
> sizing flaw found when the wiring was costed concretely: `com(C)` must
> survive the full IOPP query count, so its lift needs `t_C ≈ 6–10` and the
> level-2 sumcheck runs over `ℓ_2 + t_C ≈ 12+` variables — every one of whose
> rounds the full mask `u` must cover, making `u` `3^{ℓ_2 + t_C} ≈ 10^6+`
> coefficients, not `3^{ℓ_2} ≈ 729`. Worse, a sum-of-univariates `u` regresses
> with a variable count floored by the lift, so the tower never shrinks. v2
> removed the need for `u` (and level 3) entirely by giving the level-1 mask
> **weight-bearing padding**: the zero-weight-padding curse is that level-2
> round functionals carry coefficient `W(y)·(fold factors)`, so dead padding
> can never launder them — but padding the *mask itself* with random
> coefficients on annihilator monomials `(2x_1 − 1)·h(x_2…x_d)` contributes
> **nothing to σ and nothing to any round message except round 1's constant**
> (since `Σ_{x_1}(2x_1 − 1) = 0` kills every partial sum in which `x_1` is
> still free), yet evaluates to `(2r_1 − 1)·h(r_2…r_d) ≠ 0` at the terminal
> point — so the pad coordinates get **nonzero level-2 weights** and launder
> the level-2 rounds directly.

### Level 1 — the padded outer mask (closed-form blending)

- Prover samples `s*(x) = a_0 + Σ_i (a_i·x_i + b_i·x_i²) + (2x_1 − 1)·h(x_2…x_d)`
  where `h` carries `P` uniform coefficients on multilinear monomials of
  `x_2…x_d` (so `s*` stays degree ≤ 2 per variable). DOF = `2d + 1 + P`.
- `σ = Σ_b s*(b) = 2^d·a_0 + 2^{d−1}·Σ_i (a_i + b_i)` — the pad term sums to
  zero over the hypercube, so the **closed form is unchanged**.
- Round blending stays closed-form: rounds `k = d…2` exactly as before
  (`c_0 += ρ·K_k`, `c_2 += ρ·2^{k−1}·b_k`); round `k = 1` (binding `X_1`, no
  free prefix) additionally sees the pad term `(2t − 1)·h(r_2…r_d)`:
  `c_0 += ρ·(K_1 − h(r_2…r_d))` and the elided `c_1` absorbs `+2ρ·h(r)` —
  one extra `O(P)` evaluation of `h` at the bound challenges. This *replaces*
  the lockstep-folded multilinear mask (full table + own codeword + fold chain
  + witness-sized IOPP) — prover-side round work gets cheaper.
- The coefficient vector `C* = (a_0; a_1…a_d; b_1…b_d; h-coeffs; 2^{ℓ_2}-pad…)`
  is committed as a tiny multilinear via the **hiding, lifted** provider
  (salted leaves + dimension lift; the lift block is charged with the
  IOPP-query reveals exactly as the enforced budget already does). `com(C*)`
  and `σ` are absorbed **before** `ρ` is squeezed.
- Terminal: the verifier needs
  `s*(r) = a_0 + Σ_i (a_i r_i + b_i r_i²) + (2r_1 − 1)·h(r_2…r_d)` —
  a **public-weight inner product** `⟨C*, w*⟩` with
  `w* = (1, r_1…r_d, r_1²…r_d², (2r_1 − 1)·m_1(r)…(2r_1 − 1)·m_P(r), 0…)` —
  every real and pad coordinate carries a **nonzero** weight (generic `r`);
  only the power-of-two filler and the lift block are zero-weighted.

Soundness of the blend is CFS's: `s*` (as `com(C*)`) and `σ` are fixed before
`ρ`; a false claim survives the random linear combination with probability
`1/|F|`. No shape-claim about `s*` is needed for soundness — any committed
`C*` yields *some* mask; the shape matters only for ZK, which is the prover's
own interest.

### Level 2 — binding `s*(r)`: ONE unmasked weighted opening of `C*` (terminates)

`⟨C*, w*⟩` is a sumcheck `Σ_y C*'(y)·W*(y)` over the lifted
`ℓ_2' = ℓ_2 + t_C` variables (`W*` = MLE of the zero-extended `w*`),
interleaved with `C*`'s codeword folds and terminated against `π_0^{C*}` —
BaseFold's evaluation protocol with the `eq_z` multiplier generalised to an
arbitrary public multiplier (`ProveWeightedSum` / `VerifyWeightedSum`).

Run **unmasked**. Its reveals and who pays for them:
- the `≈ 2ℓ_2' + 1` round functionals — supported on the nonzero-weight
  coordinates = the real **and pad** blocks; laundered by the `P` pad DOF
  (the rank lemma, §3);
- the IOPP query openings — laundered by the lift block (bounded
  independence; the budget the guard enforces);
- the terminal `C*'(r')` (the base oracle value) — an eq-tensor functional,
  nonzero on every coordinate including the lift block; laundered there.

Sizing: `P ≥ (2ℓ_2' + 2) + λ_rank` ⇒ `P ≈ 30–40` for any `d`;
`ℓ_2 = ⌈log₂(2d + 1 + P)⌉ ≈ 7` at `d = 20`. One small extra commitment and
one small weighted opening per ZK opening. **No level-2 mask, no level 3, no
recursion.**

### Small `d` (≤ 4): the full-mask degenerate route (superseded by v3 — under-provisioned)

`(2x_1 − 1)·h` offers only `2^{d−1}`-monomial padding (degree-bounded
`3^{d−1}`), which cannot reach `P ≈ 30` below `d ≈ 5`. v2 proposed sampling
the mask with random coefficients on **all** `3^d ≤ 81` degree-≤2 monomials
(the full CFS mask) for small `d` — the v3 correction at the top of §2 shows
this is under-provisioned at production query counts and must not be
resurrected; v3's filler laundering covers every `d` uniformly.

### The original level-2/3 design (SUPERSEDED by the v2 correction above)

`u` as a full `3^{ℓ_2}` mask blending level 2, bound in turn by a level-3
tensor-weighted opening of `U` whose reveals spend `U`'s slack. Superseded
because the sizing ignored `C`'s lift: with `ℓ_2' = ℓ_2 + t_C` rounds to
blend, `u` is `3^{ℓ_2'} ≈ 10^6+`, and a cheaper sum-of-univariates `u`
regresses with its variable count floored by the lift, never terminating.
The v2 weight-bearing pad made the entire branch unnecessary.

## § 3 The DOF ledger

All reveals are linear functionals of the single mask coordinate vector
`C*' = (coefficients ‖ filler ‖ lift)` (the coefficients of every functional
are public at verification time: `ρ`, `r`, `r'`, `W*`, the code's encoding
rows, and the eq factors). Ledger:

| Reveal | Supported on | Count |
|---|---|---|
| Level-1 rounds `(c_0, c_2)·d` + `σ` | coefficient block | `2d + 1` |
| `s(r)` (the claim itself) | coefficient block | 1 (rank-checked against the above) |
| `σ_F` + level-2 round functionals | filler (all-ones weights × fold factors) | `≈ 2ℓ_2' + 2` |
| Level-2 terminal `C*'(r')` | every coordinate (eq tensor) | 1 |
| IOPP query openings | every coordinate (dense encoding rows) | `≈ Q·(ℓ_2' + 1) + 8` |

Required rank conditions (proven in Appendix A):
1. **Level-1 exactness:** the `2d + 1` round functionals restricted to the
   coefficient block have full rank (Libra Theorem 3's count, unchanged).
2. **Filler laundering:** the level-2 round functionals plus `σ_F` restricted
   to the filler columns have full rank `≈ 2ℓ_2' + 2` — their filler-column
   entries are all-ones weights times distinct challenge products, generically
   independent; failure is a negligible-probability challenge event added to
   the statistical distance. Requires `F ≥ 2ℓ_2' + 2 + λ_rank`, enforced by
   construction in `WellKnownStatisticalMaskParameters`.
3. **Lift laundering:** the IOPP query reveals and the level-2 terminal are
   jointly uniform given the lift block — the bounded-independence budget,
   machine-enforced (`ThrowIfHidingBudgetUnmet`); the commitment routes
   through the guarded factory.

The combined claim: the opening transcript is simulatable from the public
statement with statistical distance `O(q/2^{saltbits} + Pr[rank failure] +
1/|F|)` in the ROM (`q` = distinguisher's oracle queries; salted-leaf hiding
is statistical in the ROM).

## § 4 The construction in code (as built)

- **The kernel** — `Core/Sumcheck/MonomialBasis` (public exponent vectors
  `e ∈ {0,1,2,3}^d`; factories `SumOfUnivariatesWithPad(d, padPairCount,
  perVariableDegree ∈ [2,3])` and `Full(d)` for the small-`d` enumeration) and
  `MonomialBasisMask` (closed forms: `σ = Σ c_e·2^{d−|supp(e)|}`; the round-`k`
  blend per monomial routed by `e_k` to `c_0`/elided-`c_1`/`c_2`/`c_3`;
  `EvaluateAt`; the static `BuildWeightVector`). Rounds bind high-variable
  first (the BaseFold fold order); a low-first consumer relabels (see
  `MaskedSpartanAlgorithm` and `SPARTAN2.md` §10.1).
- **The weighted opening** — BaseFold: `ProveWeightedSum` /
  `ProveWeightedSumHiding` / `VerifyWeightedSum` (the evaluation protocol with
  the `eq_z` multiplier generalised; `W = eq_z` is byte-identical to a plain
  opening). Hyrax: the single-row vector commitment (`CommitVector`) plus the
  inner-product argument with the weight vector in the public seat
  (`HyraxWeightedOpeningExtensions`).
- **The policy** — `WellKnownStatisticalMaskParameters`: deterministic
  resolution of `(mask count, ℓ_2, t_C, filler)` from the sumcheck shape,
  `CreateClassicalSecurity` for the lifted BaseFold ledger and
  `CreatePedersenIpa` for the unlifted Pedersen/IPA ledger; filler =
  every coordinate beyond the mask coefficients.
- **The ZK-BaseFold opening** — `BaseFoldEvaluationProver.ProveZeroKnowledge` /
  `BaseFoldEvaluationVerifier.VerifyZeroKnowledge`; the proof's mask side is
  `BaseFoldMaskOpening` `{com(C*) root, σ, σ_F, nested weighted opening}`,
  gated by `BaseFoldOpeningMode.ZeroKnowledge`.
- **Masked Spartan** — the protocol-level masks (outer cubic `3d_x + 1`,
  inner quadratic `2d_y + 1`) bound the same way through the
  `PolynomialCommitmentProvider` weighted-opening seam (`CommitVector` /
  `OpenWeightedSum` / `VerifyWeightedSum` / `ResolveStatisticalMaskShape`);
  Appendix C carries the per-path ledgers.

## § 5 Costs

- Prover: round blending is cheaper than the superseded lockstep mask (no
  mask table, no mask fold chain, no witness-sized mask IOPP). Added: ONE
  small commitment (`|C*| = 2^{ℓ_2}` coordinates) and its single
  weighted-opening IOPP — comparable to, or smaller than, the witness opening
  for realistic `d`.
- Proof size: replaces the old mask section (mask roots + mask base oracle +
  `Q·d` salted mask openings) with `com(C*)` + one small weighted opening.
  For `d ≥ ℓ_2 + 3` (i.e. nearly always) the new layout is *smaller*: the old
  mask IOPP was at the lifted witness size.
- Verifier: one extra small sumcheck + IOPP verify; `O(d + F)` weight
  evaluations.

## § 6 Settled design points

1. The rank slack `λ_rank = 8` and "filler = all remaining coordinates" are
   pinned in `WellKnownStatisticalMaskParameters` (no zero-weight real
   coordinates).
2. `com(C*)` uses the full salted-and-lifted commit path, with the lift block
   charged via the enforced hiding budget — this is what makes the Appendix A
   lemma's block 3 a machine-checked precondition.
3. The Fiat-Shamir labels live in `WellKnownBaseFoldEvaluationParameters`
   (`MaskCommitmentRoot`, `MaskSum`, `MaskFillerSum`, `MaskBlendChallenge`) and
   `WellKnownMaskedSpartanTranscriptLabels` (the Spartan-level set incl. the
   filler sums).
4. No compatibility constructor for pre-upgrade proof bytes: proofs produced
   by the superseded multilinear-mask paths verify only with the code that
   produced them; the providers' ZK contract changed.
5. The `2^{d−i}` closed-form factors assume odd-prime scalar fields (true for
   both wired curves); the construction is inapplicable as-is over
   characteristic 2.

## § 7 What this does NOT do

- ~~The literal real-vs-simulated proof-byte test needs a programmable
  Fiat-Shamir oracle abstraction (an open follow-on)~~ — **closed by the FS
  batch**: `Lumoin.Veridical.Analysis/Simulation` carries
  `ProgrammableFiatShamirOracle` (recording + sequence-keyed replay squeeze
  delegates; the `FiatShamirSqueezeDelegate` seam threads through every
  driver, so no protocol change was needed) and `ZkBaseFoldOpeningSimulator`,
  the running counterpart of Appendix A's simulator. The construction leans
  on the protocol's own algebra: an honest prover run over a uniformly
  random fake witness (every oracle response recorded), then the single
  revealed mask sum patched to `sigma' = sigma + (y* - y)/rho` — the
  verifier's initial claim `y + rho*sigma'` equals the fake run's
  `y* + rho*sigma`, so the entire numeric chain is byte-identical and only
  challenge derivation breaks, which is exactly what the ROM programming
  repairs. Gates (`ZkBaseFoldSimulatorTests`): the witness-free opening
  verifies under the programmed oracle with a one-to-one squeeze sequence,
  is rejected under the real oracle, and real-vs-simulated proof bytes are
  within the label-permutation null (mean-byte KS and the pooled-histogram
  permutation test — the analytic chi-squared p-value is invalid here per
  the SM.6 finding, now institutionalised as
  `StatisticalTests/PermutationTest`). The MS batch lifted the same recipe
  to the whole masked Spartan proof (`ZkBaseFoldMaskedSpartanSimulator`):
  a uniformly random fake witness does not satisfy the constraint system,
  so the outer sumcheck's actual sum is `E_tau = g~(tau) != 0` against the
  public zero target, and the patch becomes
  `sigma' = sigma + E_tau / rho_outer` on the one pre-rho reveal — the
  inner sumcheck's initial claim is derived from absorbed proof values and
  needs no second patch. `E_tau` is the MLE of the per-row constraint
  error at the recorded `tau`, computed from public data plus the fake
  witness through the library's own MLE evaluation (conventions inherited,
  not re-derived). The honest prover's witness-satisfaction fail-fast is
  skipped through an internal unguarded entry
  (`ProveZkBaseFoldWithoutSatisfactionGuard`) — the fail-fast is an
  honest-prover convenience, not a soundness control, and the gates pin
  that the simulated proof is rejected by every unprogrammed verifier.
- Over the Pedersen/IPA path the end-to-end flavor remains computational ZK
  in the ROM (the opening layer is DLOG-rooted); the statistical end-to-end
  claim holds over the full-ZK BaseFold provider. Appendix C records the
  per-path honest claims.
- No change to soundness, the dimension lift, the hiding budget guard, or the
  commitment layout — `Commit` bytes are unchanged; only `Open`'s mask side
  changed.

## Appendix A — the DOF-ledger lemma

**Setting.** Fix the sumcheck shape `d`, query count `Q`, and the policy
resolution (`l2`, `t_C`, filler count `F` with `F >= 2*(l2 + t_C) + 2 + 8`).
The prover randomness, all uniform and mutually independent, and independent of
the witness `f`: the mask coefficients `m in F^(2d+1)`; the filler
`phi in F^F`; the witness commitment's lift block `lambda_w` (budget-enforced
`(2^t - 1)*2^d >= Q*`); the mask commitment's lift block `lambda_C` (likewise);
all Merkle leaf salts.

**Claim.** Conditioned on the public statement (the commitment, `y`, `z`) and
the squeezed challenges, the joint distribution of every prover message in the
ZK opening is within statistical distance
`epsilon = Pr[rank failure] + q/2^254 + 2/|F|` of a distribution sampleable
without `f` (q = the distinguisher's random-oracle queries; 254 ~ salt
min-entropy bits; the `2/|F|` covers the zero-rho rejection and the blend).

**Message blocks and the triangular elimination.** Order the reveals:

1. **Outer rounds + sigma** — `2d + 1` values: each is
   `(witness term) + rho * (linear functional of m)`. The mask-side matrix
   `L1` (rows: the round c0/c2 blend functionals and sigma; columns: m) is
   exactly Libra Theorem 3's system. Its determinant is a nonzero polynomial
   in the challenges (the c2 rows are diagonal in the b_j with nonzero
   2^(k-1) pivots; eliminating them leaves the a_j/a_0 system triangular up
   to challenge terms), so `L1` is invertible except on a challenge set of
   measure <= deg(det)/|F| (Schwartz-Zippel). Given invertibility, for ANY
   witness terms the block is uniform: m realises any observed value.
2. **sigma_F and the nested rounds + nested terminal** — `1 + (2*l2' + 1)`
   values: each is `(known function of m) + (linear functional of phi,
   lambda_C)` — by block 1, m is determined given the observation, so these
   are affine in `(phi, lambda_C)` with publicly determined offsets. The
   filler/lift column submatrix `B` must have full row rank
   `2*l2' + 2`: its rows are W+-weighted fold functionals (filler columns
   carry the all-ones weights times distinct challenge products) plus the
   eq-tensor terminal row and the all-ones sigma_F row. det of a maximal
   minor is again a nonzero challenge polynomial; the policy's `+8` slack
   keeps the system underdetermined so a vanishing minor is repaired by
   another (failure measure <= deg/|F|). Given full rank, the block is
   uniform irrespective of m — hence irrespective of f.
3. **IOPP query reveals (witness and mask commitments)** — bounded
   independence: the revealed codeword positions are encoding rows applied to
   `(message || lift block)`; the lift-column submatrix of <= Q* rows must
   have rank = #rows. The budget guard enforces the dimension precondition;
   the random foldable code's diagonals are hash-derived, so the rank
   condition holds except with the same generic-vanishing measure. Given it,
   the reveals are uniform given blocks 1-2.
4. **Roots, paths, and unopened structure** — salted-Merkle reveals: in the
   ROM, `H(value || salt)` with a uniform 254+-bit-entropy salt is
   distinguishable from uniform only by querying the salt: advantage
   <= q/2^254.

**Simulator.** Sample blocks 1-3 uniformly subject to the public chain
constraints (start the claim at `y + rho*sigma` with sigma sampled, enforce
`h_k(0) + h_k(1) = claim`), program the terminal identities by construction
(the derived `s(r)` is whatever the chain implies; the weighted claim is
`s(r) + sigma_F` with sigma_F sampled), and emit fresh salted commitments for
the roots. Each block's conditional uniformity above makes the simulated and
real distributions identical outside the failure events.

**What a fully formal treatment would add.** Explicit determinant
calculations for `L1` and `B` (here argued generically with Schwartz-Zippel
over the challenge space); a precise salt-entropy accounting against the
specific Merkle arity; and the Fiat-Shamir lifting (the statement here is for
the interactive protocol with honest challenges; the FS-compiled claim
inherits the standard ROM analysis). None of these change the shape of the
bound.

**Enforcement.** The lemma's preconditions are machine-checked at
configuration time: the lift budgets by `ThrowIfHidingBudgetUnmet` (both
commitments route through guarded paths), and the filler bound by
construction in `WellKnownStatisticalMaskParameters.CreateClassicalSecurity`
(the resolver only returns shapes with `F >= 2*l2' + 2 + 8`).

## Appendix B — empirical-validation record

- The byte-distribution experiment's analytic chi-squared was found invalid
  on this proof structure (it rejected witness-independent labelings at
  p < 1e-24: intra-proof byte duplication breaks its iid assumption) — which
  also confounded the earlier attribution of its Detected verdict to the
  multilinear mask's `c_2` residual. With the label-permutation null in
  place, all three leakage experiments report NotDetected against the
  full-ZK provider; the at-scale figures live in `BASEFOLD-LEAKAGE.md`.

## Appendix C — the masked-Spartan ledger (the Spartan-level masks)

The v3 construction applied to masked Spartan's two protocol-level masks,
replacing the PCS-committed multilinear `g_outer`/`g_inner` (whose degree-1
rounds left the outer `c_2, c_3` and inner `c_2` coefficients bare). Each
sumcheck gets its own degree-matched sum-of-univariates kernel mask:

- **Outer (cubic rounds):** `g_outer = a_0 + Σ_j (a_j x_j + b_j x_j² + c_j x_j³)`,
  `3·d_x + 1` coefficients. The wire reveals `(c_0, c_2, c_3)` per round plus
  `σ` = `3·d_x + 1` constraints — Libra Theorem 3's exact count at degree 3,
  with zero slack, exactly as the degree-2 case. The `L1` invertibility
  argument of Appendix A extends verbatim: the `c_3` rows are diagonal in the
  `c_j` with nonzero `2^{k−1}`-family pivots (a second diagonal block beside
  the `b_j` one), and eliminating both leaves the `a_j / a_0` system
  triangular up to challenge terms.
- **Inner (quadratic rounds):** the Appendix A mask shape verbatim,
  `2·d_y + 1` coefficients vs `2·d_y + 1` reveals.

**The bindings, per PCS path.** Each mask's `C* = (coefficients ‖ filler)` is
committed via the provider's vector commit and bound by ONE weighted opening
against `v = g(r) + σ_F` under weights `(basis monomials at the kernel point ‖
1…1 on filler)`; all of `com(C*)`, `σ`, `σ_F` are absorbed pre-`ρ` (so the CFS
blend soundness is unchanged). The kernel point is the REVERSED challenge
vector (Spartan folds low-variable-first, the kernel high-first; the
sum-of-univariates basis is invariant under the relabeling).

- **Full-ZK BaseFold path** (`ProveZkBaseFold`): `C*` is committed
  salted-and-lifted at its own minimum lift `t_C(ℓ₂)` (budget-guarded) and the
  weighted opening runs in hiding mode — Appendix A's blocks 2–4 apply with
  this mask's `(φ, λ_C)`: the `2ℓ₂' + 2` filler-laundered functionals, the
  lift-laundered IOPP queries, and the salted-ROM term. The two masks and the
  witness lift are independent samples, so the joint simulator factorises and
  the per-mask block eliminations compose by independence. Resolution:
  `WellKnownStatisticalMaskParameters.CreateClassicalSecurity(d, curve, Q,
  degree)`. End-to-end flavor: statistical ZK in the ROM.
- **Hyrax (Pedersen/IPA) path** (`Prove`): `C*` is one perfectly-hiding
  Pedersen row; the weighted opening is the IPA with the weight vector in the
  public seat. Its CLEARTEXT functionals of `C*` are exactly two — `σ_F` and
  the IPA's final folded scalar — laundered by the unlifted filler floor
  `F ≥ 2 + 8` (`CreatePedersenIpa`). The IPA's `L/R` points and `C_f` are
  unblinded DLOG-hard group elements, so the opening layer is computationally
  hiding; the path's end-to-end flavor stays computational ZK in the ROM
  (rooted in DLOG), as it always was — but with the round-message channel now
  statistically masked and the previously-detectable top-coefficient residual
  removed.
- **Plain BaseFold path** (`ProveBaseFold`): no hiding claim (the witness
  commitment itself is non-hiding); the masks share the unlifted shape with
  the filler inert — sound-only.

**What the masked-Spartan wire reveals about each mask, summed:** the
`k·d + 1` round constraints (spent exactly against the `k·d + 1` mask DOF) and
the weighted opening's reveals (spent against filler/lift per path above). The
verifier never receives `g(r)`: it derives it from the chain and the opening
binds `g(r) + σ_F` — one rank-checked functional against the same ledger, as
in the v3 opening.
