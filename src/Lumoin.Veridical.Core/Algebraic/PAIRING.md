# Pairing on BLS12-381 and BN254

This document describes the optimal-ate pairing on BLS12-381 as
implemented in `Lumoin.Veridical.Core`. It is written for someone
who has read the code and wants the algebraic shape made explicit;
it is not a tutorial on pairings from first principles, but the
sections build up the structure in an order that does not assume
prior pairing experience.

Sections § 1 through § 7 describe BLS12-381. Section § 8 carries the
same structure across to BN254 (alt_bn128) and isolates the points
where the two curves' pairing constructions genuinely differ — the
Miller-loop count, the twist direction, the final-exponentiation
chains, and the Frobenius constants. A reader checking either curve's
implementation against a published spec should read § 8 alongside the
section it points back to.

## § 1 Curve and field tower

BLS12-381 is a pairing-friendly curve with embedding degree twelve.
Three groups appear in the pairing.

**G1** is the prime-order subgroup of `E(Fp)`, where `E` is the
curve `y² = x³ + 4` over the 381-bit prime field `Fp`. G1 points
have coordinates in `Fp` and serialise to 48 compressed bytes (one
field element plus three flag bits in the most-significant byte).

**G2** is the prime-order subgroup of `E'(Fp2)`, where `E'` is the
*twisted* curve `y² = x³ + 4(1 + u)` over the quadratic extension
`Fp2`. G2 points have coordinates in `Fp2` and serialise to 96
compressed bytes (two field elements with the flag bits in the high
byte).

**GT** is the order-`r` subgroup of `Fp12*`. It is multiplicatively
written. Elements of GT are the pairing outputs and they live in
the cyclotomic subgroup carved out by the final exponentiation.

The four fields form a tower `Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12` with the
following defining relations:

- `Fp2 = Fp[u]/(u² + 1)`. Elements are `c0 + c1·u` with `u² = −1`.
- `Fp6 = Fp2[v]/(v³ − ξ)` where `ξ = 1 + u`. Elements are
  `c0 + c1·v + c2·v²` with `v³ = ξ`.
- `Fp12 = Fp6[w]/(w² − v)`. Elements are `c0 + c1·w` with `w² = v`.

The composition `Fp12 = (Fp[u]/(u² + 1))[v]/(v³ − (1 + u))[w]/(w² − v)`
factors a degree-twelve extension into one quadratic, one cubic, and
one quadratic step. This tower structure is what makes the pairing
tractable to compute: Fp12 arithmetic happens as Fp6 arithmetic over
two slots, Fp6 arithmetic as Fp2 arithmetic over three slots, and
Fp2 arithmetic as Fp arithmetic over two slots. The cost of one
Fp12 multiplication is on the order of a hundred Fp multiplications,
not the naive 144.

The non-residue `ξ = 1 + u` is the common thread tying the tower
together. Fp6 wraps `v³` to `ξ`, Fp12 wraps `w²` to `v`, the
twist's curve coefficient is `4·ξ`, and the Frobenius γ-constants
are powers of `ξ`. A sign mistake on `ξ` propagates everywhere; the
implementation derives the Frobenius constants from `ξ` at static
initialisation by exponentiation rather than transcribing them, so
any such mistake surfaces immediately as a Frobenius-identity test
failure.

## § 2 The optimal-ate pairing

The pairing `e: G1 × G2 → GT` is a bilinear, non-degenerate map:

- **Bilinearity.** `e([a]P, Q) = e(P, [a]Q) = e(P, Q)^a` for any
  scalar `a` and any `P ∈ G1`, `Q ∈ G2`.
- **Non-degeneracy.** `e(P, Q) ≠ 1` whenever `P` and `Q` are
  non-identity.

For BLS12-381 the most efficient choice is the optimal-ate pairing,
which fixes the smallest possible loop parameter. The parameter is
the curve's defining integer `x = −0xd201000000010000`, a sparse
64-bit value with only six set bits and a negative sign. The
pairing is the composition of two stages:

1. **The Miller loop** computes `f = f_{|x|, Q}(P)`, a value in
   `Fp12*` that is bilinear up to a factor that the next stage
   eliminates.
2. **The final exponentiation** raises `f` to the integer
   `(p^12 − 1)/r`, projecting the result into GT.

The Miller-loop output is unique up to multiplication by an
`r`-th power in `Fp12*` (an artefact of the Tate-like construction).
The final exponentiation kills all such ambiguity because the
exponent annihilates the `r`-th-power subgroup, leaving a canonical
element of the order-`r` cyclotomic subgroup. After final
exponentiation the bilinearity equation holds exactly.

The negative sign of `x` is handled by iterating the Miller loop
over `|x|` and applying one Fp12 inversion at the loop exit. The
inversion compensates for the fact that the trajectory of `[k]Q`
for `k > 0` differs from the trajectory of `[−k]Q` only in the
direction of the line slopes, so the Miller function on `|x|`
differs from the Miller function on `x` by exactly an Fp12
inversion before final exponentiation.

## § 3 The Miller loop

The Miller loop accumulates the Miller function `f_{n, Q}(P)`
through a double-and-add traversal of the bits of `n = |x|`. Two
state variables advance through the loop:

- `T`, the working point on `E'(Fp2)`, which represents
  `[k]Q` for the current intermediate scalar `k`.
- `f`, the running accumulator in `Fp12*`.

The loop runs for `bitLength(|x|) − 1 = 63` iterations. The top bit
of `|x|` is accounted for by initialising `T := Q` and `f := 1`,
so the first iteration processes the bit just below the top.

Each iteration performs a doubling step and, if the corresponding
bit of `|x|` is set, an addition step.

The doubling step computes the tangent line at `T` on the twist,
extracts its slope `λ` and y-intercept `ν = T.Y − λ·T.X`, doubles
`T` via the standard affine doubling formulas (`X₃ = λ² − 2X`,
`Y₃ = λ(X − X₃) − Y`), and updates `f`:

```
f ← f² · ℓ(T_before, P)
T ← [2]·T_before
```

The squaring `f²` reflects the doubling of the trajectory of `T`;
the line evaluation `ℓ(T_before, P)` accounts for the divisor
arithmetic that doubling introduces.

The addition step (when the bit is set) computes the line through
the current `T` and the original `Q`, extracts its slope and
y-intercept, adds `Q` to `T`, and multiplies `f` by the new line
evaluation:

```
f ← f · ℓ(T_before, Q, P)
T ← T_before + Q
```

After 63 iterations the working point `T` has reached `[|x|]·Q` and
the accumulator `f` is the Miller function value. Because the
curve parameter is negative, `f` is inverted in `Fp12*` before
returning to final exponentiation.

The whole loop computes one Fp12 element. A naive count would be 63
Fp12 squarings, plus up to 63 sparse Fp12 multiplications by line
values, plus some affine arithmetic on Fp2 for the trajectory. The
reference implementation uses generic Fp12 multiplication
throughout for clarity; production backends specialise on the
sparsity of line evaluations (see § 4) and on the cyclotomic
squaring (see § 6) for substantial speedups.

## § 4 Line evaluation

The Miller loop accumulates evaluations of line functions over the
twist curve at the G1 input point `P`. Each line through a pair of
points `T`, `T'` on `E'(Fp2)` has the form `Y − λ·X − ν = 0`,
where `λ` is the slope through `T`, `T'` and `ν = T.Y − λ·T.X` is
the y-intercept.

To evaluate this line at the G1 point `P = (xP, yP) ∈ Fp × Fp`, the
M-twist isomorphism `ψ⁻¹(x, y) = (x·w², y·w³)` lifts `P` to its
untwisted Fp12 representation. Substituting into the line equation
yields

```
ℓ_eval(P) = yP·w³ − λ·xP·w² − ν
```

Decomposing into the Fp12 = Fp6[w] basis with `w² = v`:

- The constant term `−ν` occupies the `w⁰` slot, which is `c0.c0`.
- The `w²` term `−λ·xP` occupies the v-slot of c0, which is `c0.c1`.
- The `w³ = v·w` term `+yP` occupies the v-slot of c1, which is `c1.c1`.

All other Fp2 slots in the line value are zero. The line evaluation
is therefore sparse — only three of the twelve Fp2 components are
non-zero — though the reference implementation stores it as a full
Fp12 element and uses the generic Fp12 multiply. A production
backend specialises on this sparsity for a measurable speedup,
since each Miller-loop iteration multiplies the running accumulator
by one or two such sparse values.

The line value's sparsity also has structural significance: the
three non-zero slots are precisely the slots reached by lifting an
Fp-pair through the M-twist's `w^(2j+3i)` structure. A line value
whose non-zero slots fall outside `{w⁰, w², w³}` is in the wrong
basis representation, regardless of how its individual components
look.

## § 5 The M-twist representation

G2 points live on the twist curve `E'/Fp2: Y² = X³ + 4(1 + u)`
rather than directly inside `E(Fp12)`. The twist exists because
representing G2 directly in Fp12 would force every G2 operation to
work with twelve-Fp coordinates instead of two-Fp2 coordinates. The
twist gives a six-times-smaller representation that an isomorphism
recovers when needed.

The M-twist isomorphism is

```
ψ: E'(Fp2) → E(Fp12),  ψ(X, Y) = (X·w⁻², Y·w⁻³)
```

with inverse

```
ψ⁻¹: E(Fp12) → E'(Fp2),  ψ⁻¹(x, y) = (x·w², y·w³)
```

(both restricted to the image points where they are defined). The
"M" in M-twist refers to the *multiplicative* twist; its
counterpart, the *divisor* or D-twist, uses the inverse direction
`ψ(X, Y) = (X·w², Y·w³)` and produces a different curve. BLS12-381
is fixed to the M-twist by the canonical specifications.

The twist's curve coefficient `4(1 + u) = 4·ξ` is what makes the
isomorphism well-defined: lifting `(X, Y)` from `E'(Fp2)` and
substituting into `y² = x³ + 4` gives `(Y·w⁻³)² = (X·w⁻²)³ + 4`,
which after multiplying by `w⁶ = v³ = ξ` becomes
`Y² · ξ / w⁰ = X³ + 4·ξ / w⁰`, i.e. `Y² = X³ + 4·ξ`. The factor `ξ`
on the right is exactly the twist's curve coefficient adjustment.

In the Miller loop, G2 points stay in `E'(Fp2)` for all
trajectory arithmetic — doubling, addition, slope extraction — and
only get lifted through `ψ⁻¹` when evaluating lines at G1 points
(see § 4). The lifting is purely conceptual: the line evaluation
formula already incorporates the `w²` and `w³` factors, so no
explicit Fp12 lift is computed.

## § 6 The final exponentiation

The Miller-loop output `f` lives in `Fp12*` but its bilinearity
property holds only modulo `r`-th powers. The final exponentiation
removes this ambiguity by raising `f` to

```
(p^12 − 1) / r
```

The exponent has a useful factorisation:

```
(p^12 − 1) / r = (p^6 − 1) · (p^2 + 1) · ((p^4 − p^2 + 1) / r)
```

The implementation splits this into two stages of very different
cost.

**Easy part.** The factor `(p^6 − 1)(p^2 + 1)` is computed
structurally rather than by general exponentiation:

- Raising to `(p^6 − 1)` is one Fp12 conjugation (the automorphism
  `w ↦ −w`, which negates the `c1` Fp6 component) followed by one
  Fp12 inversion. This works because conjugation equals raising to
  `p^6` over a properly-chosen tower, so `conj(f) · f⁻¹ = f^(p^6 − 1)`.
- Raising to `(p^2 + 1)` is one Frobenius squared followed by one
  Fp12 multiplication: `f^(p^2 + 1) = π²(f) · f`.

The whole easy part is one conjugation, one inversion, two
Frobenius applications, and two Fp12 multiplications. It is cheap.

**Hard part.** The factor `(p^4 − p^2 + 1) / r` is a large positive
integer with no closed-form structure that the implementation
exploits. The reference computes this exponent at static
initialisation and runs the hard-part exponentiation by binary
square-and-multiply on the precomputed value. This is slow
(hundreds of Fp12 squarings) but obviously correct.

A production backend replaces the generic squaring in the hard
part with cyclotomic squaring (see § 7), reducing the cost by
about a factor of three; further, it expresses the hard-part
exponent as a polynomial in `p` and `x` and computes it through
Frobenius applications instead of direct multiplications. The
reference takes neither shortcut.

After both stages the result is in the order-`r` cyclotomic
subgroup `GT ⊂ Fp12*`, and the bilinearity equation
`e([a]P, Q) = e(P, Q)^a` holds exactly.

## § 7 Frobenius and the cyclotomic shortcut

The Frobenius endomorphism is the map

```
π: Fp12 → Fp12,  π(x) = x^p
```

It is an automorphism of Fp12 fixing Fp. Its load-bearing role is in
the final exponentiation, where applications of `π² = π ∘ π` allow
the easy part to be computed without a full Fp12 exponentiation.

Computing `π(x)` directly via `BigInteger.ModPow(x, p, ...)` on each
Fp coordinate would work but would be ruinously slow (twelve Fp
modular exponentiations per call). The tower structure gives a
better route. For an Fp2 element `a = a0 + a1·u`, Frobenius is the
complex conjugation `a^p = a0 − a1·u` (because `u² = −1` and
`(−1)^((p−1)/2) = 1` for `p ≡ 1 (mod 4)` on BLS12-381 — but here
`p ≡ 3 (mod 4)`, so `u^p = −u` directly). One application becomes a
sign flip on the imaginary part.

Climbing the tower, Fp6 Frobenius acts on `a = a0 + a1·v + a2·v²` by

```
π(a) = π(a0) + γ_{6,1} · π(a1)·v + γ_{6,2} · π(a2)·v²
```

where `γ_{6,1} = ξ^((p−1)/3)` and `γ_{6,2} = ξ^(2(p−1)/3)` are
Fp2-valued constants. These constants encode the action of `π` on
the indeterminate `v` and are precomputed once at static
initialisation by Fp2 exponentiation.

Fp12 Frobenius extends the pattern: for `a = a0 + a1·w`,

```
π(a) = π(a0) + γ_{12,1} · π(a1)·w
```

with `γ_{12,1} = ξ^((p−1)/6)`, again precomputed.

One Fp12 Frobenius reduces to one Fp6 Frobenius on each of `c0` and
`c1`, plus one Fp2 multiplication by `γ_{12,1}` on the result for
`c1`. Each Fp6 Frobenius costs three Fp2 conjugations plus two Fp2
multiplications. A Frobenius is therefore on the order of six Fp2
multiplications, not twelve Fp modular exponentiations.

The **cyclotomic squaring** is a specialised squaring for elements
in the cyclotomic subgroup of `Fp12*` — the subgroup that GT lives
in. Inside the cyclotomic subgroup, the squaring formula simplifies
substantially: the cost drops from a full Fp12 multiplication
(about twelve Fp2 multiplications) to about four Fp2 squarings, a
factor of roughly three.

The reference implementation surfaces the cyclotomic squaring as a
delegate but forwards it to the generic Fp12 squaring; correctness
is the reference's goal, not speed. A production backend supplies
its own cyclotomic-squaring implementation following Granger-Scott
or Karabina compression, and the final exponentiation's hard part —
which runs hundreds of squarings on a cyclotomic-subgroup input —
benefits proportionally.

The Frobenius identity `π^12 = id` and the property that `π` fixes
Fp-embedded Fp12 elements are both checked as property-based tests.
Either failing would indicate a wrong γ-constant or a wrong sign on
`ξ`; both pass on every test run.

## § 8 BN254: the same shape, four real differences

BN254 (alt_bn128) is the other pairing-friendly curve wired into the
library. It shares the overall shape of §§ 1–7 — embedding degree
twelve, the same `Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12` tower form, an optimal-ate
pairing split into a Miller loop and a final exponentiation — so this
section does not repeat that structure. It calls out only the places
where BN254 differs, because those are the places a port from one curve
to the other goes wrong.

### § 8.1 Field tower and the non-residue

The base field is the 254-bit prime `q` rather than BLS12-381's 381-bit
`p`, so every field element is 32 bytes instead of 48. The tower steps
are the same shape — `Fp2 = Fp[u]/(u² + 1)`, `Fp6 = Fp2[v]/(v³ − ξ)`,
`Fp12 = Fp6[w]/(w² − v)` — but the cubic non-residue is

```
ξ = 9 + u    (BN254)        versus        ξ = 1 + u    (BLS12-381)
```

This is the single most confused BN254 constant. It is `9 + u`, meaning
the Fp2 element with real part `9` and imaginary part `1`, not the
basis-swapped `1 + 9u`. Everything downstream — the Fp6 multiply's
`v³ → ξ` wrap, the twist coefficient, and the Frobenius γ-constants —
is a function of `ξ`, so the value is pinned directly by a `v³ = ξ`
structural test rather than relying on the algebraic-law tests (which
hold for any non-residue).

### § 8.2 Miller-loop count: `6u + 2`, and positive

BLS12-381 loops over `|x|` with `x = −0xd201000000010000` and pays one
Fp12 inversion at the exit to compensate for the negative sign. BN254's
optimal-ate loop count is

```
6u + 2,    u = 4965661367192848881    (the BN parameter)
```

For alt_bn128 `u` is positive, so `6u + 2` is positive and there is **no
final inversion** and no `BigInteger.Parse` sign-bit trap on the loop
count — the trap that § 2 and the BLS literal's leading-zero guard exist
to avoid simply does not arise here. (A BN curve with negative `u` would
reintroduce it; alt_bn128 is not such a curve.)

BN254 also has two steps BLS12-381 does not. After the main loop the
optimal-ate construction appends a short "Frobenius tail":

```
f ← f · ℓ(T, π(Q));    T ← T + π(Q)
f ← f · ℓ(T, −π²(Q));  T ← T − π²(Q)
```

where `π` is the `p`-power Frobenius on the G2 point. These two lines
fold in the part of the ate exponent that the loop over `6u + 2` does
not reach. BLS12-381's loop parameter already spans its whole ate
exponent, so it has no such tail.

### § 8.3 Twist direction: D-twist, not M-twist

BLS12-381 uses the M-twist with coefficient `b' = 4·ξ` and the untwist
`ψ(X, Y) = (X·w⁻², Y·w⁻³)` (§ 5). BN254 uses the **D-twist**:

```
b' = b / ξ = 3 / (9 + u)        ψ(x', y') = (w²·x', w³·y')
```

The defining difference is the *division* by `ξ` (M-twist multiplies),
and correspondingly the untwist uses the positive powers `w²`, `w³`
where the M-twist uses `w⁻²`, `w⁻³`. The naming conventions for "which
direction is D" vary across the literature; what is unambiguous, and
what the code commits to, is the algebra: a point `(x', y')` on
`y² = x³ + 3/(9+u)` maps to `(w²x', w³y')` on `y² = x³ + 3`, because
`(w³y')² = w⁶ y'² = ξ y'²` and `(w²x')³ + 3 = ξ x'³ + 3 = ξ(x'³ + 3/ξ)`.

The reference does not encode the line value as a sparse Fp12 element
the way § 4 does for BLS12-381. Instead it untwists `Q` once via `ψ`
and runs the textbook chord-and-tangent line evaluation entirely in
Fp12. This trades the sparse-multiply speedup for having the twist
convention appear in exactly one place — the `ψ` map — rather than
spread across a slot map, which is where D-versus-M ports most often go
wrong. A production backend reintroduces the sparse line evaluation; at
that point the D-twist slot map (`w⁰`, `w⁻²`, `w⁻³` contributions, the
mirror of § 4's M-twist `w⁰`, `w²`, `w³`) becomes load-bearing and must
be derived for the D-twist specifically.

### § 8.4 Final exponentiation and Frobenius constants

The easy part is structurally identical: `(p⁶ − 1)(p² + 1)` is one
conjugation, one inversion, two Frobenius applications, and two
multiplications, exactly as in § 6. The hard-part *factor*
`(p⁴ − p² + 1)/r` has the same form but a different value (it is a
function of `q` and `r`), and the reference again computes it by
square-and-multiply on the precomputed exponent rather than via the
BN-specific addition chain.

The Frobenius γ-constants are given by the same formulas as § 7 —
`γ_{6,1} = ξ^((p−1)/3)`, `γ_{6,2} = ξ^(2(p−1)/3)`,
`γ_{12,1} = ξ^((p−1)/6)` — but because both `ξ` (now `9 + u`) and the
prime (now `q`) differ, the resulting Fp2 constants are entirely
different numbers. They are derived from `ξ` at static initialisation
the same way, so the `π^12 = id` test guards them identically.

### § 8.5 What is the same

Worth stating explicitly, because it is the larger part: the Fp2 layer
(`u² = −1`, Frobenius is conjugation since `q ≡ 3 mod 4`), the tower
multiplication and inversion formulas, the Miller-loop double-and-add
skeleton, the easy-part final exponentiation, and the Fp2/Fp12 square-
root and y-sign conventions are all shared. The curve-specific surface
is exactly §§ 8.1–8.4: one constant (`ξ`), one loop count (`6u + 2`
plus the Frobenius tail), one twist direction (D), and one set of
derived-from-`ξ` Frobenius constants.
