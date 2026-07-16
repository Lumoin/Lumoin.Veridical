# Building R1CS circuits in C#

This document explains how to construct an R1CS instance directly in C#
with `R1csCircuitBuilder`, without authoring a `.circom` file or running an
external toolchain. It is written for a reader who knows what a
zero-knowledge proof is but has not hand-built a rank-1 constraint system.

It is the third way to obtain an R1CS instance in Veridical. The other two
parse externally-produced files — Circom `.r1cs`/`.wtns` and the
ZkInterface format — and are documented in
[`Interop/Circom/CIRCOM-INTEROP.md`](Interop/Circom/CIRCOM-INTEROP.md) and
[`Interop/ZkInterface/ZKINTERFACE-INTEROP.md`](Interop/ZkInterface/ZKINTERFACE-INTEROP.md).
This one is the in-process path: you describe the circuit in C#, and the
builder produces the `RawR1csInstance` and `RawR1csWitness` that feed the
Spartan prover. The R1CS primer in `CIRCOM-INTEROP.md` § 1 — three matrices
`A`, `B`, `C` and a witness `z` with `(A·z) ∘ (B·z) = (C·z)`, the constant
wire `z[0] = 1` — applies here unchanged; this document assumes it.

## § 1 What the builder is for

Use the builder when you want to construct a constraint system from C#: in
tests, in examples, and for application-level predicates ("prove this value
is in that range", "prove this id is one of these") that you would rather
express in code than compile from a separate circuit language. It is the
natural choice for small to medium circuits whose logic you own.

For the Poseidon hash and Poseidon Merkle-path membership the builder now
provides native gadgets (§ 11) — no Circom toolchain needed. Use the Circom
adapter instead when you already have a different audited circuit — an ECDSA
gadget, a bespoke arithmetic circuit — that is written in Circom and compiled by
the real toolchain. For everything the gadgets and the predicate library do not
cover, the builder gives you the primitives (arithmetic constraints and a small
predicate library) to compose your own.

The builder deliberately stops short of a circuit DSL. There is no symbolic
execution, no AST, no operator sugar on variables themselves — it is
method-call notation that appends operations to a list. What it buys you over
hand-writing sparse-matrix triples is that you name variables, write
constraints as linear-combination expressions, and let the builder assign
indices and lay out the matrices.

## § 2 The fold-over-state model

The builder is a fold. It accumulates a list of **transformations** — pure
functions `(circuit, builder, state) → circuit` — and `Build()` applies them in
order to a seed circuit (just the constant-one wire), producing the final
`R1csCircuit`. Transformations are added through `With(...)`, the builder's one
composition point; the fluent declaration, constraint, and predicate methods
are sugar that call `With` for you. Because the fold is deferred to `Build()`
and every transformation is pure, two identically-configured builders produce
equal circuits and `Build()` is idempotent.

A declaration is that transformation plus an eager index assignment:

```csharp
R1csVariableIndex x = builder.DeclareWitnessVariable("x");
// Computes x's index immediately — so you can reference it in later constraint
// expressions — and underneath appends a transformation roughly equivalent to:
//   builder.With((circuit, _, _) => /* circuit + DeclareWitnessVariableOp(x, "x") + its metadata */);
```

A circuit's canonical form is the **immutable list of operations** the fold
produces (`DeclarePublicInputOp`, `AddConstraintOp`, …) plus the curve and the
per-position variable metadata — not the three matrices. Compilation is a
separate, later step (`Compile()`): the matrix triples exist only once a circuit
is evaluated against input bindings. So a circuit is **reusable** — the same
"x is in [a, b]" compiles against many different x — and structural rewrites
(padding now, optimisation passes later) operate on the operations list as
transformations composed through `With` (§ 7).

This fold/aggregate builder is shared with the Verifiable library; see its
`Builder<TResult, TState, TBuilder>` there for the asynchronous flavour applied
to credential construction. Veridical's `R1csBuilder<TResult, TState, TBuilder>`
is the synchronous form (circuit construction is pure CPU work).

## § 3 Variable kinds and the layout convention

Veridical's witness vector is `z = (1, public_inputs, witness)`: the constant
one at index 0, then the public inputs as a contiguous block, then the
private witness and any auxiliary variables. The builder owns index
assignment and produces exactly this layout, so its output drops straight
into the prover with no remapping.

Because the layout requires the public inputs to occupy a contiguous block
right after the constant, the builder enforces a rule: **all public inputs
must be declared before the first witness variable and before the first
constraint.** Declaring a public input after either throws
`InvalidOperationException`. (The file adapters cannot enforce this — they
receive id assignments they did not make — but the builder owns the ids, so
it guarantees the layout by construction.)

Four variable kinds are recorded as metadata: the constant one, public
inputs, witness variables, and *intermediate* variables. Intermediates are
auxiliary witness values a predicate introduces (the bits of a range
decomposition, a partial product); they compile identically to witness
variables and the distinction is for inspection only.

```csharp
var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
R1csVariableIndex outcome = builder.DeclarePublicInput("outcome");   // index 1
R1csVariableIndex a = builder.DeclareWitnessVariable("a");           // index 2
R1csVariableIndex b = builder.DeclareWitnessVariable("b");           // index 3
// builder.DeclarePublicInput("late"); // would throw: witness already declared
```

## § 4 Linear combinations as expressions

A constraint relates three linear combinations: `(left) · (middle) = (right)`,
one row each of `A`, `B`, `C`. `R1csLinearCombination` is the expression type
— `Σ cᵢ·xᵢ + k` with `BigInteger` coefficients and a constant term. It is
immutable and normalised (terms sorted by variable, duplicates summed, zero
coefficients dropped), so two combinations that denote the same affine form
compare equal. Coefficients stay arbitrary-precision integers in the builder;
reduction modulo the scalar field happens once, at compile time, which is why
the builder is curve-agnostic.

You build combinations with the `+`, `-`, and scalar `*` operators. One sharp
edge to know: in C#, a user-defined operator is found only on the operand's
own type, and a bare `R1csVariableIndex` is a *position*, not an expression —
it carries no operators (by design). So `x + y` and `2 * x` do **not** compile
when `x` and `y` are variable indices. Promote a variable to a combination
first with `R1csLinearCombination.From`:

```csharp
using static Lumoin.Veridical.Core.ConstraintSystems.R1csLinearCombination;

R1csLinearCombination expr = 2 * From(x) + From(y);   // 2·x + y
R1csLinearCombination shifted = From(price) - FromConstant(100);
```

Where a method simply *takes* a combination, the implicit conversion from a
variable index applies and you can pass the bare index — no `From` needed:

```csharp
builder.AddConstraint(a, b, outcome);   // a · b = outcome
```

## § 5 Worked example: multiplier2

The smallest interesting circuit proves "I know two numbers whose product is
a public value." Declare the product as a public input and the two factors as
witness variables, then add the single constraint:

```csharp
var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
R1csVariableIndex product = builder.DeclarePublicInput("product");
R1csVariableIndex a = builder.DeclareWitnessVariable("a");
R1csVariableIndex b = builder.DeclareWitnessVariable("b");
builder.AddConstraint(a, b, product);   // a · b = product
R1csCircuit circuit = builder.Build();
```

Compile it against a satisfying assignment. `Compile` returns the public
instance and the private witness, and it verifies satisfaction as it goes —
an assignment that does not satisfy the constraints throws
`R1csCircuitCompilationException` naming the first failing row, so a mistake
surfaces here rather than as a rejected proof later.

```csharp
var inputs = new R1csCircuitInputs(new Dictionary<string, BigInteger>
{
    ["product"] = 33,
    ["a"] = 3,
    ["b"] = 11,
});

(RawR1csInstance instance, RawR1csWitness witness) =
    circuit.Compile(inputs, SensitiveMemoryPool<byte>.Shared);
```

This is the same one-multiplication circuit the Circom adapter doc builds
from a `.circom` source; here it is authored directly in C#, and the compiled
matrices are byte-for-byte what the hand-crafted reference produces.

## § 6 Worked example: range check

Predicates are generators: each emits constraints (and, where it needs them,
auxiliary variables) on top of `AddConstraint`. `AssertRangeCheck(value, bits,
name)` proves `value ∈ [0, 2^bits)` by decomposing it into `bits` boolean
auxiliary variables and constraining their weighted sum to equal the value.

The auxiliaries are named from the `name` prefix — `{name}_bit_0` through
`{name}_bit_{bits-1}` — and **the caller binds them**: the builder does not
auto-compute auxiliary values. You do not compute them by hand, though —
`R1csPredicateWitness` derives the bindings for each predicate, using the same
names and arithmetic:

```csharp
var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
R1csVariableIndex v = builder.DeclareWitnessVariable("v");
builder.AssertRangeCheck(v, bits: 16, name: "v");
R1csCircuit circuit = builder.Build();

const long value = 40000;
var bindings = new Dictionary<string, BigInteger> { ["v"] = value };
R1csPredicateWitness.AddRangeCheckBits(bindings, "v", value, bits: 16, CurveParameterSet.Bls12Curve381);

(RawR1csInstance instance, RawR1csWitness witness) =
    circuit.Compile(new R1csCircuitInputs(bindings), SensitiveMemoryPool<byte>.Shared);
```

The range check costs `bits + 1` constraints and `bits` auxiliary variables.
The ordering predicates build on it: `AssertLessThanOrEqual(a, b, bits, name)`
range-checks `b - a`, and `AssertGreaterThanOrEqual` swaps the operands. The
other predicates — `AssertEqual`, `AssertNotEqual`, `AssertBoolean`,
`AssertInSet` — are summarised in `R1csCircuitBuilderPredicates`; each
documents its constraint count, its auxiliaries, and the binding the caller
must supply, and each has a matching `R1csPredicateWitness` method
(`AddNotEqualInverse`, `AddSetMembershipProducts`, the ordering-bit helpers)
that computes the auxiliary values for concrete inputs.

## § 7 Composition through `With`

Anything that operates on the whole in-progress circuit is a transformation
composed through `With`. `R1csCircuitTransformations` holds these named
transformations; the first is `PowerOfTwoPadding`, which rounds the circuit's
row and column counts up to a power of two — floored at 2, the smallest size
Spartan's sumcheck can evaluate — by appending zero-weight (`0 · 0 = 0`)
constraint rows and dummy witness columns. It preserves the real constraints,
variables, and the public-input block, and is idempotent.

```csharp
R1csCircuit circuit = builder
    .With(R1csCircuitTransformations.PowerOfTwoPadding)
    .Build();
```

Padding adds witness columns named `__pad_witness_n`; bind them to zero at
compile time with `R1csPredicateWitness.AddPowerOfTwoPaddingBindings`:

```csharp
var bindings = new Dictionary<string, BigInteger> { /* your inputs */ };
R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

(RawR1csInstance instance, RawR1csWitness witness) =
    circuit.Compile(new R1csCircuitInputs(bindings), SensitiveMemoryPool<byte>.Shared);
```

Future structural passes — constraint deduplication, common-subexpression
elimination, constant folding — land in `R1csCircuitTransformations` as further
`With`-composable transformations; the composition surface is already in place.

## § 8 Plugging the result into Spartan

`Compile` hands back a `RawR1csInstance` and a `RawR1csWitness` — exactly the
types the Spartan prover consumes, no different from an instance parsed from a
file. Prove and verify as usual: derive a Hyrax commitment key sized to the
circuit's column count, wrap it in a proving key, and call `Prove` with the
curve's scalar, group, and multilinear-extension backends; the verifier takes
the public instance and the proof.

```csharp
var provingKey = new SpartanProvingKey(commitmentKey);   // commitmentKey sized to the column count
using var prover = new SpartanProver(provingKey);
using SpartanProof proof = prover.Prove(instance, witness, transcript, /* backends */, pool);
```

The Spartan prover requires power-of-two row and column counts (at least 2 on
each axis — its sumcheck needs at least one round per axis). Reach that shape by
composing `R1csCircuitTransformations.PowerOfTwoPadding` through `With` (§ 7)
rather than hand-adding padding constraints. The full prover/verifier wiring —
the scalar and G1 reference backends, the
Fiat-Shamir transcript, the multilinear-extension delegates — is shown in the
`Spartan/` tests and the [`Spartan/README.md`](../Spartan/README.md); the
builder changes nothing about it. What the builder gives you is the front end:
a constraint system authored in C# instead of compiled from Circom.

## § 9 Supply-chain predicates and fixed-point encoding

Regulatory claims about a product — "the recycled content is at least 30 %",
"the carbon footprint is at most 12.5 kg CO₂e" — are comparisons over decimal
quantities, but the constraint system compares field integers. Three types turn
one into the other: `FixedPointScale` and `FixedPointDomain` pin how a decimal
becomes a field integer, and `R1csCircuitBuilderSupplyChainPredicates` names the
comparisons. They add no op types — a supply-chain predicate is a range check
plus an ordering check on the primitives of § 6 — and hold no credential, RDF, or
serialization concern: the input is a `System.Decimal`, the output a proof.

### Exact-or-reject encoding

`FixedPointScale.OfFractionalDigits(d)` fixes a scale whose factor is `10^d`, and
`Encode` maps a non-negative decimal to `value · 10^d` as an exact integer. It
never rounds: a value carrying finer resolution than the scale (`32.567` at one
digit) is rejected, not truncated. That is a soundness choice, not fastidiousness
— rounding a measured value up, or a "≥" threshold down, is exactly how a
sub-threshold quantity would clear the bar. Because one scale encodes both
operands, `encode(a) ≥ encode(b)` in the field holds precisely when `a ≥ b` as
decimals. Any quantisation of noisier source data is the caller's explicit
decision upstream, never a silent property here.

### One domain per comparison, and a field-safe width

A bare scale is not enough to compare safely: the range check that underlies "≥"
and "≤" reduces a difference modulo the scalar field, and a difference sized too
close to the field order can wrap and read as in-range. `FixedPointDomain.Create`
pairs a scale with an inclusive maximum and derives the range-check width from the
encoded maximum, capped at `FixedPointScale.MaximumEncodedBits` (252). The cap is
the decisive number: the difference range check rejects a negative (false)
difference only when `r ≥ 2^(bits+1)`, and the smaller wired scalar field
(BN254, `r ≈ 2^253.6`) satisfies that at 252 bits but not at 253. Every
supply-chain predicate takes a domain, so both operands of a comparison are
encoded at one scale and sized within one field-safe width — a mismatched scale
is not expressible.

### The named predicates

`AssertQuantityAtLeast(measured, threshold, name)` proves the measured quantity is
at least the threshold; `AssertQuantityAtMost(measured, cap, name)` proves it is at
most the cap. The bound is a `FixedPointBound`, which carries its domain and is
either of two forms. `FixedPointBound.Constant(domain, value)` bakes the value into
the circuit id, so a proof attests against the regulatory number structurally
rather than against a prover-suppliable input. `FixedPointBound.PublicInput(domain,
value, variable)` carries the bound in a public input the verifier supplies, so one
circuit serves many thresholds. A constant is validated at compile time to lie
within the exact domain maximum; a public input is range-checked in-circuit into
the field-safe width `[0, 2^Bits)` (auxiliaries under `{name}_bound`) — enough to
keep the difference from wrapping, though not clamped to the exact maximum the way
a constant is.

Each predicate also range-checks the measured value into `[0, 2^Bits)` under
`{name}_domain`. That is load-bearing for "≤": without it, a measured value bound
to the field element just below the modulus reads as a small positive difference
and clears a bare cap check. Range-checking the measured value for "≥" as well
(where it is self-bounding under the 252 cap) keeps the soundness argument
independent of the operands' magnitudes and of which curve compiles the circuit.

```csharp
var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
FixedPointDomain percent = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(1), 100.0m);
R1csVariableIndex recycled = builder.DeclareWitnessVariable("recycled");
builder.AssertQuantityAtLeast(recycled, FixedPointBound.Constant(percent, 30.0m), "recycled");
R1csCircuit circuit = builder.Build();

var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
R1csSupplyChainWitness.AddQuantityAtLeastBindings(
    bindings, "recycled", "recycled", FixedPointBound.Constant(percent, 30.0m), measured: 32.5m, circuit.Curve);
```

`R1csSupplyChainWitness` fills the auxiliaries like `R1csPredicateWitness` does,
and additionally binds the measured variable itself — encoding the caller's decimal
at the domain's scale — so the compared value cannot be bound at a mismatched
scale. The helper owns the measured and auxiliary bindings. For a
`FixedPointBound.PublicInput` bound the caller binds the declared bound variable to
its encoding in the instance, since a public input is part of the statement the
caller assembles, not a witness the helper derives.

### The battery-passport bundle

A `SupplyChainClaim` is one named comparison as data — a caller-declared measured
variable, a domain, a public bound, and a direction. `AssertBatteryPassport` over
a span of claims is their conjunction: the bundle proves only when every claim
holds, each claim contributing its own `{name}_domain` and `{name}` auxiliaries
under a distinct name. Naming a claim is therefore data, not a new method per
claim shape.

```csharp
SupplyChainClaim[] claims =
[
    SupplyChainClaim.AtLeast("recycled", recycled, FixedPointBound.Constant(percent, 30.0m)),
    SupplyChainClaim.AtMost("carbon", carbon, FixedPointBound.Constant(kilograms, 12.50m)),
];
builder.AssertBatteryPassport(claims);
// R1csSupplyChainWitness.AddBatteryPassportBindings(bindings, claims, name => measurement(name), circuit.Curve);
```

The measured variable is one the *caller* declares, not one the bundle
auto-declares, and the claim carries its index. That is deliberate: a later
statement can tie the same variable to a commitment — a signed credential digest,
a Poseidon-Merkle leaf — that binds the proven quantity to its source.

A bundle names one measured quantity per claim (its witness helper keys each
measured binding by the claim name). To bound a *single* hidden value on two sides
— a band such as `30 % ≤ recycled ≤ 100 %` — do not bundle two claims over it;
apply `AssertQuantityAtLeast` and `AssertQuantityAtMost` to the one variable
directly, binding both through the single-predicate witness helpers, which take
the measured variable's name separately from the auxiliary-name prefix.

### Scope

As with the range check of § 6, a supply-chain proof binds the predicate over a
*supplied* measurement. It does not, on its own, tie that in-circuit value to a
signed credential or a committed graph; binding the measured value to its source
is a follow-on that composes an in-circuit membership or commitment gadget in
front of these predicates. What this section adds is the front half: the exact
encoding convention and the named, field-safe comparisons a compliance statement
is built from.

## § 10 Multi-tier aggregation by sequential composition

A product's carbon footprint is rarely made in one place. A battery pack's
cradle-to-gate footprint is its cell makers' footprints plus assembly; each cell's
is its material suppliers' footprints plus cell production; and so on up the chain.
Proving the finished product is under a regulatory cap therefore means aggregating
a footprint that no single party holds in full, out of proofs that each verify on
their own — every tier's contribution is an independently checkable proof rather
than a trusted claim. This composes from the § 9 predicates with no new machinery:
no recursion, and no hashing inside the circuit.

### One tier, one circuit

Model each tier as one circuit of a single shape. Its cradle-to-gate footprint
`pcf` is a **public output**; the already-proven footprints of its direct suppliers
enter as **public inputs** `upstream_j`; and the tier's own gate-to-gate emissions
`direct` are a **witness**. The tier asserts the cradle-to-gate identity and its own
cap:

```csharp
R1csVariableIndex pcf = builder.DeclarePublicInput("pcf");
R1csVariableIndex upstream = builder.DeclarePublicInput("upstream_0");
R1csVariableIndex direct = builder.DeclareWitnessVariable("direct");

builder.AssertRangeCheck(direct, domain.Bits, "direct_domain");           // own emissions into the field-safe width
builder.AssertEqual(pcf, R1csLinearCombination.From(direct) + upstream);  // pcf = own emissions + upstream
builder.AssertQuantityAtMost(pcf, FixedPointBound.Constant(domain, cap), "pcf");
```

Two range checks carry the anti-wrap guarantee, and both are load-bearing.
`AssertQuantityAtMost` (§ 9) pins `pcf` itself into the field-safe width
`[0, 2^Bits)`. The range check on `direct` forces
`pcf = direct + Σ upstream_j ≥ Σ upstream_j`: without it a prover could bind
`direct` to a large field element so that the sum wraps to a value below the true
upstream total, proving a cradle-to-gate footprint smaller than its own verified
inputs — the most damaging under-report the composition must forbid. A leaf tier is
the same shape with no `upstream_j`, where `pcf` is just the tier's own emissions.

### The committed output, and how it carries

"Sequential composition" is ordinary orchestration, not an in-circuit verifier.
Prove and verify each tier on its own. The value the verifier re-checks — the
transcript-bound public-input scalar, read back from the verified `RawR1csInstance`
in canonical big-endian — is the tier's **committed output** (here "committed" means
bound into the proof's Fiat-Shamir transcript and public, not sealed in a hiding
commitment):

```csharp
ReadOnlySpan<byte> publicInputs = verifiedInstance.GetPublicInputsBytes();
int scalarSize = publicInputs.Length / verifiedInstance.PublicInputCount;
var committed = new BigInteger(publicInputs[..scalarSize], isUnsigned: true, isBigEndian: true);   // pcf is the first public input
```

That exact scalar is bound into the next tier as an `upstream_j` public input.
Because one `FixedPointDomain` scale (§ 9) encodes every tier, the field addition is
the decimal roll-up exactly — `encode(a) + encode(b) = encode(a + b)` at a shared
scale — and a total sized within one field-safe width cannot wrap. Choose a domain
whose maximum covers the whole chain's total, not just one tier's.

### What is revealed

This composition reveals everything. A tier's total footprint `pcf` is public — it
is the value the next tier and the verifier consume — and every carried `upstream_j`
is public, so the tier's own emissions `direct = pcf − Σ upstream_j` are publicly
derivable, and a leaf tier's `pcf` is its own emissions outright. `direct` is carried
as a witness rather than a labelled public field — the seam a later hiding upgrade
would protect — but it is not confidential here. What the section proves is a
verifiable multi-tier roll-up under a cap across independently verified tiers, not
per-tier privacy.

A fully hiding carry — one where a tier's own figures are bound to its proof yet
never revealed — is out of reach on this stack: it needs either an in-circuit opening
of a hiding commitment to the carried value, or a discrete-log-equality argument on
the proof system's own scalar field. Adding that hiding is a later, larger piece; the
revealed composition here is the part that stands on today's primitives.

### Where the trust sits

Each proof binds only its own public inputs. Nothing inside a parent's proof forces
its `upstream_j` to be a value some child actually proved — the parent is equally
happy to aggregate an understated figure. The chain is bound by the orchestrator's
refusal to carry anything other than the child's committed output, which is a plain
field-element comparison against the scalar the child's verifier accepted. That
check is the load-bearing step of the composition; it is not delegated to the
circuit.

### Binding to a PCF data model

The composition mirrors how product-carbon-footprint data is exchanged in the
WBCSD Pathfinder / PACT data model, and the mapping is an interoperability note, not
a schema this layer parses — the § 9 scope boundary holds, the input is a
`System.Decimal` and the output a proof:

- The additive scalar is a product's **excluding-biogenic PCF per declared unit** —
  a kilograms-CO₂e figure a supplier already computes and exchanges. Each
  `upstream_j` is one such supplier record; `direct` is the tier's own gate-to-gate
  contribution; `pcf` is the tier's cradle-to-gate result to hand its own customer.
- The exact JSON field spellings differ across PACT Tech Spec major versions (the
  cross-sectoral-standards key, for one), so a binding maps onto the conceptual
  attribute, not a pinned key name; consult the live specification for the wire form.

Three things the arithmetic assumes and the crypto does **not** check — they are
application-layer preconditions the exchanging systems must satisfy before a sum
means anything:

- **Comparable units.** Summing footprints over a shared declared unit is valid only
  when the units reconcile; a real roll-up first scales each supplier's per-unit
  footprint by the quantity of that input embodied in the product (its
  bill-of-materials amount). The worked example sums per-unit footprints directly
  (unit amounts of one). A constant embodied quantity is a linear-combination
  coefficient — free, just a coefficient on `upstream_j` — while a hidden quantity is
  one product constraint per input; either extends the identity above with no new
  predicate types, but neither substitutes for the unit reconciliation itself.
- **Consistent reference period and boundary.** Footprints computed over different
  reference periods, geographies, or system boundaries are not additively
  comparable; the crypto sees only the scalars.
- **Consistent accounting standards.** Whether the inputs used the same
  cross-sectoral and product-category rules is a data-quality precondition, not a
  field relation.

The example proves the *composition* — that a rolled-up total is the faithful sum of
independently verified tier footprints and is under a cap — and is honest that the
*comparability* of what is summed is established upstream, in the data layer, not
here.

## § 11 Poseidon and Merkle gadgets

`R1csCircuitBuilderPoseidonGadget` adds two composable gadgets on top of the
primitives: the Poseidon hash and a Poseidon Merkle-path membership proof. Both
express, as R1CS constraints, computations that are otherwise imported from an
audited Circom circuit — so a prover can show in zero knowledge that a hidden
leaf is a member of a committed set.

The Poseidon permutation's linear layers are free in R1CS: adding a round
constant is a constant term on a linear combination, and the MDS mix is a linear
combination of the previous lanes. Only the `x^5` S-box costs constraints (three
each, through `x2 = x·x`, `x4 = x2·x2`, `x5 = x4·x`). `AssertPoseidonHash` folds
the rounds exactly as the plaintext `PoseidonPermutation.Permute` does and
returns a materialised digest wire; the auxiliaries come from
`R1csPoseidonWitness`, whose `BigInteger` trace is gated equal to
`PoseidonPermutation.Hash` (itself byte-compatible with circomlib over BN254).

```csharp
PoseidonParameters parameters = WellKnownPoseidonParameters.CreateCircomlibCompatible(
    inputCount: 2, curve, add, invert);

var builder = new R1csCircuitBuilder(curve);
R1csVariableIndex expected = builder.DeclarePublicInput("expected");
R1csVariableIndex a = builder.DeclareWitnessVariable("a");
R1csVariableIndex b = builder.DeclareWitnessVariable("b");
R1csVariableIndex digest = builder.AssertPoseidonHash([From(a), From(b)], parameters, "h");
builder.AssertEqual(From(digest), From(expected));
R1csCircuit circuit = builder.Build();

var bindings = new Dictionary<string, BigInteger> { ["a"] = 7, ["b"] = 11, ["expected"] = /* the hash */ };
R1csPoseidonWitness.AddPoseidonHashWitness(bindings, "h", [7, 11], parameters);
```

`AssertMerkleMembership` authenticates a leaf against a (public) root through a
binary Merkle path under a two-to-one Poseidon compression — the in-circuit form
of `MerkleAuthenticationPath.Verify`. At each level a boolean path bit (bit
`level` of the leaf index) drives a conditional swap realised with a single
multiplication — `swap = bit·(sibling − current)`, `left = current + swap`,
`right = sibling − swap` — so `bit = 0` hashes `(current, sibling)` (the running
node is the left child) and `bit = 1` hashes `(sibling, current)`, matching the
out-of-circuit convention. It follows that a `MerkleSetCommitment` membership
proof built with `PoseidonPermutation.GetMerkleHash` (the Poseidon shadow root)
verifies unchanged inside the circuit: feed the leaf digest, the index bits, and
the path siblings, bind the auxiliaries with
`R1csPoseidonWitness.AddMerkleMembershipWitness`, and the recomputed root is
asserted equal to the committed one.

```csharp
builder.AssertMerkleMembership(From(leaf), pathBits, siblings, From(root), parameters, "m");
```

Both gadgets are curve-parameterised through `PoseidonParameters` (BN254 and
BLS12-381 are wired). A full statement composes them: hash `(key, value)` to a
leaf with one `AssertPoseidonHash`, then prove that leaf's membership. As with
every predicate, the compile-time satisfaction check is the rejection mechanism
— a wrong leaf, sibling, root, direction bit, or under-constrained intermediate
fails to compile.
