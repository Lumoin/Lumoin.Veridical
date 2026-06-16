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

Use the Circom adapter instead when you already have an audited circuit —
a circomlib Poseidon hash, an ECDSA gadget, a Merkle-path verifier — that is
written in Circom and compiled by the real toolchain. The builder does not
reimplement those; it gives you the primitives (arithmetic constraints and a
small predicate library) to compose your own.

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
