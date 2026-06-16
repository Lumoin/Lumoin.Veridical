# ConstraintSystems

The R1CS (Rank-1 Constraint System) primitives in this directory are
the bridge between circuit descriptions and proof systems. An R1CS
instance encodes an arithmetic computation as three matrices over a
finite field; a satisfying witness is a vector that makes the
matrices' product equation hold. Different *front-ends* (Circom,
Noir, arkworks DSL, hand-authored circuits) compile programs into
R1CS instances. Different *back-ends* (Spartan2, Plonk, Groth16,
Halo2) prove R1CS satisfiability. R1CS is the common ground.

Veridical's `R1csInstance` is the canonical in-library encoding for
Veridical's proof systems. The encoding choices (sparse COO matrix
layout, big-endian byte serialization, scalar field, satisfaction
check via `R1csSatisfaction.Violated` for diagnostic precision) are
Veridical's own.

## Standard and relaxed R1CS

Two related forms are supported:

- **Standard R1CS** (`R1csInstance`, `R1csWitness`) is what compiled
  circuits produce and what proof systems like Spartan2 consume
  directly. The satisfaction condition is `(A·z) ∘ (B·z) = (C·z)`.
- **Relaxed R1CS** (`RelaxedR1csInstance`, `RelaxedR1csWitness`) has
  two extra terms: a scalar `u` and an error vector `E`. The
  satisfaction condition is `(A·z) ∘ (B·z) = u · (C·z) + E`. Folding
  schemes (Nova, ProtoStar, future batches) use this form because it
  composes homomorphically.

## Variable layout convention

Veridical's variable vector is `z = (1, public_inputs, witness)`. The
constant 1 at index 0 is universal across all R1CS conventions; the
placement of public inputs before the witness is a choice. Some
external R1CS encodings use `z = (witness, 1, public_inputs)`
instead. Both are sound; the
difference matters for byte-level interoperability and is handled by
adapter code, not by changing this library's convention.

## Building circuits in C#

`R1csCircuitBuilder` constructs an R1CS instance directly in C# — the
in-process front-end, alongside the file adapters. You declare public
inputs and witness variables, add constraints as linear-combination
expressions, and compile against input bindings to a `RawR1csInstance` /
`RawR1csWitness` pair; a small predicate library (range checks, equality,
ordering, set membership) composes on top. See
[`CONSTRAINT-BUILDER.md`](CONSTRAINT-BUILDER.md) for the model and worked
examples.

## Adapters

External R1CS sources (Circom `.r1cs` files, Noir's R1CS output,
arkworks-serialized R1CS, hand-authored fixtures) are consumed via
adapter projects that implement `R1csPipeReaderDelegate` and
`R1csPipeWriterDelegate` (delegate definitions will land in a
post-v1 batch). Adapters live outside this library — in separate
`Lumoin.Veridical.Adapters.*` projects — and depend on this library's
types. The conversion is a byte-layout projection plus a
variable-layout remapping where the source's column convention
differs; the scalar field must match between source and target.

R1CS adapters are a real interoperability layer between Veridical and
the broader zk-circuit ecosystem. Unlike proof-byte interoperability
(which depends on many implementation-level conventions aligning),
R1CS represents satisfiability statements that can be re-expressed in
any encoding without altering what they assert. A Circom-authored
circuit, after adaptation to Veridical's encoding, is the same R1CS
statement and is provable by Veridical's Spartan2 prover.
