# Circom interop: from a `.circom` circuit to a Lumoin.Veridical proof

This document explains how circuits written in the Circom ecosystem reach
Lumoin.Veridical's prover, and what each artifact along the way actually is.
It is written for a reader who knows what a zero-knowledge proof is — "I can
convince you I know a secret satisfying some condition without revealing the
secret" — but who has not worked with rank-1 constraint systems (R1CS) or the
Circom toolchain before.

It is a *conceptual* companion to [`ADAPTERS.md`](../ADAPTERS.md), which one
folder up documents the adapter *contract* — the delegate shapes, the
format-label discriminator, the binary section walk, the public-input
convention. Read this first to understand what the files are; read `ADAPTERS.md`
when you need the parsing details.

## § 1 What an R1CS is

Most zero-knowledge proof systems do not prove statements about programs
directly. They prove statements about a flattened, arithmetic form of the
computation called a **rank-1 constraint system**. Flattening a computation into
this form is what makes it provable; everything Circom does is in service of
producing it.

An R1CS over a prime field is three matrices `A`, `B`, `C` and a **witness
vector** `z`. The system is *satisfied* by `z` when, for every row `i`,

```
(A·z)[i] · (B·z)[i] = (C·z)[i]      (all arithmetic modulo the field prime r)
```

Writing `∘` for the element-wise (Hadamard) product of two vectors, the whole
system in one line is `(A·z) ∘ (B·z) = (C·z)`. (This is the exact form
Lumoin.Veridical checks; see `R1csSatisfaction` and `RawR1csInstance.CheckSatisfiedBy`,
whose `Violated` case reports `(A·z)[i]·(B·z)[i] mod r` against `(C·z)[i] mod r`
for the first failing row.)

Each row is one **constraint**, and the rank-1 shape — one multiplication of two
linear combinations per row — is the only thing a constraint may express. A row
of `A` (and of `B`, of `C`) is a vector of field coefficients; `A·z` dots that
row with the witness to produce "a weighted sum of witness entries." So each
constraint reads: *(some linear combination of the witness) times (another linear
combination) equals (a third linear combination)*. Addition and multiplication
by constants are free inside a linear combination; the single rank-1
multiplication is the only place two *variables* meet.

The first witness entry is fixed: `z[0] = 1`. This is the constant wire, and it
lets a linear combination encode a constant term (a coefficient on `z[0]`).

**Worked example — `multiplier2`.** The smallest interesting circuit proves "I
know two numbers `a` and `b` whose product is `c`." Order the witness as
`z = [1, a, b, a·b]`. One constraint suffices:

```
A = [0, 1, 0, 0]      (A·z = a)
B = [0, 0, 1, 0]      (B·z = b)
C = [0, 0, 0, 1]      (C·z = a·b)
```

so the single row says `a · b = a·b`. Any `(a, b)` you plug in produces a witness
that satisfies it, and the witness reveals `a` and `b` — which is the point: the
*proof* over this R1CS is what hides them.

(Circom numbers wires output-first, so the real compiled `multiplier2` orders the
witness as `z = [1, c, a, b]` — the output `c` is wire 1, the inputs `a`, `b` are
wires 2 and 3 — and the constraint becomes `(A·z = z[2]) · (B·z = z[3]) = (C·z =
z[1])`, i.e. `a · b = c`. The shape is identical; only the wire numbering differs.
§ 4 returns to this.)

## § 2 The `.r1cs` file *is* the constraint system

A `.r1cs` file is a binary serialisation of the three matrices `A`, `B`, `C`
together with a header: the field prime `r`, the number of wires, the number of
constraints, and the split of wires into public outputs, public inputs, and
private inputs. It contains **no witness** — it is the statement to be proved,
not any particular solution to it.

The crucial property for reproducibility: a `.r1cs` is *deterministic given the
`.circom` source and the compiler version*. The same source compiled by the same
`circom` produces bit-identical `.r1cs` bytes. The binary layout — magic,
version, a section count, then variable-order typed sections — is documented by
iden3 at <https://github.com/iden3/r1csfile> (the byte offsets and section type
codes live there; `ADAPTERS.md` § 3 describes which sections Lumoin.Veridical
reads).

## § 3 The `.wtns` file *is* one specific solution

A `.wtns` ("witness") file is a binary serialisation of one witness vector `z`
that satisfies the constraint system — the dense `z = (1, z[1], …, z[n-1])` for a
particular assignment of inputs. Different *inputs to the circuit* produce
different `.wtns` files; the `.r1cs` does not change. Where the `.r1cs` is the
question, the `.wtns` is one answer.

Its layout is "header + a sequence of field elements in canonical little-endian,
indexed by wire position." There is no standalone specification; the snarkjs
encoder at <https://github.com/iden3/snarkjs> is the de-facto reference (see
`ADAPTERS.md` § 7).

## § 4 The `.circom` source language

You do not write `.r1cs` matrices by hand — you write a circuit in **Circom**, a
high-level DSL for arithmetic circuits, and the compiler flattens it to R1CS. A
Circom `template` declares input signals, output signals, and constraint
statements relating them. The operator `<==` both assigns a signal and emits the
constraint that pins it; `===` emits a bare equality constraint.

```circom
pragma circom 2.0.0;

template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;     // assign c = a*b AND emit the constraint a*b - c = 0
}

component main = Multiplier2();
```

This ten-line source compiles to the one-constraint R1CS of § 1. Circom assigns
wire 0 to the constant `1`, then numbers the **output** signals, then the inputs
— which is why the compiled witness is ordered `[1, c, a, b]` rather than the
textbook `[1, a, b, a·b]`. The arithmetic is the same; only the column ordering
of `A`, `B`, `C` follows Circom's wire numbering.

Realistic circuits compose audited templates from **circomlib** — Poseidon and
MiMC hashes, SHA-256, ECDSA verification, Merkle-tree membership, comparators,
range checks. A two-input Poseidon hash, for instance, flattens to about a
hundred constraints across a hundred wires; the coefficients are the hash's
field-specific round constants, not the all-`1` coefficients of `multiplier2`.

## § 5 The compilation pipeline

The `circom` compiler is a Rust binary. It consumes `.circom` source and emits
the constraint system (`.r1cs`) and a witness *generator* (`.wasm`); the witness
generator, driven by snarkjs (or the iden3 C++ runtime) with a concrete input,
emits a `.wtns`:

```
multiplier2.circom
      │  circom multiplier2.circom --r1cs --wasm
      ▼
multiplier2.r1cs          multiplier2.wasm
 (the constraints)         (the witness generator)
                                  │  snarkjs wtns calculate \
                                  │      multiplier2.wasm input.json multiplier2.wtns
                                  ▼
                            multiplier2.wtns
                             (one solution, for the inputs in input.json)
```

The `.r1cs` is produced **once per circuit**. The `.wtns` is produced **once per
input** — `input.json` for `multiplier2` is as small as `{ "a": "3", "b": "11" }`,
and a different input yields a different witness against the same `.r1cs`.

## § 6 Where Lumoin.Veridical sits

Lumoin.Veridical is a **consumer** of `.r1cs` and `.wtns`, not a producer of
them. It does not compile circuits and it does not run circom or snarkjs. The
Circom adapter (`CircomR1csReader`, `CircomWitnessReader`) parses the two binary
formats and lifts them into Lumoin.Veridical's own constraint-system types —
`RawR1csInstance`, `R1csMatrix`, `RawR1csWitness` — converting each field element
from Circom's little-endian to Lumoin.Veridical's canonical big-endian on the way
in. From there the instance and witness feed the Spartan prover exactly as a
natively-constructed instance would.

What Lumoin.Veridical *produces* is a **Spartan proof**: a cryptographic object
attesting "I know a witness satisfying this constraint system" without revealing
the witness. A Spartan verifier, given the proof and the public part of the
constraint system, accepts or rejects. The Circom toolchain gets the statement
into R1CS; Lumoin.Veridical proves knowledge of a solution to it.

The adapter reads any curve Lumoin.Veridical has wired (BLS12-381 and BN254
today): the `.r1cs`/`.wtns` header's prime modulus is checked against the
requested curve's scalar-field order, and a mismatch is rejected at parse time
with `R1csUnsupportedFieldException`. The curve identity rides on the parsed
instance, not on the file format.

## § 7 What the fixture tests demonstrate

The fixture-driven tests prove **interop correctness**: that the adapter reads
what the real upstream toolchain writes, and that what it reads is sound. End to
end, a fixture test asserts that a `.circom` source, compiled by a pinned `circom`
and witness-generated by a pinned snarkjs, produces `.r1cs` and `.wtns` bytes
that Lumoin.Veridical parses into a well-formed instance and witness; that the
witness *satisfies* the parsed instance under in-field arithmetic
(`CheckSatisfiedBy` — the load-bearing assertion, since a single endianness or
row/column transposition error would parse cleanly yet fail satisfaction); and,
for power-of-two-sized circuits, that the Spartan prover produces a proof the
verifier accepts.

What they deliberately do **not** demonstrate is byte-equivalent regeneration:
Lumoin.Veridical never emits `.r1cs` or `.wtns`, so there is nothing to compare
byte-for-byte. The claim is "the adapter consumes what the toolchain produces,"
not "the adapter reproduces the toolchain."

Two fixtures carry the load. `multiplier2` is the minimal canonical layout —
all-`1` coefficients, header-first section order. `poseidon2` is the realistic
case — non-trivial field-specific coefficients, ~100 constraints, and snarkjs's
constraints-first section ordering — which is what proves the reader is robust to
real toolchain output rather than just the hand-crafted minimum.

## § 8 Reproducibility

The `.r1cs` and `.wtns` byte files stay checked into the repository so the test
suite runs with no toolchain installed. Alongside them, `REGENERATE.md` records
the exact pinned versions of `circom`, `snarkjs`, and `circomlib`, the `.circom`
sources, the `input.json` files, and the command sequences that regenerate the
bytes. Anyone with the pinned tooling can reproduce identical fixtures from
sources we own — so the provenance is verifiable rather than imported on trust,
and adding a fixture for a new curve is the same one-command step as regenerating
an existing one.
