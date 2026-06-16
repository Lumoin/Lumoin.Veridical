# ZkInterface interop: from a `.zkif` stream to a Lumoin.Veridical proof

This document explains how an R1CS circuit serialised in the **ZkInterface**
format reaches Lumoin.Veridical's prover, and what the format's pieces are. It is
a *conceptual* companion to [`ADAPTERS.md`](../ADAPTERS.md) (§§ 9–12), which
documents the adapter *contract* — the delegate shapes, the decoder seam, the
field and column model.

It assumes the R1CS primer in
[`../Circom/CIRCOM-INTEROP.md`](../Circom/CIRCOM-INTEROP.md) § 1: three matrices
`A`, `B`, `C` and a witness `z` with `(A·z) ∘ (B·z) = (C·z)` over a prime field,
`z[0] = 1` the constant wire. That document explains R1CS from scratch; this one
only covers what ZkInterface adds on top.

## § 1 What ZkInterface is

ZkInterface is a **framework-neutral interchange format** for zero-knowledge
statements, maintained by QED-it
(<https://github.com/QED-it/zkinterface>). Where a `.r1cs` file is specific to the
iden3 / Circom ecosystem, ZkInterface is a lingua franca: a gadget library in one
toolchain emits ZkInterface, and a proving backend in another consumes it, without
either knowing about the other. The schema covers the same R1CS content — the
constraint matrices, the field, the variable assignment — but wraps it in a
**FlatBuffers** encoding and a small message protocol designed for composing
sub-circuits ("gadgets").

The authoritative schema is a single FlatBuffers file, `zkinterface.fbs`. Its
encoding is *not* a linear byte layout you can read front-to-back: FlatBuffers
stores tables via a vtable of field offsets, and objects reference each other by
relative offsets that point both forward and backward. A reader therefore needs
the whole message buffer in hand and navigates it by following offsets.

## § 2 The message stream

A `.zkif` is a **sequence of size-prefixed messages**. Each message is a 4-byte
little-endian length followed by that many bytes of a self-contained FlatBuffers
`Root` table, and each `Root` carries exactly one `message` — a *union* that is
one of:

- **`CircuitHeader`** — the field (`field_maximum`), the variable-space size
  (`free_variable_id`), and the `instance_variables` (the public inputs/outputs,
  with their values).
- **`ConstraintSystem`** — a batch of `BilinearConstraint`s, each three linear
  combinations `(A) · (B) = (C)`. Multiple `ConstraintSystem` messages in a stream
  concatenate, so a large system can be chunked.
- **`Witness`** — the `assigned_variables`: the private values, *excluding* the
  instance variables and the constant one.
- **`Command`** — gadget-flow control (request a constraint or witness
  generation). Veridical ignores it.

So one `.zkif` stream can bundle a complete proving job — header, constraints,
witness — or carry just part of one. This is the structural difference from
Circom, where the constraints (`.r1cs`) and the witness (`.wtns`) are always
*separate files*; ZkInterface puts them in one message stream.

## § 3 How values are carried

A few ZkInterface specifics shape the reader:

- **The field is the order minus one.** `CircuitHeader.field_maximum` is the
  largest field element — i.e. the prime `r` minus one — in canonical
  little-endian. The prime is `field_maximum + 1`. (The upstream toy
  `example.zkif` omits it; a real circuit declares it.)
- **Variable ids are arbitrary.** A `Variables` is a list of `variable_ids`
  (arbitrary `uint64`, with id 0 always the constant one) paired with a `values`
  byte blob. Ids need not be dense or sorted.
- **Elements can be truncated.** Within a `Variables`, the per-element width is
  `values.length / variable_ids.length`, and an element shorter than the field is
  treated as zero-extended. So a coefficient of `1` may be a single byte even in a
  256-bit field.
- **Public and private are separated at the source.** The public values live in
  `CircuitHeader.instance_variables`; the private values live in
  `Witness.assigned_variables`. Reassembling the full witness vector means reading
  both.

## § 4 Where Lumoin.Veridical sits

Lumoin.Veridical is a **consumer** of ZkInterface, not a producer. Two readers lift
the format into Veridical's own types:

- `ZkInterfaceR1csReader` parses the `CircuitHeader` + `ConstraintSystem` messages
  into a `RawR1csInstance` (the matrices), mapping each variable id directly to a
  matrix column and reversing every field element from ZkInterface's little-endian
  to Veridical's canonical big-endian.
- `ZkInterfaceWitnessReader` parses the same stream into a `RawR1csWitness`.

Both validate `field_maximum` against the requested curve (BLS12-381 or BN254) and
reject a mismatch with `R1csUnsupportedFieldException`. From there the instance and
witness feed the Spartan prover exactly as a natively-constructed instance would;
what Veridical *produces* is a Spartan proof.

Internally the readers separate "decode the FlatBuffers bytes" from "assemble the
R1CS" across a swappable delegate (`ADAPTERS.md` § 10): the hand-written cursor is
the default, but a different FlatBuffers backend can be substituted without
touching the assembly. The decoder *pushes* decoded values into the assembler as
spans, which keeps field elements off the managed heap — the same pooled-memory
discipline the rest of the library follows.

## § 5 The public/witness convention

R1CS proof systems split `z` into public and private parts, and `CheckSatisfiedBy`
assembles `z = (1, publicInputs, witness)`. ZkInterface separates the two natively
— so the *genuine* mapping would be `instance_variables → public inputs`,
`assigned_variables → witness`. Veridical does **not** take that mapping today, for
a concrete reason: the public part must occupy columns `1..p` contiguously, and
arbitrary ZkInterface ids give no such guarantee.

Instead Veridical uses the same convention as the Circom adapter:
`PublicInputCount = 0`, and the whole `z[1..]` (every variable but the constant) is
the witness. `ZkInterfaceWitnessReader` therefore reconstructs `z[1..]` by
**scattering both** the `instance_variables` and the `assigned_variables` values
into one dense vector keyed by column = id. A practical consequence: a witness
`.zkif` must include a `CircuitHeader`, since the public values there are part of
the full witness vector. (Promoting instance variables to first-class public
inputs is deferred work, the same item the Circom adapter notes.)

## § 6 What the fixture tests demonstrate, and reproducibility

The fixture gate proves **interop correctness** against the reference
implementation. The owned `bls12_381/multiplier2.zkif` and
`bn254/multiplier2.zkif` are serialised by the **canonical `zkinterface` Rust
crate's own FlatBuffers code** — not by Veridical — so a reader that parses them
correctly has agreed with the reference producer, not merely with our own
serialiser (Veridical has none; it never emits `.zkif`). The end-to-end test parses
instance and witness, checks that the witness *satisfies* the instance under
in-field arithmetic (`CheckSatisfiedBy` — the load-bearing assertion, since an
endianness or column error parses cleanly yet fails satisfaction), and, for the
power-of-two multiplier2 shape, runs a Spartan prove-and-verify round trip.

The `.zkif` bytes stay checked into the repository so the suite runs with no Rust
toolchain. Alongside them, `Fixtures/REGENERATE.md` records the pinned crate
version, the owned producer source, and the regeneration command — so the
provenance is verifiable rather than imported on trust. The vendored upstream
`example.zkif` (a toy field, used only to pin the FlatBuffers cursor structurally)
has its own provenance note in `Fixtures/FIXTURES.md`.
