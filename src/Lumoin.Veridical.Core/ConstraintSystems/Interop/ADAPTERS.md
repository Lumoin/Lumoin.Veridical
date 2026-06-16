# R1CS file-format adapters

This document describes the file-format adapters that let
`Lumoin.Veridical` consume externally-produced R1CS instances and
witnesses. Two formats are implemented: the iden3 Circom binary format
(§§ 3–8) and the QED-it ZkInterface v1 format (§§ 9–12). Both use the
same delegate-based shape (§ 2).

For a conceptual introduction — what R1CS is, what the various files
are, and where Lumoin.Veridical sits — see
[`Circom/CIRCOM-INTEROP.md`](Circom/CIRCOM-INTEROP.md) (the R1CS primer
and the Circom pipeline) and
[`ZkInterface/ZKINTERFACE-INTEROP.md`](ZkInterface/ZKINTERFACE-INTEROP.md)
(the ZkInterface message model). This document is the adapter-contract
reference; those are the explainers.

## § 1 Purpose

Audited circuits written for the Circom ecosystem (Poseidon hashes,
SHA-256 in R1CS, ECDSA verification, Merkle proofs, range proofs,
set membership) compile to `.r1cs` binary files plus optional
`.wtns` witness files. The adapters in this folder parse those
files into Veridical's existing
`Lumoin.Veridical.Core.ConstraintSystems` types — `RawR1csInstance`,
`R1csMatrix`, `RawR1csWitness` — so the same circuits can be proved
with Veridical's standard and masked Spartan provers without
anyone hand-translating constraint matrices into C#.

## § 2 The pipe-based delegate shape

The public surface is two delegate types in this folder:

```csharp
public delegate RawR1csInstance R1csPipeReaderDelegate(
    PipeReader pipe,
    WellKnownR1csFormatLabel format,
    CurveParameterSet curve,
    SensitiveMemoryPool<byte> pool,
    CancellationToken cancellationToken);

public delegate RawR1csWitness R1csWitnessPipeReaderDelegate(
    PipeReader pipe,
    WellKnownR1csFormatLabel format,
    CurveParameterSet curve,
    SensitiveMemoryPool<byte> pool,
    CancellationToken cancellationToken);
```

`PipeReader` lets the adapter consume bytes from files, network
streams, and in-memory buffers uniformly. The
`WellKnownR1csFormatLabel` parameter is the wire-format
discriminator: a single delegate type can carry any concrete
reader, and the reader implementation validates the label matches
the format it parses. Writer-side delegates with parallel shape
are declared in the same folder but no implementations are wired
in this batch.

A reader does not auto-detect the wire format. The caller declares
which format the pipe carries; the reader produces the deliverable
type fully constructed and validated, no intermediate AST to
convert. The delegate-plus-label approach scales across adapters
cleanly: `ZkInterfaceR1csReader.Reader` and
`ZkInterfaceWitnessReader.Reader` are `R1csPipeReaderDelegate` /
`R1csWitnessPipeReaderDelegate` values that validate against
`WellKnownR1csFormatLabel.ZkInterface` and slot into application
wiring next to the Circom readers.

## § 3 The Circom binary format

The iden3 binary specification for `.r1cs` files
(`https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md`)
is the authoritative source. The file shape:

- A 4-byte ASCII magic `r1cs`.
- A 4-byte little-endian version (only version 1 is accepted in
  this batch).
- A 4-byte little-endian section count.
- Variable-order sections, each prefixed by a 4-byte type code and
  an 8-byte little-endian payload size.

The reader interprets section type 1 (header) and section type 2
(constraints). Section type 3 (wire-to-label map) and the
UltraPlonk custom-gates sections are read past per the spec. The
header section carries the field size, the prime modulus, the wire
count, the public-output / public-input / private-input counts,
the label count, and the constraint count. The constraint section
emits, for each constraint, three linear combinations (A, B, C)
encoded as a term-count followed by `(wire_index, coefficient)`
pairs. circom emits the terms in construction order, **not**
necessarily ascending by wire index; the reader sorts the collected
triples by `(row, column)` when building each matrix, so any
intra-constraint term order parses identically (pinned by
`CircomR1csReaderOrderingTests`).

## § 4 Curve handling

The reader is wired for BLS12-381 and BN254. circom selects the curve
at compile time — `-p bls12381` for BLS12-381, the default `bn128`
for BN254 — and the reader checks the header's prime modulus against
the *requested* curve's scalar-field order, rejecting a mismatch at
parse time with `R1csUnsupportedFieldException` (naming both the
expected and found modulus). The check switches on the curve
identifier via `WellKnownCurves` / `R1csMatrix.GetValueByteSize`
rather than hardcoding one curve, so wiring a further curve into
`Lumoin.Veridical.Core` extends the adapter automatically.

## § 5 The `WellKnownR1csFormatLabels` registry

`WellKnownR1csFormatLabel` is a readonly record struct wrapping a
single `Identifier` string. Three labels are reserved:

- `CircomBinary` (`circom-r1cs-v1`) — `CircomR1csReader`.
- `CircomWitness` (`circom-wtns-v2`) — `CircomWitnessReader`.
- `ZkInterface` (`zkinterface-v1`) — `ZkInterfaceR1csReader` and
  `ZkInterfaceWitnessReader` (§§ 9–12).

The discriminator-via-label design (rather than auto-detection
from magic bytes) is deliberate. Auto-detection would couple every
reader to every other format's magic-byte conventions, and a
caller mis-wiring readers to formats would be caught at runtime
inside the reader rather than at the application's wiring site.
The explicit-label approach surfaces the mismatch at the call
site with a clear `ArgumentException`.

## § 6 Public-input convention

The iden3 `.r1cs` format declares `nPubOut` and `nPubIn` in the
header but carries no witness values. To produce a fully-constructed
`RawR1csInstance`, the Circom reader sets `RawR1csInstance.PublicInputCount`
to zero and routes every wire except the constant `z[0] = 1`
through the corresponding `RawR1csWitness`. The Circom pub/priv
distinction is therefore captured by the parsed file and recorded
in the reader's parse path but not exposed through the resulting
`RawR1csInstance` shape today.

Tests that need Circom's pub/priv distinction reconstruct an
instance with caller-supplied public values; that pathway becomes
first-class when `RawR1csInstance` grows a deferred-public-input mode
(provide `PublicInputCount` separately from the public-input bytes,
or expose a method that copies an existing instance's matrices into
a new instance with different public-input values). Both are
follow-up work; the byte-faithful prove-and-verify gate this batch
delivers does not depend on either.

## § 7 The Circom witness (`.wtns`) format

Circom's `.wtns` format carries the dense witness vector
`z = (1, z[1], ..., z[nWitness - 1])` for a specific assignment of
public inputs and private signals to a compiled circuit. The
format has no separate specification document; the encoder source
at `https://github.com/iden3/snarkjs/blob/master/src/wtns_utils.js`
is the de-facto reference, and the iden3 witness-generator C++
runtime emits the same bytes.

File shape:

- A 4-byte ASCII magic `wtns`.
- A 4-byte little-endian version (only version 2 is accepted in
  this batch).
- A 4-byte little-endian section count.
- Variable-order sections, each prefixed by a 4-byte type code and
  an 8-byte little-endian payload size — the same framing as
  `.r1cs`.

Two section types are interpreted:

- Section type 1 (header) — field size, prime modulus, and the
  witness length `nWitness`. The header validates the same prime
  modulus as the `.r1cs` reader and the same `(field_size == 32)`
  invariant for BLS12-381.
- Section type 2 (witness data) — `nWitness × field_size` bytes,
  one element per slot in little-endian byte order. Other section
  types (PolyR / PolyB sections that some snarkjs versions emit)
  are read past per the same spec-conformance pattern as the
  `.r1cs` reader.

The reader drops `z[0] = 1` (the canonical constant) and returns
the remaining elements via `RawR1csWitness.FromCanonical` in
Veridical's canonical big-endian byte order — the LE→BE byte
reversal mirrors what `CircomR1csReader` does for matrix
coefficients. This matches the `PublicInputCount = 0,
all-wires-in-the-witness` convention from § 6: the `.r1cs` and
`.wtns` adapters compose end-to-end with no re-splitting of the
witness vector at the call site. The fixture-driven
end-to-end test parses both `.r1cs` and `.wtns` for the
multiplier2 circuit and runs the result through both `SpartanProver`
and `MaskedSpartanProver`; both proofs verify.

## § 8 Real-world Poseidon fixture

The hand-constructed multiplier2 fixture proves the adapters work
on a minimal canonical layout. The second test gate, in
`CircomPoseidonFixtureTests`, exercises the adapters against
`.r1cs` + `.wtns` pairs compiled — for both BLS12-381 and BN254 — by a
pinned `circom` / `snarkjs` / `circomlib` from the owned source
`circuits/poseidon2.circom`. The pinned toolchain and regeneration
commands are documented in
`test/Lumoin.Veridical.Tests/ConstraintSystems/Interop/Circom/Fixtures/REGENERATE.md`.

Two properties of this fixture matter for the adapter contract:

- **Section ordering**: snarkjs writes the constraints section
  (type 2) before the header section (type 1) and the wire-to-label
  map (type 3). The multiplier2 fixture writes header-first; the
  Poseidon fixture writes constraints-first. The `CircomR1csReader`
  captures section payloads as `ReadOnlySequence<byte>` slices
  during the section-walk loop and processes them once both
  header and constraints have been located — section order is
  irrelevant to the reader's correctness, and the Poseidon fixture
  is the test that proves it.
- **Field-level satisfaction**: 100 constraints × 103 wires across
  three matrices means roughly three hundred coefficient round
  trips through the LE→BE byte reversal. A single sign / endianness
  / row-column transposition error in the parser would slip
  through the structural assertions but fail the
  `RawR1csInstance.CheckSatisfiedBy` evaluation that computes
  `A·z ∘ B·z` and `C·z` in BLS12-381 scalar arithmetic. The fixture
  passes that check, which is a much stronger claim than "the file
  parsed without throwing."

Spartan needs power-of-two row and column counts; the Poseidon
fixture's 100 × 103 shape does not feed directly into the prover.
Padding to 128 × 128 and running Spartan on a real Poseidon hash
is a follow-up exercise that does not change the adapter
contract; the multiplier2 fixture already validates the
Spartan-side gate.

## § 9 The ZkInterface format

The QED-it ZkInterface v1 schema
(`https://github.com/QED-it/zkinterface/blob/master/zkinterface.fbs`)
is the authoritative source. Unlike the iden3 `.r1cs` format — one
sectioned buffer — a ZkInterface stream is a **sequence of
size-prefixed FlatBuffers messages**: a 4-byte little-endian length
(excluding the prefix) followed by that many bytes of a self-contained
FlatBuffers `Root` buffer. Each `Root` carries one `message` union, and
the union discriminator selects `CircuitHeader`, `ConstraintSystem`,
`Witness`, or `Command`.

The instance reader interprets the `CircuitHeader` (the field
maximum, the free-variable id, the instance variables) and one or
more `ConstraintSystem` messages (the constraints — multiple such
messages concatenate). Each constraint is a `BilinearConstraint` of
three `Variables` linear combinations `(A) · (B) = (C)`, where a
`Variables` is a vector of `variable_ids` paired with a `values` byte
vector; the per-term coefficient width is `values.length /
variable_ids.length`, and a coefficient shorter than the field is
zero-padded (a longer one must have zero surplus high bytes).
`Command` messages (gadget-flow control) are not interpreted.

The wire format is FlatBuffers — vtable/offset indirection rather
than a linear section walk — so the reader hand-parses it through a
small cursor (`FlatBufferCursor` / `FlatBufferTable` /
`FlatBufferVector`) rather than taking a `Google.FlatBuffers`
dependency. The cursor was validated against the upstream
`examples/example.zkif` before any matrix code was written.

## § 10 The swappable FlatBuffers decoder

The ZkInterface readers split the FlatBuffers decoding from the R1CS
assembly across a delegate seam, so the FlatBuffers implementation is
replaceable:

```csharp
public delegate void ZkInterfaceMessageDecoderDelegate(
    ReadOnlySequence<byte> source,
    IZkInterfaceMessageSink sink,
    CancellationToken cancellationToken);
```

A decoder reads the stream and **pushes** decoded fields — span by
span — into an `IZkInterfaceMessageSink` (`OnFieldMaximum`,
`OnFreeVariableId`, `OnInstanceVariable`, `BeginConstraint` /
`OnConstraintTerm` / `EndConstraint`, `OnWitnessVariable`; all
defaulting to no-ops so a sink implements only what it consumes). The
built-in `ZkInterfaceCursorDecoder.Decoder` is the hand-written
implementation; `ZkInterfaceR1csReader.CreateReader(decoder)` and
`ZkInterfaceWitnessReader.CreateReader(decoder)` bind an alternate
(for example a code-generated FlatBuffers backend), and the default
`Reader` properties are those factories applied to the cursor decoder.

The contract is **synchronous and span-based by deliberate choice**.
An `IAsyncEnumerable` pull contract cannot yield `ref struct`/spans, so
it would force materialising every message into managed objects —
putting field elements and witness values on the GC heap, against the
library's `SensitiveMemoryPool` discipline — for a streaming benefit
that is marginal anyway (FlatBuffers needs whole-buffer random access,
so a message cannot be decoded before its bytes are all present). The
push/sink shape keeps decoded scalars on the stack at the seam, and it
makes the assembler-as-sink unit-testable by direct pushes.

## § 11 ZkInterface field, variable, and public-input handling

**Field.** `CircuitHeader.field_maximum` is the canonical
little-endian field order minus one, so the field prime is
`field_maximum + 1`; the reader reconciles it against the requested
curve's scalar modulus (`ZkInterfaceFieldReconciler`), rejecting a
mismatch — or an undeclared field — with
`R1csUnsupportedFieldException`. BLS12-381 and BN254 are wired, the
same set as the Circom reader.

**Columns.** ZkInterface variable ids are arbitrary `uint64`; the
reader maps id directly to matrix column (id 0 = the constant one),
sizing the column count as `max(free_variable_id, highest id seen +
1)`. No separate remap table is kept, which keeps the instance's
columns aligned with a witness read under the same id convention.

**Public/witness split.** ZkInterface separates public
(`CircuitHeader.instance_variables`) from private
(`Witness.assigned_variables`) values natively. Veridical nonetheless
follows the same convention as the Circom adapter (§ 6):
`RawR1csInstance.PublicInputCount = 0`, with the whole `z[1..]`
treated as witness. `CheckSatisfiedBy` assembles `z = (1,
publicInputs, witness)`, and a genuine split would require the public
columns to occupy positions `1..p` contiguously — which arbitrary
ZkInterface ids do not guarantee — so the PublicInputCount-zero
convention is both consistent with Circom and robust to any id
arrangement. Promoting the instance variables to first-class public
inputs is the same deferred `RawR1csInstance` work noted in § 6.

## § 12 The ZkInterface witness reconstruction and fixtures

Because the convention of § 11 treats `z[1..]` as the whole witness,
`ZkInterfaceWitnessReader` reconstructs it by scattering **both** the
`CircuitHeader.instance_variables` and the `Witness.assigned_variables`
values into one dense vector keyed by column = variable id (column 0,
the constant, is dropped; unassigned columns default to zero), into a
`SensitiveMemoryPool` buffer. A consequence of this convention: a
witness `.zkif` must carry a `CircuitHeader` — it supplies the field,
the variable count, and the public values that complete `z[1..]`.

The fixture gate (`ZkInterfaceFixtureTests`) parses owned
`bls12_381/multiplier2.zkif` and `bn254/multiplier2.zkif` through both
readers, checks `CheckSatisfiedBy` on each curve, and runs a Spartan
prove-and-verify round trip on the BLS12-381 instance. Crucially the
fixture bytes are produced by the **canonical `zkinterface` Rust
crate's own FlatBuffers serializer** (pinned `=1.3.4`; see
`test/Lumoin.Veridical.Tests/ConstraintSystems/Interop/ZkInterface/Fixtures/REGENERATE.md`),
so the hand-written reader parsing them is a genuine interop check
against the reference implementation rather than a round trip against
our own assumptions. The fixtures mix full-width 32-byte instance and
witness values with truncated single-byte coefficients, exercising
both element encodings.
