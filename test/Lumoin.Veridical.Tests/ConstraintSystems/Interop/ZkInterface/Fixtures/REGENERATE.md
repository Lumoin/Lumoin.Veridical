# Regenerating the owned ZkInterface fixtures

The `.zkif` byte files in `bls12_381/` and `bn254/` are checked in so the test
suite runs with no toolchain installed. This repository carries **no producer
source** — the repository holds no third-party or Rust code, only
reference-computed bytes — so this file records everything a regeneration
needs: the exact fixture specification, the pinned tool versions, and the
expected output hashes, making the provenance verifiable rather than imported
on trust. (The separate `example.zkif` is *vendored* upstream data, not
generated here; its provenance is in `FIXTURES.md`.)

## What they are

`bls12_381/multiplier2.zkif` and `bn254/multiplier2.zkif` are the padded
multiplier2 circuit — `a · b = c` plus a `1 · 1 = 1` padding row (so the shape is
2 constraints × 4 variables, a power of two for Spartan) — emitted as a
size-prefixed ZkInterface stream of `CircuitHeader`, `ConstraintSystem`, `Witness`.

- Variables `z = (one=0, c=1, a=2, b=3)`, `free_variable_id = 4`.
- `instance_variables` (public): `c` (id 1) = 33, as a full 32-byte little-endian element.
- `Witness.assigned_variables` (private): `a` (id 2) = 3, `b` (id 3) = 11, full 32-byte elements.
- Constraint coefficients are the single byte `1` (a *truncated* element; the reader
  zero-pads to the field width) — so the fixtures exercise both full-width and
  truncated element encodings.
- `field_maximum` = the curve's scalar field order minus one, canonical little-endian:
  the only difference between the two files. Satisfied by `a = 3, b = 11, c = 33`.

| Fixture | Bytes | SHA-256 |
|---------|-------|---------|
| `bls12_381/multiplier2.zkif` | 624 | `c9b92cabbb5244d2c03bdec45e673ec5ec60e1748b77173b1bcfad771289635a` |
| `bn254/multiplier2.zkif` | 624 | `c6f1fb5a1caa8f987853450651dab11febc1d340b5fcd673080037f7cc4d8321` |

## Why a real producer

The bytes are serialized by the **canonical `zkinterface` Rust crate's own
FlatBuffers code**, not by Veridical. So the hand-written reader in
`src/.../Interop/ZkInterface/` parsing them is a genuine interop check against the
reference implementation, not a round-trip against our own assumptions.

## Regenerating

The producer is a minimal Rust binary crate maintained **outside this
repository** (it lives with the other machine-local reference harnesses). Its
whole content is determined by this document: it depends on the `zkinterface`
crate pinned below, builds the circuit specified above with the crate's
`CircuitHeaderOwned` / `ConstraintSystemOwned` / `WitnessOwned` types, and
writes each curve's stream to `bls12_381/` and `bn254/` under this `Fixtures/`
directory. A regeneration is correct exactly when the emitted bytes match the
SHA-256 table above.

## Pinned toolchain

| Tool | Version | Notes |
|------|---------|-------|
| rustc / cargo | `1.95.0` | |
| `zkinterface` crate | `=1.3.4` | matches the upstream `zkinterface.fbs` schema the reader targets |
| `flatbuffers` crate | `0.5.0` | the transitive dep that actually serializes the wire format; pin it in the harness lockfile |

Pin every transitive dependency in the harness's `Cargo.lock`, so a
regeneration with the same rustc reproduces the bytes; verify against the
SHA-256 table either way.
