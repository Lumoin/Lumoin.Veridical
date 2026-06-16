# Regenerating the owned ZkInterface fixtures

The `.zkif` byte files in `bls12_381/` and `bn254/` are checked in so the test
suite runs with no toolchain installed. This file records the owned producer
source (in `producer/`), the pinned tool versions, and the exact command that
regenerates the bytes — so the provenance is verifiable rather than imported on
trust. (The separate `example.zkif` is *vendored* upstream, not generated here;
its provenance is in `FIXTURES.md`.)

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

## Pinned toolchain

| Tool | Version | Notes |
|------|---------|-------|
| rustc / cargo | `1.95.0` | |
| `zkinterface` crate | `=1.3.4` | pinned in `producer/Cargo.toml`; matches the upstream `zkinterface.fbs` schema the reader targets |
| `flatbuffers` crate | `0.5.0` | the transitive dep that actually serializes the wire format; pinned by the committed `producer/Cargo.lock` |

`producer/Cargo.lock` pins every transitive dependency, so a regeneration with the
same rustc reproduces the bytes.

## Command

```bash
# From this Fixtures/ directory; writes bls12_381/ and bn254/ subfolders.
cargo run --release --manifest-path producer/Cargo.toml -- .
```

The producer (`producer/src/main.rs`) is curve-independent except for the two
`field_maximum` constants (the big-endian scalar field orders minus one, reversed
to little-endian on the way in). Keep the produced `.zkif` bytes; the Rust
`target/` directory is a build artifact and need not be checked in.
