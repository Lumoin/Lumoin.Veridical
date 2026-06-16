# ZkInterface fixtures

## `example.zkif` — vendored upstream sample

`example.zkif` is the canonical example shipped by the ZkInterface project. It is
**vendored verbatim**, not generated here: it exercises the FlatBuffers cursor and
the message-stream parser over real upstream bytes, so a wire-format misread
surfaces against the reference producer rather than against our own assumptions.

| Property | Value |
|----------|-------|
| Source | `QED-it/zkinterface`, path `examples/example.zkif` |
| Upstream URL | `https://github.com/QED-it/zkinterface/blob/master/examples/example.zkif` |
| Pinned commit (last touched the file) | `2dd6ead091dd1b682df4c7417eec8f3a429e19c7` (2020-06-02) |
| Repo default-branch commit at vendoring time | `4f8d9785871ddf959500458d5f5d9912c0a851f7` (2021-07-21) |
| Schema (`zkinterface.fbs`) at that commit | union `Message { CircuitHeader, ConstraintSystem, Witness, Command }`, `root_type Root`, 4-byte LE size-prefixed framing |
| Size | 648 bytes |
| SHA-256 | `e7179437895140cffc978eb732505d148b48de299d46f93de0deff7890a17277` |

### What it contains

Three size-prefixed `Root` messages, in order (the structure is mirrored by the
upstream `examples/example.json`, which is the human-readable twin):

1. **`CircuitHeader`** — `instance_variables` = ids `[1, 2, 3]` with values
   `[3, 4, 25]` (4-byte little-endian elements: element size = `values.length / variable_ids.length` = 12 / 3),
   `free_variable_id` = 6, `field_maximum` = absent (the toy field is not declared).
2. **`ConstraintSystem`** — three bilinear constraints `(A)·(B) = (C)`:
   `v1·v1 = v4`, `v2·v2 = v5`, `1·(v4 + v5) = v3`.
3. **`Witness`** — `assigned_variables` = ids `[4, 5]` with values `[9, 16]`.

### Why it is structural-only

The field is a toy field with `field_maximum` absent, so `example.zkif` cannot be
reconciled against a wired curve (BLS12-381 / BN254). It validates **parsing**: the
FlatBuffers cursor (vtables, offsets, scalar/vector/sub-table reads) and the
size-prefixed message loop with union dispatch. End-to-end parse → satisfy →
Spartan over a real curve uses the owned BLS/BN254 `.zkif` fixtures added in W.4
(generated via the zkinterface Rust producer, with their own `REGENERATE.md`).
