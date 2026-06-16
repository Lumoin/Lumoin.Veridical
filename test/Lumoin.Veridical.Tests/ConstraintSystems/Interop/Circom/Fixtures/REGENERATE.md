# Regenerating the Circom fixtures

The `.r1cs` and `.wtns` byte files in `bls12_381/` and `bn254/` are checked in so
the test suite runs with no toolchain installed. This file records the owned
`.circom` sources (in `circuits/`), the pinned tool versions, and the exact
commands that regenerate the bytes — so the provenance is verifiable rather than
imported on trust.

## Pinned toolchain

| Tool | Version | Install |
|------|---------|---------|
| circom | `v2.2.3` | Rust binary, built from source (no crates.io publish): `git clone --branch v2.2.3 https://github.com/iden3/circom.git && cd circom && cargo build --release` → `target/release/circom`. Needs rustc ≥ 1.78 (its `Cargo.lock` is lockfile-version 4); built and verified with rustc 1.95.0. |
| snarkjs | `0.7.5` | `npm install -g snarkjs@0.7.5` |
| circomlib | `2.0.5` (npm; git tag `v2.0.5`) | `npm install circomlib@2.0.5` — record the resolved git SHA in this table when regenerating |

> Record the exact circomlib commit SHA `npm` resolves here on first regeneration;
> circomlib's Poseidon round-constant generation has changed across versions, and
> the SHA is what actually pins the produced `.r1cs` bytes.

## Sources (curve-independent)

`circuits/multiplier2.circom` and `circuits/poseidon2.circom` are compiled once
per curve target. The curve is selected by circom's `--prime` flag — `bls12381`
for BLS12-381, the default `bn128` for BN254 — so the `.circom` source itself does
not change between curves. Inputs for witness generation are
`circuits/<name>.input.json`.

## Commands

Run from this `Fixtures/` directory, with `circomlib` reachable via `-l` (e.g.
`-l ../../../../../node_modules` or wherever `npm install circomlib` placed it):

```bash
# --- BLS12-381 (--prime bls12381) ---
circom circuits/multiplier2.circom  --r1cs --wasm --prime bls12381 -o bls12_381/ -l <node_modules>
circom circuits/poseidon2.circom  --r1cs --wasm --prime bls12381 -o bls12_381/ -l <node_modules>

# --- BN254 (default prime bn128) ---
circom circuits/multiplier2.circom  --r1cs --wasm -o bn254/ -l <node_modules>
circom circuits/poseidon2.circom  --r1cs --wasm -o bn254/ -l <node_modules>

# --- witnesses (one per circuit/curve, using the circuit's input.json) ---
# circom emits a <name>_js/ folder containing <name>.wasm + generate_witness.js
node bls12_381/poseidon2_js/generate_witness.js \
     bls12_381/poseidon2_js/poseidon2.wasm \
     circuits/poseidon2.input.json \
     bls12_381/poseidon2.wtns
# ...repeat for multiplier2, and for the bn254/ outputs.
```

Keep the produced `<name>.r1cs` and `<name>.wtns`; the `<name>_js/` witness-
generator folders are build artifacts and need not be checked in.

## Provenance baseline and known divergences

- **Poseidon was previously imported** from the third-party
  `perturbing/plutus-plonk-example` repo with no version pin (see the historical
  `README.md`). Regenerating from `circuits/poseidon2.circom` with the pinned
  circomlib replaces that imported BLS fixture with one whose source we own, and
  produces the parallel BN254 fixture. Because the imported fixture's circomlib
  version is unknown, the regenerated `.r1cs` will **not** be byte-identical to the
  old import and may have a different constraint/wire count than the historical
  `100 / 103`. The tests assert *properties* (parse succeeds, witness satisfies
  via `CheckSatisfiedBy`, Spartan round-trips where the shape is a power of two),
  not the frozen counts — update any remaining hard-coded `Expected*Count` to the
  regenerated shape when V.4b runs.

- **multiplier2 stays hand-crafted for the Spartan path.** A circom `multiplier2`
  is a single rank-1 constraint, which Spartan cannot prove (it requires a
  power-of-two row count). The Spartan reader tests therefore continue to use the
  hand-crafted, padding-augmented two-constraint multiplier2 in
  `CircomR1csFixtures.cs` (already owned, not imported). `circuits/multiplier2.circom`
  documents the canonical un-padded circuit and is what a `--r1cs` regeneration
  yields; it is provided for provenance and as a reader fixture, not as the
  Spartan input.
