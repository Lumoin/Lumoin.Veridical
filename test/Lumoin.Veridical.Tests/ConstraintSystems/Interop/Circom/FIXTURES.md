# Circom binary fixtures

Two fixture pairs live in this folder:

- `CircomR1csFixtures.Multiplier2Bytes` and
  `CircomWitnessFixtures.Multiplier2Bytes`: small, hand-constructed
  hex constants for a 2-row multiplication circuit, used by the
  end-to-end Spartan prove-and-verify gate.
- `Fixtures/bls12_381/poseidon2.{r1cs,wtns}` and
  `Fixtures/bn254/poseidon2.{r1cs,wtns}`: a `circomlib` Poseidon(2)
  two-input preimage compiled per curve from the owned source
  `Fixtures/circuits/poseidon2.circom`, used by the parser /
  satisfaction-check gate. Pinned toolchain and regeneration commands
  live in `Fixtures/REGENERATE.md`.

Both fixture sets match the iden3 binary format spec
(`https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md`).
The hand-crafted multiplier2 hex is owned by construction; the Poseidon
bytes are regenerable from owned `.circom` sources with the pinned
toolchain recorded in `Fixtures/REGENERATE.md`.

## `Multiplier2Bytes` (`.r1cs`, 384 bytes)

Source circuit:

```
pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main = Multiplier();
```

Real `circom -p bls12381 --r1cs multiplier2.circom` emits one
constraint (`a * b = c`). The fixture here is augmented with a
trivial second constraint `z[0] · z[0] = z[0]` so the parsed
matrix's row count is two — the smallest power-of-two row count the
Spartan prover accepts. The padding has no semantic effect (it
holds for any satisfying witness with `z[0] = 1`) and mirrors the
m=2 padding pattern the existing `SpartanRoundtripTests` use.

The byte layout, per the iden3 spec:

```
File header (12 bytes)
  Magic "r1cs"     72 31 63 73
  Version          01 00 00 00
  Section count    03 00 00 00

Section 1 (header, 12-byte type/size header + 64-byte payload)
  Type             01 00 00 00
  Size             40 00 00 00 00 00 00 00
  field_size       20 00 00 00                 (32)
  prime            r little-endian             (BLS12-381 scalar)
  nWires           04 00 00 00
  nPubOut          01 00 00 00
  nPubIn           00 00 00 00
  nPrvIn           02 00 00 00
  nLabels          04 00 00 00 00 00 00 00
  nConstraints     02 00 00 00

Section 2 (constraints, 12-byte type/size header + 240-byte payload)
  Type             02 00 00 00
  Size             f0 00 00 00 00 00 00 00
  Constraint 0
    A: nTerms=1, (wire=2, coeff=1 LE)
    B: nTerms=1, (wire=3, coeff=1 LE)
    C: nTerms=1, (wire=1, coeff=1 LE)
  Constraint 1
    A: nTerms=1, (wire=0, coeff=1 LE)
    B: nTerms=1, (wire=0, coeff=1 LE)
    C: nTerms=1, (wire=0, coeff=1 LE)

Section 3 (wire-to-label, 12-byte type/size header + 32-byte payload)
  Type             03 00 00 00
  Size             20 00 00 00 00 00 00 00
  Labels           four 8-byte little-endian label IDs (sequential)
```

## `Bn254Multiplier2Bytes` (`.r1cs`, 384 bytes)

The BN254 counterpart of `Multiplier2Bytes`. Because every coefficient in this
circuit is `1` (prime-independent) and BN254's scalar field is also 254 bits
(so `field_size` stays `0x20` = 32), the BN254 fixture is byte-for-byte
identical to the BLS one except for the header's 32-byte little-endian `prime`,
which becomes BN254's `r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
It is produced by a single substring swap in `CircomR1csFixtures`
(`Bls12Curve381ScalarPrimeLittleEndianHex` → `Bn254ScalarPrimeLittleEndianHex`),
not a separate transcription. `Bn254CircomR1csReaderTests` parses it under
`CurveParameterSet.Bn254` (exercising the reader's BN254 prime dispatch) and
proves/verifies the parsed instance with the BN254 reference Spartan backends.
Requesting it under BLS12-381 is rejected as a prime mismatch.

A BN254 Poseidon fixture **is** now provided
(`Fixtures/bn254/poseidon2.{r1cs,wtns}`), regenerated from the same owned
`circuits/poseidon2.circom` as the BLS one — Poseidon's round constants are
field-specific, so it is a genuine BN254 compilation, not a prime swap.
`CircomPoseidonFixtureTests` parses both curves' Poseidon fixtures under their
respective `CurveParameterSet` and checks satisfaction. Regenerating it under the
pinned circom 2.2.3 surfaced (and fixed) a `CircomR1csReader` assumption that
linear-combination terms arrive in ascending wire order — circom does not
guarantee that, and the reader now sorts triples in its `TripleAccumulator`.

## `Multiplier2Bytes` (`.wtns`, 204 bytes)

Witness for the same `multiplier2` circuit with `a = 3`, `b = 11`,
`c = 33`, i.e. the witness vector `z = (1, c, a, b) = (1, 33, 3, 11)`.

The byte layout:

```
File header (12 bytes)
  Magic "wtns"     77 74 6e 73
  Version          02 00 00 00
  Section count    02 00 00 00

Section 1 (header, 12-byte type/size header + 40-byte payload)
  Type             01 00 00 00
  Size             28 00 00 00 00 00 00 00
  field_size       20 00 00 00                 (32)
  prime            r little-endian             (BLS12-381 scalar)
  nWitness         04 00 00 00

Section 2 (witness data, 12-byte type/size header + 128-byte payload)
  Type             02 00 00 00
  Size             80 00 00 00 00 00 00 00
  z[0] = 1   (32 bytes little-endian)
  z[1] = 33  (32 bytes little-endian)
  z[2] = 3   (32 bytes little-endian)
  z[3] = 11  (32 bytes little-endian)
```

The element ordering follows the Circom compiler's wire-numbering
convention for the multiplier2 circuit: `z[0] = 1` (constant),
`z[1] = c` (the only public output), `z[2] = a` and `z[3] = b`
(the two private inputs).

## Regeneration

Once `circom 2.x` and `snarkjs` are available on the reference
machine, the trivial `multiplier2.circom` source above can be
compiled with `circom -p bls12381 --r1cs --wasm multiplier2.circom`
and the witness produced with `node multiplier2_js/generate_witness.js
multiplier2_js/multiplier2.wasm input.json multiplier2.wtns` where
`input.json` is `{ "a": "3", "b": "11" }`. The produced `.r1cs`
will have one constraint instead of two; the parser-side test that
exercises the prove-and-verify path needs the padded form, so a
manual padding pass on top of `circom`'s output is the lift back to
this fixture's shape. The `.wtns` produced by `snarkjs` matches the
hex constant in `CircomWitnessFixtures.Multiplier2Bytes` byte for
byte.
