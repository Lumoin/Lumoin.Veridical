# Scalar-field NTT fixture provenance

The fixture in this directory is a data dump computed independently of the library: pure
Python 3 integer arithmetic (`pow` and Horner evaluation), no third-party libraries and no
code shared with the C# implementation. The generating harness lives outside this repository
in a local, untracked directory; no harness code is committed here.

## Derivation

- Field orders: the BLS12-381 and BN254 (alt_bn128) scalar-field orders, matching the
  constants in `WellKnownCurves`.
- Domain generators: 7 (BLS12-381) and 5 (BN254) — prime quadratic nonresidues matching the
  conventional multiplicative generators of published parameter tables for these fields (for
  BLS12-381, 5 is a smaller nonresidue but not the convention; for BN254, 5 is the
  smallest); the harness asserts the Euler criterion before emitting.
- `omega_2pK = g^((r−1)/2^K) mod r`, asserted to have exact order `2^K` (half-order power
  equals `−1`, full-order power equals `1`) before emitting. The `2p32`/`2p28` entries pin
  the full 2-adic roots; independent published parameter tables (arkworks, gnark) list the
  same values for these fields.
- Codewords: coefficient-side ground truth for the systematic Reed–Solomon extension over
  consecutive-integer nodes — the polynomial with coefficients `c_i = i² + 42 + 1000·N + M`
  is Horner-evaluated at the points `0..M−1`. The engine under test computes the same map
  evaluation-side (message = evaluations at `0..N−1`, extension via NTT convolution), so
  agreement crosses two independent computation paths.

## Encoding

Data lines are `key=hex` with exactly 64 hex characters per value: one scalar field element
as 32 canonical big-endian bytes, the library's own scalar layout (no reversal on parse).
Header prose carries no `=`-separated hex, so the standard keep-only-hex-values parse skips
it.

## Fixture inventory

| File | Gate | Contents |
|------|------|----------|
| `scalar-ntt-anchor-output.txt` | ScalarNtt conformance | Per-curve `one`/`of_scalar_300` parse anchors, `omega_2p{4,6,s}` roots of unity, and the `cw5x16`/`cw9x23` Reed–Solomon codewords for BLS12-381 and BN254 |

## Regeneration

`py <local-anchor-harness>\scalar_ntt_anchor.py > test\Lumoin.Veridical.Tests\TestMaterial\ScalarNtt\scalar-ntt-anchor-output.txt`

The harness asserts every mathematical property it relies on before emitting, so a wrong
constant fails generation rather than producing a drifted fixture.
