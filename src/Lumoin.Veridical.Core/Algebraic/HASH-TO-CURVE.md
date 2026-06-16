# Hash-to-curve for BLS12-381 G1

This document describes the BLS12-381 G1 hash-to-curve operation as
implemented in `Lumoin.Veridical.Core` (and exercised through the
BBS+ stack in `Lumoin.Veridical.Bbs`). It is written for someone who
has read the code and wants the algebraic shape — and the test
strategy — made explicit.

## § 1 What is implemented

The reference implementation
`Bls12Curve381BigIntegerG1Reference.HashToCurve` is the
**RFC 9380 §8.8.1** suite

```
BLS12381G1_XMD:SHA-256_SSWU_RO_
```

with all three composable layers:

- **`hash_to_field_fp1`** — `expand_message_xmd` with SHA-256 to a
  uniform byte string, then OS2IP reduced modulo the BLS12-381 base
  prime `p` to produce two field elements `u₀, u₁`.

- **`map_to_curve`** — the Simplified Shallue–van de Woestijne–Ulas
  (SSWU) map onto an auxiliary 11-isogenous curve `E'`. Both `u₀`
  and `u₁` are mapped, producing two points `Q₀`, `Q₁` on `E'`.

- **`iso_map`** — the 11-isogeny from `E'` to the BLS12-381 G1
  curve `E: y² = x³ + 4`. The map is evaluated via Horner's scheme
  on the four published polynomials in RFC 9380 §E.2.

- **`clear_cofactor`** — multiplication by `h_eff = 0xd201000000010001`
  per RFC 9380 §8.8.1, projecting the result into the prime-order
  subgroup of G1.

The flow for each input message is `(msg, dst) → expand_message →
u₀, u₁ → map_to_curve(u_i) on E' → Q₀, Q₁ → Q₀ + Q₁ on E' →
iso_map → cofactor clearing → P`, where `P` is the final 48-byte
canonical ZCash-compressed encoding.

## § 2 What it guarantees

**Byte-faithful agreement with the RFC 9380 §J.9.1 published test
vectors** for the same suite. The five vectors (empty message,
`"abc"`, `"abcdef0123456789"`, a 133-byte `"q128_"` message, and a
517-byte `"a512_"` message) are committed under
`test/Lumoin.Veridical.Tests/Algebraic/Fixtures/Rfc9380J9_1Bls12Curve381G1Vectors.json`.
The regression test
`Bls12Curve381G1HashToCurveByteFaithfulTests` produces the canonical
compressed encoding from each input and asserts byte equality
against the expected value derived from the published `(P.x, P.y)`.

**Algebraic invariants** are also exercised independently: every
output is on the curve `y² = x³ + 4 mod p` and inside the
prime-order subgroup of G1. These properties are necessary but not
sufficient for spec conformance.

## § 3 Why both layers of test matter

The BBS+ batch surfaced a concrete case where the two layers diverge.
An earlier implementation used a **try-and-increment** mapping —
hash the message to a field element, lift to a curve point if
possible, otherwise increment and retry. The output is always
on-curve and (after cofactor clearing) inside the prime-order
subgroup. Algebraic-invariant tests on random inputs accept it as
correct.

But try-and-increment is not the algorithm RFC 9380 §8.8.1 mandates.
The published vectors expect SSWU with the 11-isogeny and `h_eff`
cofactor multiplication. The byte composition of the output point
depends on the algorithm, not just on `(msg, dst)`. Two correct
implementations of *different* hash-to-curve algorithms produce
different points for the same input — and only one passes the RFC
9380 §J.9.1 byte equality check.

Higher-layer protocols that build on hash-to-curve inherit this
sensitivity. BBS+ generator derivation, for instance, feeds the
output of hash-to-curve into a chain of operations that produces
the signature's `B` commitment. A divergence at the hash-to-curve
layer manifests as a divergence in every signature byte downstream,
and a wire-incompatible implementation that nonetheless looks correct
to its own internal test surface.

The lesson the batch made explicit: when adding a new RFC-bound
primitive, both algebraic-invariant tests *and* byte-faithful tests
against published vectors should land in the same commit. The
algebraic tests are cheap and run on random inputs, catching a wide
class of arithmetic bugs. The byte-faithful tests are the gate
against spec divergence — the only one that catches "right answer,
wrong algorithm" failures.

## § 4 References

- **RFC 9380** §3 (suite construction), §6.6.3 (SSWU mapping),
  §8.8.1 (the `BLS12381G1_XMD:SHA-256_SSWU_RO_` suite definition),
  §E.2 (the 11-isogeny coefficients), §J.9.1 (the five published
  test vectors).
- **ZCash protocol specification** §5.4.9.1 — the canonical
  compressed encoding flag convention (compression bit, infinity
  bit, y-parity bit).
- **paulmillr/noble-curves** (`bls12-381.ts`) — independent
  reference implementation consulted during development for
  cross-checking the SSWU coefficients and isogeny polynomials.
