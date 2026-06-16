# Spartan

The Spartan2 protocol implementation in this directory proves and
verifies R1CS satisfiability with zero knowledge. The protocol is from
Setty 2020 ("Spartan: Efficient and general-purpose zkSNARKs without
trusted setup"). Spartan reduces R1CS satisfaction to multilinear-
polynomial claims via sumcheck, then opens those claims via a
polynomial commitment scheme. Veridical uses Hyrax (from
`Lumoin.Veridical.Core.Commitments`) as the commitment scheme; Hyrax
is transparent (no trusted setup) and discrete-log-based.

For the full protocol description, see SPARTAN2.md in this directory.
For the zero-knowledge transformations layered on the base prover —
round-message masking and fold-with-randomness — see
SPARTAN-ZK-DESIGN.md, and FOLDING.md for the as-built Nova-style folding
(`FoldChain`).

## On wire-format interoperability

Cryptographic proof systems have an interoperability story that
differs from cryptographic primitives like hash functions or
signature schemes. Hash functions (SHA-256, BLAKE3) and signature
schemes (Ed25519, BBS+) have IETF or other standards bodies that
pin down the byte representation; two conformant implementations
produce byte-identical outputs for the same inputs.

Proof systems do not. Spartan, Plonk, Groth16, Halo2 — none has a
published wire-format standard. Each implementation chooses its own
byte layout for the proof. The protocols agree on the mathematics;
the bytes differ.

Veridical's Spartan2 proof byte layout is described in SPARTAN2.md §5.
A proof produced by Veridical is verified by Veridical. Proofs from
other Spartan2 implementations are not byte-compatible with
Veridical's verifier and vice versa. The mathematical content is
the same; the bytes differ.

This is normal for current zk-SNARK tooling and is not specific to
Veridical. Wire-format standardization in zk-SNARKs may come as the
field matures; until then, each implementation is its own ecosystem
at the proof-byte level.

## Future directions

`MaskedSpartanProver` (post-v1) wraps the standard prover with a
masking-polynomial construction (Setty 2020 §4) to provide
statistical zero-knowledge against an unbounded verifier. The
construction is additive; the standard prover is preserved
unchanged.
