# Lumoin.Veridical.Bbs

BBS+ signatures (multi-message with selective-disclosure proofs) per
the IETF draft
[`draft-irtf-cfrg-bbs-signatures-10`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
over BLS12-381.

This project provides cryptographic primitives only: it builds on
`Lumoin.Veridical.Core` for the BLS12-381 field arithmetic, group
operations, hash-to-scalar / hash-to-curve, and the optimal-Ate
pairing. The wire format follows the IETF draft byte-for-byte; the
test project's Appendix A fixtures are the interoperability gate.

The currently shipping surface:

- `BbsCiphersuite.Bls12Curve381Sha256.Generate(...)` — KeyGen.
- `secretKey.Sign(publicKey, header, messages, ...)` — Sign.
- `publicKey.Verify(signature, header, messages, ...)` — Verify.

Sub-batches still pending:

- `BbsCiphersuite.Bls12Curve381Sha256.GenerateProof(...)` and
  `publicKey.VerifyProof(...)` for selective-disclosure proofs.
- The BLS12-381-SHAKE-256 ciphersuite.
- A full sweep of the IETF Appendix A test vectors.

For codebase documentation see [BBS-PLUS.md](BBS-PLUS.md).
