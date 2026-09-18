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

The shipping surface, for both the BLS12-381-SHA-256 and
BLS12-381-SHAKE-256 ciphersuites:

- `BbsCiphersuite.Bls12Curve381Sha256.Generate(...)` — KeyGen.
- `secretKey.Sign(publicKey, header, messages, ...)` — Sign.
- `publicKey.Verify(signature, header, messages, ...)` — Verify.
- `signature.GenerateProof(...)` and `publicKey.VerifyProof(...)` —
  selective-disclosure proofs.

For codebase documentation see [BBS-PLUS.md](BBS-PLUS.md).
