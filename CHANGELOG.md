# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!-- Available types of changes:
### Added
### Changed
### Fixed
### Deprecated
### Removed
### Security
-->

## [Unreleased]

### Added

- `veridical longfellow-jwt-prove` and `longfellow-jwt-verify`, with the MCP tools `LongfellowJwtProve` and `LongfellowJwtVerify`: Longfellow JWT proofs from the command line, with the crypto suite and prover randomness composed from the platform.
- `veridical bbs-keygen`, `bbs-sign`, `bbs-verify`, `bbs-proof-generate` and `bbs-proof-verify`, with the MCP tools `BbsKeyGenerate`, `BbsSign`, `BbsVerify`, `BbsProofGenerate` and `BbsProofVerify`: BBS key generation, signatures and selective-disclosure proofs; secret keys are read from and written to files only.
- `veridical secdsa-*` commands (split sign, public key, verify, nonce-point recovery, full verify, DL-equality prove and verify, blinding and control relations, ECDH-MAC derive, sign, verify and split sign) with matching `Secdsa...` MCP tools; secret scalars are read from files only.
- `veridical analysis-basefold-leakage`, `analysis-welch-t`, `analysis-ks` and `analysis-chi-squared`, with the MCP tools `AnalysisBaseFoldLeakage`, `AnalysisWelchT`, `AnalysisKolmogorovSmirnov` and `AnalysisChiSquared`: the BaseFold leakage experiments and statistical tests as reports.
- `LongfellowProverRandomness`: the prover's plain random bytes for one proof, single use, with a draw count. The prover does the field mapping and the below-prime rejection itself.
- `LongfellowRandomnessChecks`: `IsBelowP256BaseFieldPrime`, `IsNotAllZero` and `ProducesDistinctNonZeroDraws`, for suppliers to test their own randomness.
- `SecdsaAlgorithm.PrepareSplitSign` and `SecdsaAlgorithm.CompleteSplitSign`: split sign as two pure phases around an external key holder. Prepare returns the blinded representative `e' = P^-1 * e`; complete masks the key holder's `(r, s0)` and releases `s` only after the finished signature verifies under the composite public key, so a faulty or substituted key holder cannot make the caller emit a bad signature. The two-party key-share split is the same two phases applied once per party.
- `EcdhMacAlgorithm.PrepareKeyAgreement`, `ApplyKeyShare`, `DeriveMacKeyFromSharedSecret`, `CompleteSign`, `CompleteVerify` and `VerifyMac`: ECDH-MAC and Split-ECDH-MAC as phases around a key holder that returns either the shared secret `Z_AB` or the derived key.
- `EcdhMacKeyDerivationDelegate`: the key derivation that turns `Z_AB` and `SharedInfo` into the MAC key, chosen by the caller (HKDF-SHA256 for the paper's Algorithms 16 and 17, an X9.63 derivation for an HSM that applies `CKD_SHA256_KDF`).
- `veridical secdsa-split-sign-prepare`, `secdsa-split-sign-complete`, `secdsa-ecdh-mac-prepare`, `secdsa-ecdh-mac-apply-key-share`, `secdsa-ecdh-mac-complete-sign`, `secdsa-ecdh-mac-complete-verify` and `secdsa-ecdh-mac-verify-mac`, with the MCP tools `SecdsaSplitSignPrepare`, `SecdsaSplitSignComplete`, `SecdsaEcdhMacPrepare`, `SecdsaEcdhMacApplyKeyShare`, `SecdsaEcdhMacCompleteSign`, `SecdsaEcdhMacCompleteVerify` and `SecdsaEcdhMacVerifyMac`: the phases for a key held outside the process; secret intermediates move through files only.
- `SecdsaSignatureResultConformity.Prove` and `Check`, with `SignatureResultRecord` and `SignatureResultConformity`: the zero-knowledge signature-result conformity check of Annex F, Algorithm 41. The prover forms `G'' = s^-1 * G` and `Q_U'' = s^-1 * Q_U` and proves them with the blinding relation; the verifier checks the proof and `R = e*G'' + r*Q_U''`. The result distinguishes no alarm from the three alarms as a value, never an exception, and the record is one tagged, pooled value.
- `EciesAlgorithm` (`Encrypt`, `AgreeSharedSecret`, `PrepareDecryption`, `DeriveKeyMaterial`, `TryCompleteDecryption` from the shared secret or the derived key material, and the all-software `TryDecrypt`), with `EciesParameterSet` (key and IV split, tag length and the role of `A`, with `X963Sha256Aes256Gcm` as the typical set), `X963KeyDerivation` over the supplied SHA-256 delegate, the delegates `EciesKeyDerivationDelegate`, `AeadEncryptDelegate`, `AeadDecryptDelegate` and `SecdsaEntropySource`, and the tagged values `EciesCiphertext`, `EciesPlaintext`, `SharedSecret`, `DerivedKeyMaterial` and `AdditionalData`: ECIES of Annex A.4 (Algorithms 18 and 19), with decryption as prepare and complete phases for a key held in an HSM. The library implements no cipher; a tag failure returns no plaintext and clears the buffer.
- `TransferableProofAlgorithm` (`Issue`, `TryPrepareResponse`, `TryCompleteResponse`, `TryFinishResponse`, `TryRespond` and `Verify`) with `TransferableProofVerdict`, and the tagged values `TransferableChallenge`, `TransferableResponse`, `ProofStatement`, `ProofSeed`, `ProofDigest`, `ProofDigestKind`, `P256PointVector` and `P256ScalarVector`: the signed, transferable proof of a discrete-logarithm statement of Annex A.5 (Algorithms 22 to 24), with seeded ephemeral keys, the ECIES-encrypted seed, the response as phases around the key holder (steps 5 to 7) and the mandatory repeated decryption of step 11. The signature schemes and the seed derivation enter as `StructureSignDelegate`, `StructureVerifyDelegate` and `SeedKeyDerivationDelegate`.
- `SecdsaLayoutProfile`, `SecdsaLayoutProfileId`, `LayoutWriter` and the layout delegate types: every byte layout of the transferable proof (the hashed and signed structures, the derivation input, the vectors, the seed payload and the transport containers) is chosen by a swappable profile of encoder and decoder delegates, and values signed under a profile record its identifier in their tag; a challenge and a response under different profiles are rejected. `SecdsaProvisionalLayout` is the one profile the library ships: length-prefixed, big-endian, injective, and not an interoperability format.
- `veridical secdsa-result-prove` and `secdsa-result-check`, with the MCP tools `SecdsaResultProve` and `SecdsaResultCheck`: the signature-result conformity check from the command line; a compromise alarm exits non-zero.
- `veridical secdsa-ecies-encrypt`, `secdsa-ecies-decrypt`, `secdsa-ecies-prepare-decryption`, `secdsa-ecies-agree` and `secdsa-ecies-complete-decryption`, with the MCP tools `SecdsaEciesEncrypt`, `SecdsaEciesDecrypt`, `SecdsaEciesPrepareDecryption`, `SecdsaEciesAgree` and `SecdsaEciesCompleteDecryption`: ECIES with AES-256-GCM from the platform; plaintexts and shared secrets move through files only, and a failed tag writes nothing.
- `veridical secdsa-proof-challenge`, `secdsa-proof-respond-prepare`, `secdsa-proof-respond-complete` and `secdsa-proof-verify`, with the MCP tools `SecdsaProofChallenge`, `SecdsaProofRespondPrepare`, `SecdsaProofRespondComplete` and `SecdsaProofVerify`: the transferable proof from the command line with ECDSA over P-256 for both signatures and the provisional layout; keys and additional secret data move through files only, and a rejected proof exits non-zero.
- `PinKey`, `PrivateScalar`, `MessageHash`, `BlindedHash` and `RawSignature`: tagged, pooled protocol values of split ECDSA that clear on dispose and validate their invariants in `FromCanonical` (a scalar in `[1, n-1]`, a canonical blinded hash, both components of the key holder's raw signature in range). `BlindedHash` and `RawSignature` carry the pairing warnings of the secrets they would reveal together with the message hash.
- `MacKey`, `MacTag`, `MacSalt` and `SharedInfo`: tagged, pooled protocol values of ECDH-MAC; the key and the tag clear on dispose, and the tag and the key validate their lengths in `FromCanonical`.

### Changed

- `EcdhMacAlgorithm.DeriveMacKey`, `Sign`, `Verify`, `SplitSign`, `PrepareKeyAgreement`, `ApplyKeyShare`, `DeriveMacKeyFromSharedSecret`, `CompleteSign`, `CompleteVerify` and `VerifyMac` take and return the tagged values: keys and shares as `PrivateScalar`, peer and result points as `G1Point`, the key holder's secret as `SharedSecret`, salt as `MacSalt`, shared info as `SharedInfo`, the tag as `MacTag` and the derived key as `MacKey`, each result rented from a pool passed last. The message stays a span. A wrong-length tag is rejected when the `MacTag` is formed.
- `EciesAlgorithm.AgreeSharedSecret`, `EciesAlgorithm.TryDecrypt` and `TransferableProofAlgorithm.TryRespond` take the private key as a `PrivateScalar` instead of a span; the range check happens once, when the `PrivateScalar` is formed.
- `DlEqualityNizk.Prove` and `Verify` take and return the tagged values: the witness as `PrivateScalar`, the generator and public-key lists as `P256PointVector`, the context as `AdditionalData`, and the proof as `DlEqualityProof`; `SecdsaEvidence.ProveBlindingRelation`, `VerifyBlindingRelation`, `ProveControlRelation` and `VerifyControlRelation` take `G1Point` relation points, a `PrivateScalar` witness, an `AdditionalData` record context and a `DlEqualityProof`. The span-output overload of `DlEqualityNizk.Prove` is removed from the public surface.
- `SecdsaAlgorithm.PrepareSplitSign`, `CompleteSplitSign` and `SplitSign` take and return the tagged values: `PrepareSplitSign(PinKey, MessageHash, ...)` returns a `BlindedHash`, `CompleteSplitSign(PinKey, MessageHash, G1Point, RawSignature, ...)` returns a `SecdsaSignature`, and both `SplitSign` overloads (hardware key as `PrivateScalar`, or a `G1Point` public key with a raw-sign seam) return a `SecdsaSignature`; the span-output overload is removed and the pool is the last parameter. A zero or out-of-range raw signature is now rejected by `RawSignature.FromCanonical`.
- `TransferableProofAlgorithm.TryCompleteResponse` and `TryFinishResponse` take the `StructureVerifyDelegate` for the challenger's signature and verify it (Algorithm 23 step 4) before any decryption result is used, so no entry point signs a response or releases the additional secret data for an unsigned challenge; `TryRespond` passes the delegate through. `veridical secdsa-proof-respond-complete` and the `SecdsaProofRespondComplete` tool take the challenger's public key.
- `SecdsaAlgorithm.SplitSign` verifies the finished signature before returning it, as every split-sign entry point now does. The software overloads take a `G1AddDelegate` and derive the composite public key themselves; the raw-signer overload takes the composite public key, a `G1ScalarMultiplyDelegate` and a `G1AddDelegate`, runs through `PrepareSplitSign` and `CompleteSplitSign`, and clears `r` and `s` when the key holder's answer is rejected.
- `EcdhMacAlgorithm` takes an `EcdhMacKeyDerivationDelegate` where it took an `HkdfSha256Delegate`; `Sha256Hkdf.DeriveKey` converts to it directly. `Sign` and `SplitSign` run through the new phase members.
- `LongfellowMdoc.Prove` and `LongfellowJwt.Prove` take a `LongfellowProverRandomness` after the suite.
- `LongfellowEntropyDelegate` fills plain random bytes with no field constraint.

- `LongfellowMdoc.Prove`/`Verify` and `LongfellowJwt.Prove`/`Verify` require the crypto suite; the `suite` parameter is no longer optional and a `null` suite throws.
- `Lumoin.Veridical.Longfellow` targets the browser platform; no platform cryptography remains in the facade.
- `SecdsaEvidence.ProveBlindingRelation`/`VerifyBlindingRelation` take the standard base point `g` first (was `gPrime`), matching `ZKP[(G,G''),(Y',Y'')]`.
- `SecdsaEvidence.ProveControlRelation`/`VerifyControlRelation` take `h`, `w`, `hPrime`, `wPrime` (were `generator`, `noncePoint`, `blindedGenerator`, `blindedNoncePoint`), matching `ZKP[(H,H'),(W,W'),H(T_I)]` of Equation (7).

### Removed

- The entropy delegates on `LongfellowMdocCryptoSuite` (`HashRandom`, `SignatureRandom`) and `LongfellowJwtCryptoSuite` (`ProverRandom`), and the matching `Create` parameters.
- `LongfellowMdocCryptoSuite.Default` and `LongfellowJwtCryptoSuite.Default`; the library no longer selects a hash, block cipher or entropy source for the caller.

## [0.0.8] - 2026-11-11

### Changed

- Built with the .NET 11 SDK 11.0.100; dependency updates, including `Lumoin.Base` 0.0.15.
- The BLS12-381, BN254 and P-256 AVX-512 field kernels transpose limbs in vector registers.

### Security

- The native AOT tool packages are built on the .NET 11.0.0 runtime, which fixes CVE-2026-111497.

## [0.0.7] - 2026-09-21

### Added

- Configurable digest width, up to 64 bytes, for every hash-tree commitment (`MerkleCommitmentParameters`).
- Commitment providers report their commitment and opening sizes.
- Spartan2 over any polynomial commitment scheme, WHIR included (`CommitmentSpartanProof`, `ProveCommitted`, `VerifyCommitted`).
- A 100-bit proven-Johnson soundness profile for WHIR (IACR ePrint 2025/2055).
- `R1csIntakeLimitExceededException` and `WellKnownR1csIntakeLimits.Unbounded`, for the R1CS pipe readers' intake ceiling.

### Changed

- Targets `net11.0`; dependency updates, including `Lumoin.Base` 0.0.14.
- The Poseidon, BaseFold, `MonomialBasis` and ZkInterface decoder APIs take the caller's `BaseMemoryPool`; `MonomialBasis` is disposable.
- `PoseidonParameterGenerator.Generate` takes the scalar field from the curve.
- The raw-instance `ProveCommitted` rejects hiding commitment providers.
- AVX-512 kernels are selected only where 512-bit vectors are hardware-accelerated.
- `R1csPipeReaderDelegate`, `R1csWitnessPipeReaderDelegate`, and every Circom and ZkInterface reader implementing them, take a required `maximumIntakeBytes` ceiling.

### Removed

- `BaseFoldSpartanProof`, `LigeroSpartanProof` and their prove and verify methods, replaced by `CommitmentSpartanProof`.

### Security

- WHIR rejects a commitment of the wrong width before parsing it.
- Hash-tree commitments reject digest widths above 64 bytes at construction.

## [0.0.6] - 2026-08-12

### Added

- The WHIR polynomial commitment scheme (Arnon–Chiesa–Fenzi–Yogev, IACR ePrint
  2024/1586): a parameter schedule with a computed round-by-round soundness
  ledger (unique decoding as the proven wired default; the Johnson
  list-decoding regime priced from the proven BCHKS25 mutual
  correlated-agreement bound), a coset NTT encoder, the IOPP prover and
  verifier, constraint batching, a wire codec, and provider integration
  (`CommitmentScheme.Whir`).
- The hiding WHIR variant (Chiesa–Fenzi–Weissenberg, IACR ePrint 2026/391):
  zero-knowledge encoding, masked sumcheck, code-switch rounds with private
  out-of-domain replies, the masked base case, a hiding commitment provider
  (`WhirPolynomialCommitmentScheme.CreateZeroKnowledge`, reporting
  `IsHiding`), a zero-knowledge soundness ledger with a separately priced
  honest-verifier zero-knowledge distance, a wire codec, and a witness-free
  transcript simulator in `Lumoin.Veridical.Analysis`.
- A JWS compact-serialization extractor and a JWT statement facade in
  `Lumoin.Veridical.Longfellow`, with a base64url delegate seam, alongside the
  existing mdoc facade.
- `memberOf` lookup claims on the predicate CLI and MCP surfaces, backed by
  the LogUp lookup argument over Ligero (statement format `/3`, a derived
  union-bounded query budget, and a wire codec).
- AVX-512 VPCLMULQDQ carryless-multiplication kernels for the GF(2^128)
  backend, agreement-tested against the serial reference.

### Changed

- The supply-chain predicate request and artifact formats bump to `/3`: a claim
  carries a required `kind` discriminator (`range` or `memberOf`), `direction`
  and `bound` become optional and apply to `range` claims only, and requests and
  artifacts in the earlier `/2` format are rejected.
- `Lumoin.Veridical.Longfellow` and `Lumoin.Veridical.Json` are packed and
  published alongside the other libraries.
- Dependency refresh: `Lumoin.Base` 0.0.9, `ModelContextProtocol` 2.1.0,
  `Blake3` 3.0.2, `CsCheck` 4.8.0, `System.CommandLine` 2.0.11,
  `Microsoft.Extensions.Hosting` 10.0.11, `System.Formats.Cbor` 10.0.11, and
  `Microsoft.Extensions.TimeProvider.Testing` 10.9.0; the .NET SDK pin moves to
  10.0.400; the MSTest and Microsoft.Testing.Platform test infrastructure moves
  to `MSTest.Sdk` 4.3.3, with the SDK managing the adapter, framework,
  extension, and code-coverage versions; GitHub Actions pins moved to
  `actions/checkout` v7.0.1, `actions/setup-dotnet` v6.0.0, and
  `step-security/harden-runner` v2.20.1.

### Security

- All Bulletproofs and Hyrax verify funnels screen every prover-supplied group
  element for on-curve and prime-order-subgroup membership before any group
  arithmetic (material on BLS12-381, where the subgroup test is the
  endomorphism check of Scott, IACR ePrint 2021/1130).
- A Ligero opening's proximity response, evaluation response, and every opened
  column are canonicality-checked at the verifier's reader funnel, so an
  accepted Ligero opening has exactly one byte representation.
- The LogUp proof codecs enforce named dimension caps and reject joint shapes
  whose buffer arithmetic would overflow; the predicate CLI surfaces reject
  smuggled, duplicate-name, and oversized claim sets.

## [0.0.5] - 2026-07-29

### Added

- A zero-knowledge circuit compiler and statement family for Longfellow-style
  proofs: the quad-circuit kernel, logic and SHA-256 gadgets, SD-JWT and mdoc
  revocation statements, and an ML-DSA (FIPS 204) statement over an
  extension-field Reed–Solomon/Ligero profile, byte-conformant to the pinned
  upstream reference where an upstream registry exists.
- `Lumoin.Veridical.Longfellow`: a consumable, serialization-free facade over
  the dual-field Longfellow zero-knowledge-over-ECDSA mdoc prover and
  verifier.
- `WellKnownLigeroParameters` and `LigeroSoundnessRegime`: pinned Ligero
  polynomial-commitment soundness parameters with a regime-based opened-column
  derivation (defaulting to the provable Johnson bound).
- Constant-time point multiplication for BLS12-381 and BN254 (a shared
  ladder over constant-time Montgomery base fields), joining the existing
  constant-time NIST P-256 scalar-field backend used by SECDSA and ECDSA
  signing.
- The `veridical prove`/`verify` predicate surface (CLI and MCP) over
  supply-chain predicate bundles, with a JSON envelope library and native-AOT
  per-platform tool packages.
- The LogUp lookup argument and the security-bits ledger
  (`WellKnownSecurityLevels`) with per-path soundness accounting.
- `SECURITY.md`: the consolidated security and constant-time posture.

### Changed

- The masked-Spartan non-hiding BaseFold entry points are renamed
  `ProveBaseFoldSound` / `VerifyBaseFoldSound`, and the zero-knowledge entry
  points (`ProveZkBaseFold` / `VerifyZkBaseFold`) require a hiding commitment
  provider.

## [0.0.4] and earlier

- Initial public packages: `Lumoin.Veridical.Core`, `Lumoin.Veridical.Hashing`,
  `Lumoin.Veridical.Backends.Managed`, `Lumoin.Veridical.Bbs`,
  `Lumoin.Veridical.Secdsa`, `Lumoin.Veridical.Analysis`, and the
  `Lumoin.Veridical.Cli` command-line / MCP tool.
