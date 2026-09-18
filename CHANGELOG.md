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

- `MerkleCommitmentParameters` binds a Merkle tree's two-to-one compression to the node width it produces, and every hash-tree commitment scheme — BaseFold, `ZkBaseFold`, Ligero, WHIR, and the Merkle set commitment — now takes its digest width from that pairing instead of assuming it coincides with the scalar field, up to the 64-byte Merkle-surface cap. Ligero, BaseFold, `ZkBaseFold`, and WHIR (plain and hiding) commit, open, and verify correctly at digest widths of 16, 32, 48, and 64 bytes; the Merkle set commitment carries the same widest-admissible-digest bound and is proven at the wired 32-byte width and at the 64-byte cap.
- A commitment provider can now state its own sizing. `PolynomialCommitmentProvider.CommitmentSizeBytes` and `EvaluationProofSizeBytes` (backed by the new `PolynomialCommitmentSizeDelegate` and `PolynomialOpeningSizeDelegate`) return a commitment's and an evaluation opening's serialized length for a given variable count, computed purely from the parameters the provider was built with. A caller composing a fixed-format proof reads every section length from the provider instead of reassembling scheme-specific arithmetic — a query repetition count, an inverse rate, a digest size — that cannot describe every scheme; WHIR's query count varies per round and could not be expressed that way at all. BaseFold, `ZkBaseFold`, Ligero, Hyrax, and WHIR (plain and hiding) all implement it.
- Spartan2 proofs now compose with any polynomial-commitment scheme, through `SpartanProverExtensions.ProveCommitted`/`SpartanVerifierExtensions.VerifyCommitted` and the new `CommitmentSpartanProof`, so WHIR gains a Spartan2 path for the first time; it proves over a padded relaxed R1CS instance, since WHIR cannot open a polynomial in fewer variables than its folding parameter.
- `WellKnownWhirParameters.ProvenJohnsonSecurityLevelBits` and `ProvenJohnsonSecurityRegime` name a 100-bit proven-Johnson soundness profile for WHIR (the Johnson list-decoding regime already priced from the proven BCHKS25 mutual correlated-agreement bound), expressed the same way as the wired default regime. It is opt-in and not interchangeable with the default regime on one artifact, and admits both a plain and a hiding evaluation schedule at the same pinned shape.

### Changed

- The target framework moves from `net10.0` to `net11.0` across every published package.
- Dependency refresh: `Lumoin.Base` 0.0.14, `Microsoft.Extensions.Hosting` 10.0.12, `System.CommandLine` 2.0.12, and `ModelContextProtocol` 2.2.0.
- `PoseidonParameterGenerator.Generate` no longer takes `fieldSizeBits` or `modulus`; the scalar-field order comes from the curve, and a curve without a wired order is rejected.
- `PoseidonParameterGenerator.Generate` and `WellKnownPoseidonParameters.CreateCircomlibCompatible` require a `BaseMemoryPool`; callers supply the pool for temporary generation buffers.
- The BaseFold and zero-knowledge BaseFold provider factories require a `BaseMemoryPool`; callers keep the pool alive until the provider is disposed.
- `MonomialBasis` factories require a `BaseMemoryPool`, and `MonomialBasis` implements `IDisposable`; callers dispose each basis after its borrowed exponent views and masks are finished.
- `ZkInterfaceMessageDecoderDelegate` receives a `BaseMemoryPool`; custom decoders accept the reader caller's pool and use it for temporary buffers.
- The raw-instance `ProveCommitted` overload refuses a hiding commitment provider up front with `InvalidOperationException`. The overload supplies a zero error-opening blind, and a hiding provider's opening needs the blind sampled when the error vector was committed, which the placeholder cannot match; the `ProveBaseFold` overload it replaces had no such check, so a hiding provider passed there failed inside its opening rather than producing a proof. A hiding scheme proves through the relaxed-instance entry point with a blind the caller samples.
- SIMD dispatch and kernel work: the AVX-512 scalar-field dispatch for BLS12-381 and BN254 batch operations, and for the P-256 base-field batch multiplier, now additionally requires the runtime to report 512-bit vector acceleration before selecting the AVX-512 kernels, falling back to AVX2 otherwise. The AVX2 batch kernels for BLS12-381, BN254, and the P-256 base field transpose quartets of limbs with vector zip/concat primitives instead of per-limb scalar reads and per-lane inserts; their arithmetic and outputs are unchanged.

### Removed

- The per-scheme Spartan2 proof types `BaseFoldSpartanProof` and `LigeroSpartanProof`, and their entry points `ProveBaseFold`, `ProveLigero`, `VerifyBaseFold` and `VerifyLigero`, are gone, replaced by `CommitmentSpartanProof` with `ProveCommitted` and `VerifyCommitted`: one proof type and one pair of entry points for any commitment scheme. The proof keeps the same four sections in the same order — witness commitment, sumcheck, error opening, witness opening — with no length prefixes, and takes each section's length from the verifying provider's sizing instead of deriving it from scheme-specific parameters.

### Security

- WHIR's verify funnels refuse a wire commitment whose width does not match the scheme's configured digest size, before any parsing runs, rather than reaching a raw fault from inside the authentication walk on malformed input; the shared coset-leaf authentication likewise refuses a root wider than the Merkle surface can recompute.
- BaseFold, `ZkBaseFold`, Ligero, and the Merkle set commitment refuse a configured digest width wider than the 64-byte Merkle surface at construction (BaseFold, `ZkBaseFold` and Ligero at every factory entry point), so a misconfigured scheme fails immediately instead of inside a later verification.
- Wire bytes for Ligero, BaseFold, and WHIR commitments and openings, at the wired 32-byte digest paired with the 32-byte scalar, are pinned unchanged.

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
