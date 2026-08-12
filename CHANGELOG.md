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
