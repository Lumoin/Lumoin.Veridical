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

- Initial public packages: `Lumoin.Veridical.Core`, `Lumoin.Veridical.Hashing`,
  `Lumoin.Veridical.Backends.Managed`, `Lumoin.Veridical.Bbs`,
  `Lumoin.Veridical.Secdsa`, `Lumoin.Veridical.Analysis`, and the
  `Lumoin.Veridical.Cli` command-line / MCP tool.
- `Lumoin.Veridical.Longfellow`: a consumable, serialization-free facade over the
  dual-field Longfellow zero-knowledge-over-ECDSA mdoc prover and verifier.
- `WellKnownLigeroParameters` and `LigeroSoundnessRegime`: pinned Ligero
  polynomial-commitment soundness parameters with a regime-based opened-column
  derivation (defaulting to the provable Johnson bound).
- A constant-time NIST P-256 scalar-field Montgomery backend, used by SECDSA and
  ECDSA signing in place of the variable-time `BigInteger` path.
- `SECURITY.md`: the consolidated security and constant-time posture.

### Changed

- The masked-Spartan non-hiding BaseFold entry points are renamed
  `ProveBaseFoldSound` / `VerifyBaseFoldSound`, and the zero-knowledge entry
  points (`ProveZkBaseFold` / `VerifyZkBaseFold`) require a hiding commitment
  provider.
