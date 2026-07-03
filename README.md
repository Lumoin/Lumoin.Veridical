<img style="display: block; margin-inline-start: auto; margin-inline-end: auto;" src="resources/lumoin-veridical-github-logo.svg" width="800" height="161" alt="Lumoin Veridical wordmark: a circular emblem in gradient indigo hues followed by the project name in matching lettering.">

# Lumoin.Veridical

**A .NET stack for advanced cryptography: zero-knowledge proof systems, polynomial commitments, folding schemes, selective-disclosure signatures, and split-ECDSA sole-control signing.**

![Main build workflow](https://github.com/Lumoin/Lumoin.Veridical/actions/workflows/main.yml/badge.svg)

---

## What is Veridical?

Veridical is a .NET library for cryptography beyond signatures and hashes: zero-knowledge proofs over rank-1 constraint systems, polynomial commitment schemes, Nova-style folding, and BBS selective-disclosure signatures. It lets credential and identity systems adopt these primitives without binding themselves to any particular curve, proof system, or hardware backend.

It is designed as a peer of credential and identity stacks rather than a dependency of one. Cryptographic material is never exposed as naked bytes: field elements, group elements, and polynomials are semantic types carrying `Tag` metadata over pool-backed memory.

## Libraries

| Library | Purpose | NuGet |
|---------|---------|:-----:|
| **Lumoin.Veridical.Core** | Field and group arithmetic (BLS12-381, BN254, P-256), multilinear polynomials, Fiat-Shamir transcripts, R1CS, the Spartan proof system, Hyrax/BaseFold/Ligero polynomial commitments, P-256 ECDSA, Nova-style folding, Bulletproof range proofs, a circomlib-compatible Poseidon, and Merkle set commitments | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Core.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Core/) |
| **Lumoin.Veridical.Bbs** | BBS multi-message signatures with unlinkable selective-disclosure proofs (IETF draft, BLS12-381-SHA-256) | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Bbs.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Bbs/) |
| **Lumoin.Veridical.Secdsa** | Split-ECDSA (SECDSA) over NIST P-256 — the EUDI-wallet sole-control signing primitive (Verheul): split signing from a PIN-key and a hardware key without forming the composite key, a discrete-log-equality NIZK, and blind-signing and transaction-evidence proofs | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Secdsa.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Secdsa/) |
| **Lumoin.Veridical.Backends.Managed** | Managed scalar-field backends: a BigInteger reference plus per-ISA SIMD (AVX2, AVX-512, NEON, WebAssembly PackedSimd) with runtime dispatch | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Backends.Managed.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Backends.Managed/) |
| **Lumoin.Veridical.Hashing** | BLAKE3 with per-ISA SIMD backends | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Hashing.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Hashing/) |
| **Lumoin.Veridical.Analysis** | Statistical tools (Kolmogorov–Smirnov, chi-squared) for leakage investigations of masked commitment designs | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Analysis.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Analysis/) |
| **Lumoin.Veridical.Cli** | Command-line and MCP tool: platform/backend info, BLAKE3 hashing, conformance self-tests; ships as native-AOT packages per platform | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Cli.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Cli/) |

## Capabilities

- **BBS selective-disclosure signatures** — multi-message signing, verification, and unlinkable subset-disclosure proofs (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256); the draft's Appendix A test vectors are the interoperability gate.
- **Zero-knowledge proofs over R1CS** — a Spartan-style prover and verifier built on sumcheck over multilinear extensions, with masked variants for zero knowledge and circuit-builder utilities.
- **Polynomial commitments** — Hyrax (discrete-log), BaseFold (hash-based, with a zero-knowledge variant validated by the leakage toolkit), and Ligero (interleaved Reed–Solomon), all behind a uniform `Commit`/`Open`/`Verify` surface so Spartan drops in any of them unchanged.
- **Transparent Ligero argument** — field-generic and NTT-free over a correctness-first barycentric Reed–Solomon encoder, so it runs over fields without smooth-order roots of unity, including the P-256 scalar field. This is the substrate for Longfellow-style zero-knowledge over ECDSA-signed mdoc credentials.
- **P-256 as a first-class curve** — scalar and base fields, short-Weierstrass G1, and ECDSA sign/verify cross-checked against `System.Security.Cryptography.ECDsa`.
- **Split-ECDSA (SECDSA)** — Verheul's split-signing for HSM-based EUDI wallets: a standard ECDSA signature under the composite key `P·u` formed from a PIN-key and a hardware key without ever materialising `P·u`, with RFC 6979 nonces, a pluggable raw-sign seam that keeps the hardware key inside a TPM/HSM, a Schnorr/Chaum-Pedersen discrete-log-equality NIZK, and publicly verifiable transaction-transparency evidence. See [the paper](https://wellet.nl/SECDSA-EUDI-wallet-latest.pdf).
- **Nova-style folding** — relaxed R1CS folding of two instance–witness pairs into one, with fold chains for accumulating long-running computations.
- **Range proofs** — Bulletproofs over BLS12-381 and BN254: single-value, aggregated, batched verification, and batched aggregated, riding a Pippenger multi-exponentiation with a decoded-point cache.
- **Algebraic hashing** — a native Poseidon permutation, Grain-derived and byte-compatible with circomlib over BN254, behind Merkle set-commitment shadow roots.
- **Curves and hashing** — BLS12-381 (including the Ate pairing), BN254, and P-256; RFC 9380 hash-to-curve and hash-to-scalar; BLAKE3 with per-ISA SIMD.
- **Managed backends and memory safety** — a BigInteger reference oracle plus agreement-tested per-ISA SIMD backends (all managed code, no native binaries); cryptographic material lives in pool-backed `SensitiveMemory` tagged with its algebraic role, with no naked byte arrays in public APIs.

## Architecture

Curves, proof systems, and backends wire through delegates rather than interfaces: the same prover runs against the reference backend in tests and a SIMD backend in production with no change at the call site, and backend selection is the application's concern. Every allocation of cryptographic material goes through a pool, and there is no static cache or hidden global state in the cryptographic core.

## Getting started

Install the packages relevant to your use case:

```bash
# Core primitives: algebra, transcripts, R1CS, Spartan, commitments, folding
dotnet add package Lumoin.Veridical.Core

# BBS selective-disclosure signatures
dotnet add package Lumoin.Veridical.Bbs

# Split-ECDSA (SECDSA) sole-control signing
dotnet add package Lumoin.Veridical.Secdsa

# Accelerated managed backends and hashing
dotnet add package Lumoin.Veridical.Backends.Managed
dotnet add package Lumoin.Veridical.Hashing
```

The command-line tool installs as a dotnet tool:

```bash
dotnet tool install --global Lumoin.Veridical.Cli
```

## Development

The codebase runs on Windows, Linux, and macOS; backend acceleration is selected at runtime per instruction set, and the managed reference backend always works. Press **.** on the repository page to open the codebase in the VS Code web editor.

## Vulnerability disclosure

Please report suspected security vulnerabilities privately through [GitHub security advisories](https://github.com/Lumoin/Lumoin.Veridical/security/advisories), not through public issues.

## Contributing

Open issues or pull requests. Especially welcome: tests using vectors from established implementations, expanded curve/proof-system/commitment coverage, and improved threat and privacy modeling.

## Acknowledgements

Veridical's design is informed by published specifications and papers. The implementations here are independent; no code is copied or translated mechanically.

- **IETF draft-irtf-cfrg-bbs-signatures** — wire-format authority for the BBS signature scheme; the Appendix A test vectors are the interoperability gate.
- **RFC 9380** — hash-to-curve and hash-to-scalar primitives.
- **Spartan** (Setty, 2020) — the sumcheck-based R1CS proof system.
- **Nova** (Kothapalli, Setty, Tzialla, 2021) — the relaxed R1CS folding scheme.
- **BaseFold** (Zeilberger, Chen, Fisch, 2023) — the field-agnostic hash-based polynomial commitment.
- **Hyrax** (Wahby, Tzialla, shelat, Thaler, Walfish, 2018) — the discrete-log polynomial commitment.
- **Ligero** (Ames, Hazay, Ishai, Venkitasubramaniam, 2017/2022) — the interleaved-Reed–Solomon transparent argument.
- **Anonymous Credentials from ECDSA** (Frigo, shelat, 2024) — the Longfellow-style ZK-over-ECDSA construction the P-256 and Ligero work targets.
- **Bulletproofs** (Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell, 2018) — the range-proof construction.
- **[An HSM-based EUDI wallet using Split-ECDSA (SECDSA)](https://wellet.nl/SECDSA-EUDI-wallet-latest.pdf)** (Verheul, version 21 June 2026) — the split-ECDSA sole-control construction, its discrete-log-equality NIZK, and the transaction-transparency evidence proofs in `Lumoin.Veridical.Secdsa`.

## License

See the LICENSE file for details.

---

> **Note:** This is an early version under active development. APIs may change between versions.
