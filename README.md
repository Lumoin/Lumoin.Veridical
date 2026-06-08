<img style="display: block; margin-inline-start: auto; margin-inline-end: auto;" src="resources/lumoin-veridical-github-logo.svg" width="800" height="161" alt="Lumoin Veridical wordmark: a circular emblem in gradient indigo hues followed by the project name in matching lettering.">

# Lumoin.Veridical

**A .NET stack for advanced cryptography: zero-knowledge proof systems, polynomial commitments, folding schemes, and selective-disclosure signatures.**

![Main build workflow](https://github.com/Lumoin/Lumoin.Veridical/actions/workflows/main.yml/badge.svg)

---

## What is Veridical?

Veridical is a .NET library for cryptography beyond signatures and hashes: zero-knowledge proofs over rank-1 constraint systems, polynomial commitment schemes, Nova-style folding, and BBS selective-disclosure signatures. The library is built so that high-level credential and identity systems can adopt these primitives without needing to bind themselves to any particular curve, proof system, or hardware backend.

The core value proposition is verifiable computation and privacy-preserving disclosure. A holder can prove statements about credentials, computations, or data without revealing the underlying material; a verifier can check those proofs cheaply; and an issuer can produce credentials that support post-issuance, unlinkable presentations.

Veridical is designed to be a peer of credential and identity stacks rather than a dependency of any one of them. Cryptographic material is never exposed as naked bytes; field elements, group elements, and polynomials each have semantic types with `Tag` metadata and pool-backed memory.

## Libraries

| Library | Purpose | NuGet |
|---------|---------|:-----:|
| **Lumoin.Veridical.Core** | Field and group arithmetic (BLS12-381, BN254), multilinear polynomials, Fiat-Shamir transcripts, R1CS, the Spartan proof system with sumcheck, Hyrax and BaseFold polynomial commitments, Nova-style folding, Bulletproof range proofs (single, aggregated, batched), a native circomlib-compatible Poseidon, and Merkle set commitments | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Core.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Core/) |
| **Lumoin.Veridical.Bbs** | BBS multi-message signatures with unlinkable selective-disclosure proofs (IETF draft, BLS12-381-SHA-256 ciphersuite) | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Bbs.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Bbs/) |
| **Lumoin.Veridical.Backends.Managed** | Managed scalar-field backends: a BigInteger reference implementation and per-ISA SIMD backends (AVX2, AVX-512, NEON, WebAssembly PackedSimd) with runtime dispatch | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Backends.Managed.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Backends.Managed/) |
| **Lumoin.Veridical.Hashing** | BLAKE3 with per-ISA SIMD backends | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Hashing.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Hashing/) |
| **Lumoin.Veridical.Analysis** | Statistical analysis tools: Kolmogorov–Smirnov and chi-squared tests, leakage investigations for masked commitment designs | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Analysis.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Analysis/) |
| **Lumoin.Veridical.Cli** | Command-line and MCP tool: platform and backend info, BLAKE3 hashing, conformance self-tests; ships as native-AOT packages per platform with a framework-dependent fallback | [![NuGet](https://img.shields.io/nuget/v/Lumoin.Veridical.Cli.svg?style=flat)](https://www.nuget.org/packages/Lumoin.Veridical.Cli/) |

## Key capabilities

**BBS selective-disclosure signatures.** A managed implementation of the IETF BBS signature scheme (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256 ciphersuite): multi-message signing, verification, and unlinkable proofs that disclose a chosen subset of signed messages. The draft's Appendix A test vectors are the load-bearing interoperability gate.

**Zero-knowledge proofs over R1CS.** A Spartan-style prover and verifier for rank-1 constraint systems, built on the sumcheck protocol over multilinear extensions, with masked variants for zero knowledge and circuit-builder utilities for constructing constraint systems.

**Polynomial commitment schemes.** Hyrax (discrete-log based) and BaseFold (hash-based), including a zero-knowledge BaseFold variant with statistical masking validated by the leakage-analysis toolkit. Schemes sit behind a uniform `Commit`/`Open`/`Verify` delegate surface so protocols are parameterized over the commitment scheme rather than hard-coded against one.

**Nova-style folding.** Relaxed R1CS folding combines two instance–witness pairs into one via a Fiat-Shamir challenge, with fold chains for accumulating long-running computations into a single instance.

**Range proofs.** Bulletproof range proofs over BLS12-381 and BN254 across the full family: single-value, aggregated (many values in one logarithmic proof), batched verification (many proofs collapsed into one multi-exponentiation), and batched aggregated verification. The verifier paths ride a bucket-method (Pippenger) multi-exponentiation with a decoded-point cache.

**Algebraic hashing.** A native Poseidon permutation and hash, Grain-derived and byte-compatible with circomlib over BN254, for in-circuit-friendly hashing where BLAKE3 is expensive — the compression behind Merkle set-commitment shadow roots.

**Curves and hashing.** BLS12-381 (including the Ate pairing) and BN254 arithmetic; RFC 9380 hash-to-curve and hash-to-scalar; BLAKE3 hashing with per-ISA SIMD backends.

**Managed backend abstraction.** Field and group operations are exposed as delegates. A BigInteger reference backend provides the correctness oracle; per-ISA SIMD backends (AVX2, AVX-512, NEON, WebAssembly PackedSimd) accelerate scalar-field arithmetic with runtime ISA selection. Everything is managed code — agreement between backends is property-tested, and no native binaries are shipped.

**Memory-safe cryptographic material.** Field elements, scalars, group points, and polynomials are wrapped in pool-backed `SensitiveMemory` types tagged with their algebraic role. There are no naked byte arrays in public APIs.

## Architecture principles

Veridical follows the same data-oriented principles as the rest of the family: code is separate from immutable data, generic data structures are favored, and general-purpose functions are implemented as static extensions. Domain types contain raw algebraic material without encoding artifacts; encoding lives at serialization boundaries in dedicated `Lumoin.Veridical.Json` or `Lumoin.Veridical.Cbor` packages when those are introduced.

Curves, proof systems, and backends are wired through delegates rather than interfaces. The same prover code runs against the reference backend during testing and a SIMD backend in production without changes at the call site. Backend selection is the application developer's concern, not the library's.

Every allocation of cryptographic material goes through a pool so that the library is friendly to arena-style allocators if a Rust port is ever written. There are no static caches or hidden global state in the cryptographic core.

## Getting started

Install the packages relevant to your use case:

```bash
# Core primitives: algebra, transcripts, R1CS, Spartan, commitments, folding
dotnet add package Lumoin.Veridical.Core

# BBS selective-disclosure signatures
dotnet add package Lumoin.Veridical.Bbs

# Accelerated managed backends and hashing
dotnet add package Lumoin.Veridical.Backends.Managed
dotnet add package Lumoin.Veridical.Hashing
```

The command-line tool installs as a dotnet tool:

```bash
dotnet tool install --global Lumoin.Veridical.Cli
```

## Development

The codebase runs on Windows, Linux, and macOS. Backend acceleration is selected at runtime per instruction set; the managed reference backend always works.

Press **.** on the repository page to open the codebase in VS Code web editor for quick exploration.

### Banned-API enforcement

Two banlists at the repository root are wired into every project via `Directory.Build.props`:

- **`BannedSymbols.txt`** — applied universally, no opt-out. Bans wall-clock APIs (`DateTime.Now`, `DateTime.UtcNow`, `DateTimeOffset.Now`, `DateTimeOffset.UtcNow`) and the non-UTC file-time getters (`File.GetCreationTime`, `File.GetLastWriteTime`). Production and test code use `TimeProvider` consistently.
- **`BannedSymbols.Serialization.txt`** — applied by default, opt-out per project. Bans `System.Text.Json` and `System.Formats.Cbor`. A project that legitimately needs a serialization namespace (a future `Lumoin.Veridical.Json` or `Lumoin.Veridical.Cbor` package) opts out by setting `<EnableSerializationBan>false</EnableSerializationBan>` in its `<PropertyGroup>`. Opt-out is deliberate rather than incidental: a maintainer adding a JSON-using project has to silence the ban explicitly, which surfaces the design decision.

The wiring uses `Microsoft.CodeAnalysis.BannedApiAnalyzers`, which surfaces violations as `RS0030` build errors. New projects pick up both bans automatically by existing inside the repository; no per-csproj ceremony.

### Naming conventions

**Wire-format strings keep their exact bytes; identifiers reflect mechanics.** A wire-format string — a DST suffix, a ciphersuite identifier, an IETF domain separator, any spec-defined ASCII constant — keeps its exact byte content, because it is hashed into a wire protocol and changing it would break interoperability or test-vector reproduction. The byte content is locked by the spec, not by us. The *C# identifier* that names such a string, however, is ours, and it should describe what the string **is** (a domain separator, a ciphersuite tag, a DST suffix) rather than echoing the role-based name a spec gives it where that name differs from the mechanics. Lock the bytes in an XML comment so the next reader knows not to touch the value.

**`Mocked`, `Fake`, `Stub`, and `Dummy` are reserved for genuine test doubles** — constructs that return canned values *without computing*. A deterministic construction that merely happens to be used in tests is not a mock: it computes a precise result. For example, the IETF BBS draft's `mocked_calculate_random_scalars` is a role-based spec name, but the function expands a seed through `expand_message_xmd`, chunks the output, and reduces each chunk modulo the field order — a deterministic key-derivation, not a pretence. The corresponding type is therefore named `BbsDeterministicScalars`, with its XML doc retaining the pointer to the spec function so a reader coming from the draft can still find it. Conversely, a placeholder that fills bytes never read by the code under test (`BuildDummyCommitment`), an adversarial input that fails to satisfy (a "fake witness"), or a delegate wired only to prove a guard rejects before invoking it (`StubPairing`) genuinely are doubles and keep those names.

## Vulnerability disclosure

Please report suspected security vulnerabilities privately through [GitHub security advisories](https://github.com/Lumoin/Lumoin.Veridical/security/advisories), not through public issues.

## Contributing

Open issues for bugs, suggestions, or improvements, or create pull requests. Especially welcome:

- Tests using test vectors from established implementations for cross-checking.
- Expanded coverage of curves, proof systems, and commitment schemes.
- Improved threat and privacy modeling.

## Acknowledgements

Veridical's design is informed by published specifications and papers. The implementations here are independent; no code is copied or translated mechanically. The sources below were consulted during development:

- **IETF draft-irtf-cfrg-bbs-signatures** (Looker, Kalos, Whitehead, Lodder) — wire-format authority for the BBS signature scheme in `Lumoin.Veridical.Bbs`. The Appendix A test vectors are the load-bearing interoperability gate.
- **RFC 9380** (Faz-Hernandez, Scott, Sullivan, Wahby, Wood) — hash-to-curve and hash-to-scalar primitives, including the BLS12-381 G1 SSWU + 11-isogeny map used inside BBS's generator derivation.
- **Spartan** (Setty, 2020) — the sumcheck-based R1CS proof system.
- **Nova** (Kothapalli, Setty, Tzialla, 2021) — the relaxed R1CS folding scheme.
- **BaseFold** (Zeilberger, Chen, Fisch, 2023) — the field-agnostic hash-based polynomial commitment.
- **Hyrax** (Wahby, Tzialla, shelat, Thaler, Walfish, 2018) — the discrete-log polynomial commitment.
- **Bulletproofs** (Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell, 2018) — the range-proof construction.

Additional acknowledgements will be added as the library grows. Design decisions informed by these specifications are recorded in the `tempdocs/` directory (gitignored), which is the historical archive of architecture choices.

## License

See the LICENSE file for details.

---

> **Note:** This is an early version under active development. APIs may change between versions.
