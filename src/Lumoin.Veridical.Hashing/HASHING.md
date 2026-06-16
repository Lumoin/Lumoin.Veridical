# Hashing

This document describes the managed hash implementations shipped in
`Lumoin.Veridical.Hashing`. It is written for someone who has read the
code and wants the construction made explicit; the BLAKE3 specification
document by Aumasson, Neves, O'Connor, and Wilcox-O'Hearn (January 2020)
and the reference Rust implementation distributed alongside it are the
construction authority.

## § 1 What this project provides

`Lumoin.Veridical.Hashing` is the home for managed hash implementations
used elsewhere in the library. The current inhabitant is BLAKE3 in all
three modes (regular hash, keyed hash, and key derivation). Additional
hash functions land here as use cases arise; the project is scoped to
hash primitives only.

The project sits beneath `Lumoin.Veridical.Core` and depends on the
`SensitiveMemoryPool` allocator from that layer. Higher-level libraries
in the library — Spartan, BBS+, future statistical-analysis work — call
into a hash implementation through the Fiat-Shamir transcript's
`FiatShamirHashDelegate` and `FiatShamirSqueezeDelegate`, which any
backend can satisfy. BLAKE3 is the wire-format choice for the
zero-knowledge proof stack; the managed implementation here removes the
runtime dependency on a native Rust binary.

## § 2 BLAKE3 implementation overview

BLAKE3 is a Merkle-tree-structured hash function. Input is divided into
1024-byte **chunks**; each chunk is folded through a sequence of
compressions of 64-byte **blocks**. The chunk-tail compression produces
an 8-word **chaining value** that represents the chunk. Chunks compose
into a balanced binary tree by parent-hashing: every two completed
sub-trees' chaining values combine through a single compression under
the PARENT flag, producing the parent's chaining value. The tree's
final root produces the output.

Three modes share the same construction with different domain-separator
flags:

- **hash** seeds the leaf chunks with the BLAKE3 IV.
- **keyed_hash** seeds the leaf chunks with the caller-supplied 32-byte
  key. The KEYED_HASH flag is set on every compression so the keyed
  output cannot collide with the regular hash output for the same
  input.
- **derive_key** first hashes the application-supplied context string
  under the DERIVE_KEY_CONTEXT flag, producing a 32-byte context key.
  The supplied key material is then hashed under the
  DERIVE_KEY_MATERIAL flag, seeded with that context key.

Every compression takes an 8-word input chaining value, a 16-word
message block, a 64-bit counter, a block length, and a flag word; it
returns 16 words. The first 8 of those are the chaining value used by
the next compression; the full 16 feed the root XOF stream when the
ROOT flag is set.

## § 3 Backend layering

The compression function is the inner loop, and the chunk-parallel
compression path is the throughput multiplier on long inputs. A
backend bundles two delegates: `Blake3CompressionDelegate` for the
per-block single-compression work (parent nodes, root XOF expansion,
the chunk's tail block) and `Blake3ManyChunksDelegate` for the
chunk-parallel SIMD path. The portable backend's many-chunks delegate
loops one chunk at a time; the accelerated backends' many-chunks
delegates compress their natural SIMD batch in parallel.

The portable scalar backend is pure managed C# — no `unsafe`, no
platform intrinsics, no P/Invoke — and runs unchanged on every host
the .NET runtime supports, including AOT and WebAssembly. It is the
correctness reference against which the accelerated backends are
agreement-tested across both the canonical test vector set and a
CsCheck-driven random-input sweep.

The accelerated backends each lay one chunk's state per SIMD lane:

- **AVX2** (`Blake3Avx2Backend`, x86\_64 with AVX2): processes eight
  chunks per batch using `Vector256<uint>`. Byte-shuffle intrinsics
  (`Avx2.Shuffle`) implement the 16-bit and 8-bit rotations within
  each 32-bit lane; the 12-bit and 7-bit rotations use the shift-or
  composition that AVX2 has no native rotate for.
- **AVX-512F** (`Blake3Avx512Backend`, x86\_64 with AVX-512F):
  processes sixteen chunks per batch using `Vector512<uint>`. All
  rotations use the shift-or composition; the JIT lowers them to the
  native `VPROR`/`VPROL` instructions when AVX-512F is active.
- **AArch64 NEON** (`Blake3NeonBackend`, ARM64 with Advanced SIMD):
  processes four chunks per batch using `Vector128<uint>`. All
  rotations use the shift-or composition (NEON has no single
  32-bit rotate instruction).

`Blake3BackendSelection.SelectBest` performs the runtime CPU
detection once per process — AVX-512F if present, then AVX2, then
NEON, falling through to the portable scalar baseline. The result is
cached so repeated `Blake3Hasher.CreateAutoSelected` calls do not
re-detect. Callers that want to pin a specific backend wire it
explicitly via `Blake3Hasher.Create`, passing a
`Blake3Backend` bundle constructed by the backend's `GetBackend()`
factory.

The `Blake3Hasher.Update` path enters the chunk-parallel branch when
the chunk-state buffer is empty and the remaining input contains at
least one batch plus one trailing chunk — the trailing chunk stays in
the chunk-state buffer so finalisation finds it where the spec
expects.

## § 4 Wire format and outputs

The default digest length is 32 bytes. `Blake3Hasher.Finalize` requires
a 32-byte destination and produces the standard fixed-output digest.
`Blake3Hasher.FinalizeXof` accepts a destination of any length and
produces the corresponding prefix of the extendable-output stream; by
the BLAKE3 specification, the first 32 bytes of an XOF expansion equal
the fixed-output digest of the same input under the same mode.

The top-level static `Blake3` facade exposes
`Hash(input, output)`, `HashKeyed(key, input, output)`, and
`DeriveKey(context, keyMaterial, output)` as the convenience surface
for one-shot hashing of in-memory payloads under the auto-selected
backend. These methods are signature-compatible with the xoofx
`Blake3` NuGet package's `Hash(input, output)` call style, so consumer
call sites can swap implementations textually.

`Blake3Hasher` implements `IDisposable`. Dispose clears the chaining
value, key words, chunk block, and chaining-value stack so sensitive
key material in keyed_hash and derive_key modes does not linger after
the hasher is released.

## § 5 IETF / standards interoperability

BLAKE3 is specified by the BLAKE3-team specification document (Aumasson,
Neves, O'Connor, Wilcox-O'Hearn, January 2020) and the C2SP community
specification. The byte-faithful interoperability gate is the canonical
test vector set distributed with the reference implementation under
`test_vectors/test_vectors.json`: each entry covers one input length
across all three modes, with input being the cycling 251-byte sequence
`0, 1, 2, ..., 249, 250, 0, 1, ...` repeated to the requested length.

The conformance suite in `Lumoin.Veridical.Hashing.Tests` transcribes
all 35 canonical entries as typed C# constants and asserts byte
equality against the portable backend across every entry and every
mode. Accelerated backends, when they land, are agreement-tested
against the portable baseline across the same vector set plus a
random-input sweep.
