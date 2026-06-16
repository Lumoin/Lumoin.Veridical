using System;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// The per-ISA polymorphism point for SHA-256. Every backend supplies an
/// implementation that folds one 64-byte message block into the eight-word
/// chaining state, in place.
/// </summary>
/// <param name="state8">
/// The eight-word chaining state (H0..H7), held as native <see cref="uint"/>
/// words. On entry it is the state after all prior blocks (seeded from the
/// SHA-256 initialization vector for the first block); on return it is the
/// state after folding <paramref name="block64"/>.
/// </param>
/// <param name="block64">
/// One 64-byte message block. The sixteen message words are read big-endian
/// from these bytes; SHA-256 is a big-endian algorithm.
/// </param>
/// <remarks>
/// <para>
/// Unlike <see cref="Blake3CompressionDelegate"/> there is no counter,
/// block-length, or flags argument: SHA-256 is a single linear
/// Merkle-Damgard chain with no domain-separation flags and no chunk
/// parallelism. The block length is always exactly
/// <see cref="Internal.Sha256Constants.BlockLength"/>; the message-length
/// padding is applied by the caller before the final block is compressed.
/// </para>
/// <para>
/// Backends implementing this delegate must produce the bit-exact value
/// FIPS 180-4 defines. The portable scalar backend is the correctness
/// reference; any future accelerated backend (SHA-NI on x86, the SHA2
/// instructions on AArch64) is agreement-tested against it.
/// </para>
/// </remarks>
public delegate void Sha256CompressionDelegate(Span<uint> state8, ReadOnlySpan<byte> block64);
