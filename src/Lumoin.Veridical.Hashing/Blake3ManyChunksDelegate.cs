using System;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// Per-ISA polymorphism point for the BLAKE3 chunk-parallel
/// compression path. A backend's implementation processes
/// <paramref name="chunkCount"/> complete chunks of input in parallel
/// (each chunk is <see cref="Internal.Blake3Constants.ChunkLength"/> bytes
/// long) and writes a 32-byte chaining value per chunk into the
/// output span.
/// </summary>
/// <param name="chunkInputs">
/// Contiguous bytes containing exactly <paramref name="chunkCount"/>
/// chunks back-to-back. The total length is
/// <paramref name="chunkCount"/> times
/// <see cref="Internal.Blake3Constants.ChunkLength"/>.
/// </param>
/// <param name="chunkCount">The number of complete chunks in the input.</param>
/// <param name="startChunkCounter">
/// The chunk counter for the first chunk in <paramref name="chunkInputs"/>;
/// chunk <c>i</c> uses counter <c>startChunkCounter + i</c>.
/// </param>
/// <param name="keyWords">
/// The eight key words used as the initial chaining value for every chunk
/// (BLAKE3 IV in the regular hash mode, the supplied key in keyed_hash,
/// the derived context key in derive_key).
/// </param>
/// <param name="baseFlags">
/// The flag word every block of every chunk shares — for example
/// <c>KEYED_HASH</c> or <c>DERIVE_KEY_MATERIAL</c>. The per-block
/// CHUNK_START and CHUNK_END bits are added by the backend.
/// </param>
/// <param name="chainingValuesOut">
/// Destination span receiving <paramref name="chunkCount"/> × 32 bytes:
/// one chaining value per chunk in little-endian word order.
/// </param>
/// <remarks>
/// <para>
/// Backends that implement chunk-parallel SIMD (AVX2, AVX-512, NEON)
/// process their natural batch size in lockstep, with each SIMD lane
/// holding one chunk's state at the same word position. Backends that
/// do not parallelize across chunks (the portable scalar baseline)
/// loop one chunk at a time. Both shapes satisfy the same byte-faithful
/// contract: chunk <c>i</c>'s 32-byte chaining value equals what the
/// single-block compression sequence would produce for that chunk's
/// 16 blocks.
/// </para>
/// </remarks>
public delegate void Blake3ManyChunksDelegate(
    ReadOnlySpan<byte> chunkInputs,
    int chunkCount,
    ulong startChunkCounter,
    ReadOnlySpan<uint> keyWords,
    uint baseFlags,
    Span<byte> chainingValuesOut);