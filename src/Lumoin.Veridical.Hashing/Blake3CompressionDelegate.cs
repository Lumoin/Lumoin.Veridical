using System;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// The per-ISA polymorphism point for BLAKE3. Every backend supplies an
/// implementation that maps the spec's compression function from chaining
/// value, message block, counter, block length, and flags to the
/// sixteen-word compression output.
/// </summary>
/// <param name="chainingValue">
/// The eight-word input chaining value. For a chunk's first block this is
/// the key words (the BLAKE3 IV in the regular hash mode, the supplied key
/// in keyed_hash, the derived context key in derive_key). For subsequent
/// blocks within a chunk it is the previous block's chaining value.
/// </param>
/// <param name="blockWords">
/// The sixteen-word message block, read little-endian from the input
/// bytes. The buffer is zero-padded past the active block length when
/// the chunk's tail block is partial.
/// </param>
/// <param name="counter">
/// For chunk compressions, the chunk index; for parent compressions,
/// always zero; for root XOF compressions, the output-block index.
/// </param>
/// <param name="blockLen">
/// The active byte length of the message block, in <c>[0, BlockLen]</c>.
/// For non-tail compressions this is always <see cref="Internal.Blake3Constants.BlockLength"/>.
/// </param>
/// <param name="flags">
/// The OR of the domain-separator flag bits active for this compression
/// (CHUNK_START, CHUNK_END, PARENT, ROOT, KEYED_HASH, DERIVE_KEY_CONTEXT,
/// DERIVE_KEY_MATERIAL).
/// </param>
/// <param name="output">
/// The sixteen-word compression output. The first eight words are the
/// chaining value (used as input to the next compression); the full
/// sixteen words feed the root XOF stream when the ROOT flag is set.
/// </param>
/// <remarks>
/// <para>
/// Backends implementing this delegate must produce the bit-exact value
/// the spec defines. The canonical BLAKE3 test vectors are the
/// byte-faithful interoperability gate; every backend that runs is
/// agreement-tested against the portable scalar baseline across the full
/// vector set.
/// </para>
/// </remarks>
public delegate void Blake3CompressionDelegate(
    ReadOnlySpan<uint> chainingValue,
    ReadOnlySpan<uint> blockWords,
    ulong counter,
    uint blockLen,
    uint flags,
    Span<uint> output);