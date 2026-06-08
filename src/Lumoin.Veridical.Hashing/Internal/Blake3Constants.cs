using System;

namespace Lumoin.Veridical.Hashing.Internal;

/// <summary>
/// Sizes, IV words, message permutation, and domain-separator flag bits
/// for BLAKE3. The values follow the BLAKE3 specification by Aumasson,
/// Neves, O'Connor, and Wilcox-O'Hearn (January 2020), Section 2.
/// </summary>
/// <remarks>
/// <para>
/// All multi-word constants are stored as little-endian 32-bit words,
/// matching the spec's u32 layout and the reference Rust implementation.
/// The portable backend and the accelerated backends share these
/// constants so a byte-identical wire format is impossible to drift on.
/// </para>
/// </remarks>
internal static class Blake3Constants
{
    /// <summary>Default fixed-output length in bytes (the XOF mode allows arbitrary lengths).</summary>
    public const int OutputLength = 32;

    /// <summary>Key length in bytes for the keyed-hash mode.</summary>
    public const int KeyLength = 32;

    /// <summary>Block length in bytes — the granularity of the compression function input.</summary>
    public const int BlockLength = 64;

    /// <summary>Chunk length in bytes — the leaf-node payload of the Merkle tree.</summary>
    public const int ChunkLength = 1024;

    /// <summary>Byte width of a single 32-bit message or state word.</summary>
    public const int WordSizeBytes = 4;

    /// <summary>Number of 32-bit words in a chaining value (the truncated compression output).</summary>
    public const int ChainingValueWords = 8;

    /// <summary>Number of 32-bit words in a message block (the compression-function block input).</summary>
    public const int BlockWords = 16;

    /// <summary>Number of 32-bit words the compression function produces before truncation.</summary>
    public const int CompressionOutputWords = 16;

    /// <summary>
    /// Maximum depth of the chaining-value stack the incremental hasher
    /// maintains. <c>2^54 * 1024 = 2^64</c> bytes — the entire input domain
    /// the chunk counter can address.
    /// </summary>
    public const int CvStackDepth = 54;


    /// <summary>Flag bit marking the first block of a chunk.</summary>
    public const uint ChunkStart = 1u << 0;

    /// <summary>Flag bit marking the last block of a chunk.</summary>
    public const uint ChunkEnd = 1u << 1;

    /// <summary>Flag bit marking a parent (non-leaf) tree node.</summary>
    public const uint Parent = 1u << 2;

    /// <summary>Flag bit marking the root-output compression.</summary>
    public const uint Root = 1u << 3;

    /// <summary>Flag bit marking the keyed-hash mode.</summary>
    public const uint KeyedHash = 1u << 4;

    /// <summary>Flag bit marking the context-hashing phase of derive_key.</summary>
    public const uint DeriveKeyContext = 1u << 5;

    /// <summary>Flag bit marking the material-hashing phase of derive_key.</summary>
    public const uint DeriveKeyMaterial = 1u << 6;


    /// <summary>
    /// The BLAKE3 initialization vector — eight 32-bit words equal to the
    /// SHA-256 IV.
    /// </summary>
    public static ReadOnlySpan<uint> Iv => IvStorage;


    /// <summary>
    /// The message-word permutation applied between rounds 1-6 (round 7 does
    /// not permute because no further round consumes the result).
    /// </summary>
    public static ReadOnlySpan<byte> MessagePermutation => MessagePermutationStorage;


    private static readonly uint[] IvStorage =
    [
        0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
        0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
    ];

    private static readonly byte[] MessagePermutationStorage =
    [
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
    ];
}