using System;

namespace Lumoin.Veridical.Hashing.Internal;

/// <summary>
/// Sizes, the eight-word initialization vector, and the sixty-four
/// round constants for SHA-256. The values follow FIPS 180-4,
/// Sections 4.2.2 and 5.3.3. Mirrors <see cref="Blake3Constants"/> in
/// shape; the load-bearing difference is that SHA-256 is a big-endian
/// algorithm — message words load big-endian, the length suffix in the
/// pad is big-endian, and the digest emits big-endian.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="Iv"/> words are the first thirty-two bits of the
/// fractional parts of the square roots of the first eight primes; the
/// <see cref="K"/> words are the first thirty-two bits of the fractional
/// parts of the cube roots of the first sixty-four primes. They are
/// stored as native <see cref="uint"/> words (not bytes on the wire) so
/// the portable backend and any future accelerated backend share one
/// definition and cannot drift on the wire format.
/// </para>
/// </remarks>
internal static class Sha256Constants
{
    /// <summary>Digest length in bytes — the fixed SHA-256 output.</summary>
    public const int DigestLength = 32;

    /// <summary>Block length in bytes — the granularity of the compression function input.</summary>
    public const int BlockLength = 64;

    /// <summary>Byte width of a single 32-bit message or state word.</summary>
    public const int WordSizeBytes = 4;

    /// <summary>Number of 32-bit words in the chaining state (the digest, before serialization).</summary>
    public const int StateWords = 8;

    /// <summary>Number of 32-bit words in a message block.</summary>
    public const int BlockWords = 16;

    /// <summary>Number of words in the expanded message schedule.</summary>
    public const int ScheduleWords = 64;

    /// <summary>
    /// The byte offset within a padded block at which the 64-bit
    /// big-endian message-length suffix is written. A block can hold the
    /// terminating <c>0x80</c> byte and the length only when the partial
    /// length is at or below this offset; otherwise an extra all-pad
    /// block is compressed first.
    /// </summary>
    public const int LengthSuffixOffset = 56;


    /// <summary>The SHA-256 initialization vector — eight 32-bit words (H0..H7).</summary>
    public static ReadOnlySpan<uint> Iv => IvStorage;


    /// <summary>The sixty-four SHA-256 round constants (K0..K63).</summary>
    public static ReadOnlySpan<uint> K => KStorage;


    private static readonly uint[] IvStorage =
    [
        0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
        0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
    ];

    private static readonly uint[] KStorage =
    [
        0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u,
        0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
        0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u,
        0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
        0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu,
        0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
        0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u,
        0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
        0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u,
        0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
        0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u,
        0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
        0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u,
        0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
        0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u,
        0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u,
    ];
}
