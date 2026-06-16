using Lumoin.Veridical.Hashing.Internal;
using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// Inline storage for a <see cref="Sha256Hasher"/>'s working state — the
/// eight-word chaining state and the partially-filled message block. The
/// <see cref="InlineArrayAttribute"/> places every byte of state inside the
/// containing struct's layout, so a plain value copy of the hasher
/// duplicates the entire state with no heap or pool allocation. Mirrors
/// <c>Blake3HasherStateBuffer</c>.
/// </summary>
[InlineArray(Sha256HasherStateBufferLength.Bytes)]
internal struct Sha256HasherStateBuffer
{
    private byte _element0;
}


/// <summary>
/// Compile-time constant for the size of the inline state buffer. Lives in
/// its own type so the <see cref="InlineArrayAttribute"/> argument on
/// <see cref="Sha256HasherStateBuffer"/> can name a single constant rather
/// than embed the arithmetic. Mirrors <c>Blake3HasherStateBufferLength</c>.
/// </summary>
internal static class Sha256HasherStateBufferLength
{
    public const int Bytes =
        Sha256Constants.DigestLength    // chaining state h[8], as native uint words
        + Sha256Constants.BlockLength;  // partially-filled message block
}


/// <summary>
/// Incremental SHA-256 hasher. Construct via <see cref="CreateAutoSelected"/>
/// or <see cref="Create"/>, feed input through <see cref="Update"/>, and
/// produce the digest through <see cref="Finalize"/>.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <see cref="Blake3Hasher"/> — which is a <see langword="ref struct"/>
/// whose state lives only on the stack — this is a plain VALUE
/// <see langword="struct"/> with all of its state inline. That difference is
/// load-bearing: a value-struct hasher can be held in a field and FORKED by
/// a plain value copy (<c>var fork = hasher;</c>), which is exactly the
/// reference transcript's <c>SHA256 tmp; tmp.CopyState(sha_);</c>. The
/// Longfellow transcript holds one running hasher across many absorbs and
/// forks it on every challenge squeeze, turning the per-squeeze cost from a
/// full re-hash of the entire absorbed buffer into a single partial-block
/// finalize.
/// </para>
/// <para>
/// <see cref="Finalize"/> may mutate <c>this</c> (it consumes the partial
/// block and applies the Merkle-Damgard padding), so a caller that needs to
/// keep hashing after taking a digest must fork first: take a value copy,
/// finalize the copy, and keep absorbing into the original. The value copy
/// is independent because the entire state is inline.
/// </para>
/// <para>
/// The chaining state h[8] is stored as native <see cref="uint"/> words, not
/// as serialized big-endian bytes, so a value copy duplicates it trivially;
/// the big-endian conversions happen only at the block-load and digest-emit
/// boundaries.
/// </para>
/// </remarks>
[SuppressMessage("Performance", "CA1815",
    Justification = "An incremental hasher carries mutable working state and an inline state buffer; value equality is not a meaningful operation. Forking is a plain value copy, not an equality comparison.")]
public struct Sha256Hasher
{
    //State layout inside the inline buffer (96 bytes total):
    //  [0..32)   h[8]  — eight u32 chaining-state words in native byte order
    //  [32..96)  block — the partial 64-byte message block accumulating bytes not yet compressed
    private const int StateOffset = 0;
    private const int BlockOffset = StateOffset + Sha256Constants.DigestLength;


    private Sha256HasherStateBuffer state;
    private readonly Sha256Backend backend;
    private ulong totalLength;
    private byte blockLen;


    /// <summary>The fixed SHA-256 digest length in bytes.</summary>
    public const int DigestSizeBytes = Sha256Constants.DigestLength;


    private Sha256Hasher(Sha256Backend backend)
    {
        //Zero-initialise the inline state, then seed the chaining state
        //with the SHA-256 IV. blockLen and totalLength start at zero.
        this = default;
        this.backend = backend;

        Sha256Constants.Iv.CopyTo(HView);
    }


    [UnscopedRef]
    private Span<byte> StateBuffer => MemoryMarshal.CreateSpan(
        ref Unsafe.As<Sha256HasherStateBuffer, byte>(ref state),
        Sha256HasherStateBufferLength.Bytes);


    [UnscopedRef]
    private Span<uint> HView => MemoryMarshal.Cast<byte, uint>(
        StateBuffer.Slice(StateOffset, Sha256Constants.DigestLength));


    [UnscopedRef]
    private Span<byte> BlockView =>
        StateBuffer.Slice(BlockOffset, Sha256Constants.BlockLength);


    /// <summary>
    /// Constructs a fresh hasher wired to the specified backend. The
    /// hasher's entire working state lives inline; no allocation is
    /// performed.
    /// </summary>
    /// <param name="backend">The block-compression backend bundle.</param>
    /// <returns>A fresh hasher seeded with the SHA-256 initialization vector.</returns>
    public static Sha256Hasher Create(Sha256Backend backend) => new(backend);


    /// <summary>
    /// Constructs a fresh hasher wired to the highest-capability backend
    /// supported on the current CPU. The portable scalar backend is the
    /// fallback.
    /// </summary>
    /// <returns>A fresh hasher seeded with the SHA-256 initialization vector.</returns>
    public static Sha256Hasher CreateAutoSelected() => Create(Sha256BackendSelection.SelectBest());


    /// <summary>
    /// Feeds bytes into the hash state. May be called any number of times;
    /// concatenating input across calls is byte-equivalent to a single call
    /// over the concatenated input (the streaming property of
    /// Merkle-Damgard hashing).
    /// </summary>
    /// <param name="input">Bytes to feed into the hash state.</param>
    public void Update(ReadOnlySpan<byte> input)
    {
        totalLength += (ulong)input.Length;

        Span<byte> block = BlockView;
        while(!input.IsEmpty)
        {
            int want = Sha256Constants.BlockLength - blockLen;
            int take = Math.Min(want, input.Length);
            input[..take].CopyTo(block[blockLen..]);
            blockLen = (byte)(blockLen + take);
            input = input[take..];

            if(blockLen == Sha256Constants.BlockLength)
            {
                backend.Compression(HView, block);
                blockLen = 0;
            }
        }
    }


    /// <summary>
    /// Produces the SHA-256 digest into <paramref name="digest"/>, which must
    /// be exactly <see cref="DigestSizeBytes"/> bytes. This applies the
    /// Merkle-Damgard padding and consumes the partial block, so it may
    /// mutate <c>this</c>; a caller that needs to keep absorbing afterwards
    /// must fork (take a value copy) before calling Finalize.
    /// </summary>
    /// <param name="digest">Destination for exactly <see cref="DigestSizeBytes"/> bytes.</param>
    /// <exception cref="ArgumentException">When <paramref name="digest"/> length is not <see cref="DigestSizeBytes"/>.</exception>
    public void Finalize(Span<byte> digest)
    {
        if(digest.Length != DigestSizeBytes)
        {
            throw new ArgumentException(
                $"SHA-256 produces exactly {DigestSizeBytes} bytes; received a {digest.Length}-byte destination.",
                nameof(digest));
        }

        ulong bitLength = totalLength * 8UL;
        Span<byte> block = BlockView;

        //Append the terminating 0x80 byte.
        block[blockLen] = 0x80;
        blockLen++;

        //If the 64-bit length suffix does not fit after the 0x80 in this
        //block, zero-fill the rest of this block, compress it, and start a
        //fresh all-pad block for the length.
        if(blockLen > Sha256Constants.LengthSuffixOffset)
        {
            block[blockLen..].Clear();
            backend.Compression(HView, block);
            blockLen = 0;
        }

        block[blockLen..Sha256Constants.LengthSuffixOffset].Clear();
        BinaryPrimitives.WriteUInt64BigEndian(block[Sha256Constants.LengthSuffixOffset..], bitLength);
        backend.Compression(HView, block);

        WriteWordsBigEndian(HView, digest);
    }


    /// <summary>Clears the inline state buffer. The hasher state is non-secret (it hashes the public transcript), but a Clear helper is provided for symmetry with <see cref="Blake3Hasher.Dispose"/>.</summary>
    public void Clear()
    {
        StateBuffer.Clear();
        blockLen = 0;
        totalLength = 0UL;
    }


    /// <summary>
    /// Encodes <paramref name="words"/> as big-endian bytes into
    /// <paramref name="bytes"/>. <paramref name="bytes"/> must have room for
    /// exactly <c>words.Length * Sha256Constants.WordSizeBytes</c> bytes.
    /// SHA-256 emits its digest big-endian per word.
    /// </summary>
    private static void WriteWordsBigEndian(ReadOnlySpan<uint> words, Span<byte> bytes)
    {
        for(int wordIndex = 0; wordIndex < words.Length; wordIndex++)
        {
            int byteOffset = wordIndex * Sha256Constants.WordSizeBytes;
            BinaryPrimitives.WriteUInt32BigEndian(
                bytes.Slice(start: byteOffset, length: Sha256Constants.WordSizeBytes),
                words[wordIndex]);
        }
    }
}
