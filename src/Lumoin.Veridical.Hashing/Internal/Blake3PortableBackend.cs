using System;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace Lumoin.Veridical.Hashing.Internal;

/// <summary>
/// Portable scalar implementation of the BLAKE3 compression function.
/// Mirrors the reference Rust implementation distributed with the
/// BLAKE3 specification: seven rounds of the BLAKE2-style G mixing
/// function with the BLAKE3 message permutation between rounds, then
/// a final XOR-folding step that produces the sixteen-word output.
/// </summary>
/// <remarks>
/// <para>
/// This is the correctness reference for every other backend.
/// Accelerated backends in subsequent commits are agreement-tested
/// against this baseline across the canonical test vector set.
/// </para>
/// <para>
/// The implementation is pure managed C# — no <c>unsafe</c>, no
/// platform intrinsics, no P/Invoke — so it runs unchanged under
/// AOT and in a browser via WebAssembly.
/// </para>
/// </remarks>
internal static class Blake3PortableBackend
{
    /// <summary>
    /// Natural batch size for the portable backend. Set to one because
    /// the portable path has no SIMD parallelism; the many-chunks
    /// delegate iterates one chunk at a time. The constant exists so
    /// the dispatch facade can present a uniform Blake3Backend bundle.
    /// </summary>
    public const int ManyChunksBatchSize = 1;


    /// <summary>Returns the portable compression delegate.</summary>
    public static Blake3CompressionDelegate GetCompression() => Compress;


    /// <summary>Returns the portable many-chunks delegate.</summary>
    public static Blake3ManyChunksDelegate GetManyChunks() => CompressManyChunks;


    /// <summary>Returns the full portable backend bundle.</summary>
    public static Blake3Backend GetBackend() =>
        new(GetCompression(), GetManyChunks(), ManyChunksBatchSize);


    /// <summary>
    /// Hashes <paramref name="chunkCount"/> complete chunks one at a
    /// time. The portable backend has no chunk-parallel SIMD; each
    /// chunk runs through the standard sixteen-block compression
    /// sequence with CHUNK_START on block 0 and CHUNK_END on block 15.
    /// </summary>
    private static void CompressManyChunks(
        ReadOnlySpan<byte> chunkInputs,
        int chunkCount,
        ulong startChunkCounter,
        ReadOnlySpan<uint> keyWords,
        uint baseFlags,
        Span<byte> chainingValuesOut)
    {
        Span<uint> cv = stackalloc uint[Blake3Constants.ChainingValueWords];
        Span<uint> blockWords = stackalloc uint[Blake3Constants.BlockWords];
        Span<uint> compressionOutput = stackalloc uint[Blake3Constants.CompressionOutputWords];

        const int blocksPerChunk = Blake3Constants.ChunkLength / Blake3Constants.BlockLength;

        for(int chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++)
        {
            int chunkByteOffset = chunkIndex * Blake3Constants.ChunkLength;
            ReadOnlySpan<byte> chunkBytes = chunkInputs.Slice(
                start: chunkByteOffset, length: Blake3Constants.ChunkLength);
            ulong chunkCounter = startChunkCounter + (ulong)chunkIndex;

            keyWords.CopyTo(cv);

            for(int blockIndex = 0; blockIndex < blocksPerChunk; blockIndex++)
            {
                int blockByteOffset = blockIndex * Blake3Constants.BlockLength;
                ReadOnlySpan<byte> blockBytes = chunkBytes.Slice(
                    start: blockByteOffset, length: Blake3Constants.BlockLength);
                ReadWordsLittleEndian(blockBytes, blockWords);

                uint flags = baseFlags;
                if(blockIndex == 0)
                {
                    flags |= Blake3Constants.ChunkStart;
                }

                if(blockIndex == blocksPerChunk - 1)
                {
                    flags |= Blake3Constants.ChunkEnd;
                }

                Compress(cv, blockWords, chunkCounter, Blake3Constants.BlockLength, flags, compressionOutput);
                compressionOutput[..Blake3Constants.ChainingValueWords].CopyTo(cv);
            }

            int chainingValueOffset = chunkIndex * Blake3Constants.OutputLength;
            WriteWordsLittleEndian(
                cv,
                chainingValuesOut.Slice(start: chainingValueOffset, length: Blake3Constants.OutputLength));
        }
    }


    /// <summary>
    /// Decodes <paramref name="bytes"/> as a sequence of little-endian
    /// 32-bit words and writes them into <paramref name="words"/>.
    /// <paramref name="bytes"/> must contain exactly
    /// <c>words.Length * Blake3Constants.WordSizeBytes</c> bytes.
    /// Returns no value — the destination span is populated in place.
    /// </summary>
    private static void ReadWordsLittleEndian(ReadOnlySpan<byte> bytes, Span<uint> words)
    {
        for(int wordIndex = 0; wordIndex < words.Length; wordIndex++)
        {
            int byteOffset = wordIndex * Blake3Constants.WordSizeBytes;
            words[wordIndex] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.Slice(start: byteOffset, length: Blake3Constants.WordSizeBytes));
        }
    }


    /// <summary>
    /// Encodes <paramref name="words"/> as little-endian bytes into
    /// <paramref name="bytes"/>. <paramref name="bytes"/> must have
    /// room for exactly
    /// <c>words.Length * Blake3Constants.WordSizeBytes</c> bytes.
    /// Returns no value — the destination span is populated in place.
    /// </summary>
    private static void WriteWordsLittleEndian(ReadOnlySpan<uint> words, Span<byte> bytes)
    {
        for(int wordIndex = 0; wordIndex < words.Length; wordIndex++)
        {
            int byteOffset = wordIndex * Blake3Constants.WordSizeBytes;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
                bytes.Slice(start: byteOffset, length: Blake3Constants.WordSizeBytes),
                words[wordIndex]);
        }
    }


    /// <summary>
    /// Portable single-compression. The sixteen-word state and the
    /// sixteen-word message block are held in local <see cref="uint"/>
    /// variables and passed by <see langword="ref"/> between
    /// <see cref="Round"/> and <see cref="G"/>, not in a
    /// <see cref="Span{T}"/>; that layout lets the JIT keep every
    /// state and message word in CPU registers across the seven
    /// rounds and avoids per-access bounds checks on the inner loop.
    /// </summary>
    private static void Compress(
        ReadOnlySpan<uint> chainingValue,
        ReadOnlySpan<uint> blockWords,
        ulong counter,
        uint blockLen,
        uint flags,
        Span<uint> output)
    {
        ReadOnlySpan<uint> iv = Blake3Constants.Iv;
        uint counterLow = (uint)counter;
        uint counterHigh = (uint)(counter >> 32);

        //Initial chaining value (saved for the final XOR-fold step).
        uint cv0 = chainingValue[0];
        uint cv1 = chainingValue[1];
        uint cv2 = chainingValue[2];
        uint cv3 = chainingValue[3];
        uint cv4 = chainingValue[4];
        uint cv5 = chainingValue[5];
        uint cv6 = chainingValue[6];
        uint cv7 = chainingValue[7];

        //State: rows 0-7 = chaining value, 8-11 = IV[0..4],
        //12 = counter lo, 13 = counter hi, 14 = block len, 15 = flags.
        uint s0 = cv0;
        uint s1 = cv1;
        uint s2 = cv2;
        uint s3 = cv3;
        uint s4 = cv4;
        uint s5 = cv5;
        uint s6 = cv6;
        uint s7 = cv7;
        uint s8 = iv[0];
        uint s9 = iv[1];
        uint s10 = iv[2];
        uint s11 = iv[3];
        uint s12 = counterLow;
        uint s13 = counterHigh;
        uint s14 = blockLen;
        uint s15 = flags;

        //Message words, copied into locals so the per-round permutation
        //is a register-to-register reassignment rather than a write
        //into a Span<uint>.
        uint m0 = blockWords[0];
        uint m1 = blockWords[1];
        uint m2 = blockWords[2];
        uint m3 = blockWords[3];
        uint m4 = blockWords[4];
        uint m5 = blockWords[5];
        uint m6 = blockWords[6];
        uint m7 = blockWords[7];
        uint m8 = blockWords[8];
        uint m9 = blockWords[9];
        uint m10 = blockWords[10];
        uint m11 = blockWords[11];
        uint m12 = blockWords[12];
        uint m13 = blockWords[13];
        uint m14 = blockWords[14];
        uint m15 = blockWords[15];

        //Round 1
        Round(
            ref s0, ref s1, ref s2, ref s3,
            ref s4, ref s5, ref s6, ref s7,
            ref s8, ref s9, ref s10, ref s11,
            ref s12, ref s13, ref s14, ref s15,
            m0, m1, m2, m3, m4, m5, m6, m7,
            m8, m9, m10, m11, m12, m13, m14, m15);
        PermuteLocal(
            ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
            ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);

        //Round 2
        Round(
            ref s0, ref s1, ref s2, ref s3,
            ref s4, ref s5, ref s6, ref s7,
            ref s8, ref s9, ref s10, ref s11,
            ref s12, ref s13, ref s14, ref s15,
            m0, m1, m2, m3, m4, m5, m6, m7,
            m8, m9, m10, m11, m12, m13, m14, m15);
        PermuteLocal(
            ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
            ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);

        //Round 3
        Round(
            ref s0, ref s1, ref s2, ref s3,
            ref s4, ref s5, ref s6, ref s7,
            ref s8, ref s9, ref s10, ref s11,
            ref s12, ref s13, ref s14, ref s15,
            m0, m1, m2, m3, m4, m5, m6, m7,
            m8, m9, m10, m11, m12, m13, m14, m15);
        PermuteLocal(
            ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
            ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);

        //Round 4
        Round(
            ref s0, ref s1, ref s2, ref s3,
            ref s4, ref s5, ref s6, ref s7,
            ref s8, ref s9, ref s10, ref s11,
            ref s12, ref s13, ref s14, ref s15,
            m0, m1, m2, m3, m4, m5, m6, m7,
            m8, m9, m10, m11, m12, m13, m14, m15);
        PermuteLocal(
            ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
            ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);

        //Round 5
        Round(
            ref s0, ref s1, ref s2, ref s3,
            ref s4, ref s5, ref s6, ref s7,
            ref s8, ref s9, ref s10, ref s11,
            ref s12, ref s13, ref s14, ref s15,
            m0, m1, m2, m3, m4, m5, m6, m7,
            m8, m9, m10, m11, m12, m13, m14, m15);
        PermuteLocal(
            ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
            ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);

        //Round 6
        Round(
            ref s0, ref s1, ref s2, ref s3,
            ref s4, ref s5, ref s6, ref s7,
            ref s8, ref s9, ref s10, ref s11,
            ref s12, ref s13, ref s14, ref s15,
            m0, m1, m2, m3, m4, m5, m6, m7,
            m8, m9, m10, m11, m12, m13, m14, m15);
        PermuteLocal(
            ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
            ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);

        //Round 7 (no trailing permute — no further round consumes the result).
        Round(
            ref s0, ref s1, ref s2, ref s3,
            ref s4, ref s5, ref s6, ref s7,
            ref s8, ref s9, ref s10, ref s11,
            ref s12, ref s13, ref s14, ref s15,
            m0, m1, m2, m3, m4, m5, m6, m7,
            m8, m9, m10, m11, m12, m13, m14, m15);

        //Output finalization: the upper half of state XORs with the lower
        //half (giving the next-block chaining value), and the lower half
        //XORs with the original chaining value (preserved for the XOF
        //stream when the ROOT flag is set).
        output[0] = s0 ^ s8;
        output[1] = s1 ^ s9;
        output[2] = s2 ^ s10;
        output[3] = s3 ^ s11;
        output[4] = s4 ^ s12;
        output[5] = s5 ^ s13;
        output[6] = s6 ^ s14;
        output[7] = s7 ^ s15;
        output[8] = s8 ^ cv0;
        output[9] = s9 ^ cv1;
        output[10] = s10 ^ cv2;
        output[11] = s11 ^ cv3;
        output[12] = s12 ^ cv4;
        output[13] = s13 ^ cv5;
        output[14] = s14 ^ cv6;
        output[15] = s15 ^ cv7;
    }


    /// <summary>
    /// One BLAKE3 round operating on sixteen state words held in
    /// <see langword="ref"/> locals. Four column-mixing G calls
    /// followed by four diagonal-mixing G calls.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round(
        ref uint s0, ref uint s1, ref uint s2, ref uint s3,
        ref uint s4, ref uint s5, ref uint s6, ref uint s7,
        ref uint s8, ref uint s9, ref uint s10, ref uint s11,
        ref uint s12, ref uint s13, ref uint s14, ref uint s15,
        uint m0, uint m1, uint m2, uint m3,
        uint m4, uint m5, uint m6, uint m7,
        uint m8, uint m9, uint m10, uint m11,
        uint m12, uint m13, uint m14, uint m15)
    {
        //Column mixing.
        G(ref s0, ref s4, ref s8, ref s12, m0, m1);
        G(ref s1, ref s5, ref s9, ref s13, m2, m3);
        G(ref s2, ref s6, ref s10, ref s14, m4, m5);
        G(ref s3, ref s7, ref s11, ref s15, m6, m7);

        //Diagonal mixing.
        G(ref s0, ref s5, ref s10, ref s15, m8, m9);
        G(ref s1, ref s6, ref s11, ref s12, m10, m11);
        G(ref s2, ref s7, ref s8, ref s13, m12, m13);
        G(ref s3, ref s4, ref s9, ref s14, m14, m15);
    }


    /// <summary>
    /// The G mixing function, applied to four state words plus two
    /// message words. Operates on <see langword="ref uint"/> so the
    /// JIT keeps the values in registers between calls within the same
    /// <see cref="Round"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G(
        ref uint a,
        ref uint b,
        ref uint c,
        ref uint d,
        uint mx,
        uint my)
    {
        a = unchecked(a + b + mx);
        d = BitOperations.RotateRight(d ^ a, 16);
        c = unchecked(c + d);
        b = BitOperations.RotateRight(b ^ c, 12);
        a = unchecked(a + b + my);
        d = BitOperations.RotateRight(d ^ a, 8);
        c = unchecked(c + d);
        b = BitOperations.RotateRight(b ^ c, 7);
    }


    /// <summary>
    /// Applies the BLAKE3 message permutation
    /// <c>[2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]</c>
    /// in place across sixteen <see langword="ref uint"/> message
    /// words. The new <c>m_i</c> is read from the old <c>m[perm[i]]</c>;
    /// snapshotting all sixteen old values into locals first lets the
    /// permutation execute without a temporary array.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void PermuteLocal(
        ref uint m0, ref uint m1, ref uint m2, ref uint m3,
        ref uint m4, ref uint m5, ref uint m6, ref uint m7,
        ref uint m8, ref uint m9, ref uint m10, ref uint m11,
        ref uint m12, ref uint m13, ref uint m14, ref uint m15)
    {
        uint n0 = m2;
        uint n1 = m6;
        uint n2 = m3;
        uint n3 = m10;
        uint n4 = m7;
        uint n5 = m0;
        uint n6 = m4;
        uint n7 = m13;
        uint n8 = m1;
        uint n9 = m11;
        uint n10 = m12;
        uint n11 = m5;
        uint n12 = m9;
        uint n13 = m14;
        uint n14 = m15;
        uint n15 = m8;

        m0 = n0; m1 = n1; m2 = n2; m3 = n3;
        m4 = n4; m5 = n5; m6 = n6; m7 = n7;
        m8 = n8; m9 = n9; m10 = n10; m11 = n11;
        m12 = n12; m13 = n13; m14 = n14; m15 = n15;
    }
}