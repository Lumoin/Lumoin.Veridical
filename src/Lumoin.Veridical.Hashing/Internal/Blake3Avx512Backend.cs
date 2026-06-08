using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Hashing.Internal;

/// <summary>
/// AVX-512 backend for BLAKE3. Compresses sixteen independent chunks
/// in parallel by laying out chunk state across the 16 lanes of a
/// <see cref="Vector512{T}"/>, then running the standard sixteen-block
/// BLAKE3 compression sequence lane-wise.
/// </summary>
/// <remarks>
/// <para>
/// One <see cref="Vector512{T}"/> of <see cref="uint"/> holds the same
/// state-word position across all sixteen chunks: lane <c>i</c>
/// carries chunk <c>i</c>'s word. The structure mirrors
/// <see cref="Blake3Avx2Backend"/> at twice the parallelism.
/// </para>
/// <para>
/// AVX-512 has native 32-bit rotate (VPROL/VPROR), but the JIT
/// recognises the shift-or-shift pattern used here and emits the
/// rotate intrinsic where available, so the implementation stays
/// portable across .NET runtimes.
/// </para>
/// </remarks>
internal static class Blake3Avx512Backend
{
    /// <summary>Number of chunks processed per parallel batch (AVX-512's sixteen 32-bit lanes).</summary>
    public const int ManyChunksBatchSize = 16;


    /// <summary>True when the host CPU supports the AVX-512F instruction set.</summary>
    public static bool IsSupported => Avx512F.IsSupported;


    /// <summary>Returns the single-compression delegate (delegated to the portable backend).</summary>
    public static Blake3CompressionDelegate GetCompression() =>
        Blake3PortableBackend.GetCompression();


    /// <summary>Returns the AVX-512 chunk-parallel many-chunks delegate.</summary>
    public static Blake3ManyChunksDelegate GetManyChunks() => CompressManyChunks;


    /// <summary>Returns the AVX-512 backend bundle.</summary>
    public static Blake3Backend GetBackend() =>
        new(GetCompression(), GetManyChunks(), ManyChunksBatchSize);


    private static void CompressManyChunks(
        ReadOnlySpan<byte> chunkInputs,
        int chunkCount,
        ulong startChunkCounter,
        ReadOnlySpan<uint> keyWords,
        uint baseFlags,
        Span<byte> chainingValuesOut)
    {
        if(!Avx512F.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "Blake3Avx512Backend requires AVX-512F; check IsSupported before wiring it as a delegate.");
        }

        int batches = chunkCount / ManyChunksBatchSize;
        for(int batchIndex = 0; batchIndex < batches; batchIndex++)
        {
            int chunkOffset = batchIndex * ManyChunksBatchSize;
            CompressSixteenChunks(
                chunkInputs.Slice(
                    start: chunkOffset * Blake3Constants.ChunkLength,
                    length: ManyChunksBatchSize * Blake3Constants.ChunkLength),
                startChunkCounter + (ulong)chunkOffset,
                keyWords,
                baseFlags,
                chainingValuesOut.Slice(
                    start: chunkOffset * Blake3Constants.OutputLength,
                    length: ManyChunksBatchSize * Blake3Constants.OutputLength));
        }

        int tailStart = batches * ManyChunksBatchSize;
        int tailCount = chunkCount - tailStart;
        if(tailCount > 0)
        {
            Blake3PortableBackend.GetManyChunks()(
                chunkInputs[(tailStart * Blake3Constants.ChunkLength)..],
                tailCount,
                startChunkCounter + (ulong)tailStart,
                keyWords,
                baseFlags,
                chainingValuesOut[(tailStart * Blake3Constants.OutputLength)..]);
        }
    }


    private static void CompressSixteenChunks(
        ReadOnlySpan<byte> sixteenChunks,
        ulong startChunkCounter,
        ReadOnlySpan<uint> keyWords,
        uint baseFlags,
        Span<byte> sixteenChainingValues)
    {
        Vector512<uint> h0 = Vector512.Create(keyWords[0]);
        Vector512<uint> h1 = Vector512.Create(keyWords[1]);
        Vector512<uint> h2 = Vector512.Create(keyWords[2]);
        Vector512<uint> h3 = Vector512.Create(keyWords[3]);
        Vector512<uint> h4 = Vector512.Create(keyWords[4]);
        Vector512<uint> h5 = Vector512.Create(keyWords[5]);
        Vector512<uint> h6 = Vector512.Create(keyWords[6]);
        Vector512<uint> h7 = Vector512.Create(keyWords[7]);

        Span<uint> counterLoScratch = stackalloc uint[ManyChunksBatchSize];
        Span<uint> counterHiScratch = stackalloc uint[ManyChunksBatchSize];
        for(int i = 0; i < ManyChunksBatchSize; i++)
        {
            ulong c = startChunkCounter + (ulong)i;
            counterLoScratch[i] = (uint)c;
            counterHiScratch[i] = (uint)(c >> 32);
        }
        Vector512<uint> counterLo = Vector512.Create<uint>(counterLoScratch);
        Vector512<uint> counterHi = Vector512.Create<uint>(counterHiScratch);
        Vector512<uint> blockLengthBroadcast = Vector512.Create((uint)Blake3Constants.BlockLength);

        ReadOnlySpan<uint> iv = Blake3Constants.Iv;
        Vector512<uint> iv0 = Vector512.Create(iv[0]);
        Vector512<uint> iv1 = Vector512.Create(iv[1]);
        Vector512<uint> iv2 = Vector512.Create(iv[2]);
        Vector512<uint> iv3 = Vector512.Create(iv[3]);

        Span<uint> messageScratch = stackalloc uint[ManyChunksBatchSize];
        const int blocksPerChunk = Blake3Constants.ChunkLength / Blake3Constants.BlockLength;

        for(int blockIndex = 0; blockIndex < blocksPerChunk; blockIndex++)
        {
            uint blockFlags = baseFlags;
            if(blockIndex == 0)
            {
                blockFlags |= Blake3Constants.ChunkStart;
            }

            if(blockIndex == blocksPerChunk - 1)
            {
                blockFlags |= Blake3Constants.ChunkEnd;
            }

            Vector512<uint> m0 = LoadMessageWord(sixteenChunks, blockIndex, 0, messageScratch);
            Vector512<uint> m1 = LoadMessageWord(sixteenChunks, blockIndex, 1, messageScratch);
            Vector512<uint> m2 = LoadMessageWord(sixteenChunks, blockIndex, 2, messageScratch);
            Vector512<uint> m3 = LoadMessageWord(sixteenChunks, blockIndex, 3, messageScratch);
            Vector512<uint> m4 = LoadMessageWord(sixteenChunks, blockIndex, 4, messageScratch);
            Vector512<uint> m5 = LoadMessageWord(sixteenChunks, blockIndex, 5, messageScratch);
            Vector512<uint> m6 = LoadMessageWord(sixteenChunks, blockIndex, 6, messageScratch);
            Vector512<uint> m7 = LoadMessageWord(sixteenChunks, blockIndex, 7, messageScratch);
            Vector512<uint> m8 = LoadMessageWord(sixteenChunks, blockIndex, 8, messageScratch);
            Vector512<uint> m9 = LoadMessageWord(sixteenChunks, blockIndex, 9, messageScratch);
            Vector512<uint> m10 = LoadMessageWord(sixteenChunks, blockIndex, 10, messageScratch);
            Vector512<uint> m11 = LoadMessageWord(sixteenChunks, blockIndex, 11, messageScratch);
            Vector512<uint> m12 = LoadMessageWord(sixteenChunks, blockIndex, 12, messageScratch);
            Vector512<uint> m13 = LoadMessageWord(sixteenChunks, blockIndex, 13, messageScratch);
            Vector512<uint> m14 = LoadMessageWord(sixteenChunks, blockIndex, 14, messageScratch);
            Vector512<uint> m15 = LoadMessageWord(sixteenChunks, blockIndex, 15, messageScratch);

            Vector512<uint> s0 = h0;
            Vector512<uint> s1 = h1;
            Vector512<uint> s2 = h2;
            Vector512<uint> s3 = h3;
            Vector512<uint> s4 = h4;
            Vector512<uint> s5 = h5;
            Vector512<uint> s6 = h6;
            Vector512<uint> s7 = h7;
            Vector512<uint> s8 = iv0;
            Vector512<uint> s9 = iv1;
            Vector512<uint> s10 = iv2;
            Vector512<uint> s11 = iv3;
            Vector512<uint> s12 = counterLo;
            Vector512<uint> s13 = counterHi;
            Vector512<uint> s14 = blockLengthBroadcast;
            Vector512<uint> s15 = Vector512.Create(blockFlags);

            for(int roundIndex = 0; roundIndex < 7; roundIndex++)
            {
                Round(
                    ref s0, ref s1, ref s2, ref s3,
                    ref s4, ref s5, ref s6, ref s7,
                    ref s8, ref s9, ref s10, ref s11,
                    ref s12, ref s13, ref s14, ref s15,
                    m0, m1, m2, m3, m4, m5, m6, m7,
                    m8, m9, m10, m11, m12, m13, m14, m15);

                if(roundIndex < 6)
                {
                    PermuteMessage(
                        ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
                        ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
                }
            }

            h0 = s0 ^ s8;
            h1 = s1 ^ s9;
            h2 = s2 ^ s10;
            h3 = s3 ^ s11;
            h4 = s4 ^ s12;
            h5 = s5 ^ s13;
            h6 = s6 ^ s14;
            h7 = s7 ^ s15;
        }

        Span<uint> hScratch = stackalloc uint[ManyChunksBatchSize];
        StoreChainingValueWord(h0, hScratch, sixteenChainingValues, 0);
        StoreChainingValueWord(h1, hScratch, sixteenChainingValues, 1);
        StoreChainingValueWord(h2, hScratch, sixteenChainingValues, 2);
        StoreChainingValueWord(h3, hScratch, sixteenChainingValues, 3);
        StoreChainingValueWord(h4, hScratch, sixteenChainingValues, 4);
        StoreChainingValueWord(h5, hScratch, sixteenChainingValues, 5);
        StoreChainingValueWord(h6, hScratch, sixteenChainingValues, 6);
        StoreChainingValueWord(h7, hScratch, sixteenChainingValues, 7);
    }


    private static Vector512<uint> LoadMessageWord(
        ReadOnlySpan<byte> sixteenChunks,
        int blockIndex,
        int wordIndex,
        Span<uint> scratch)
    {
        for(int chunkIndex = 0; chunkIndex < ManyChunksBatchSize; chunkIndex++)
        {
            int byteOffset =
                chunkIndex * Blake3Constants.ChunkLength
                + blockIndex * Blake3Constants.BlockLength
                + wordIndex * Blake3Constants.WordSizeBytes;
            scratch[chunkIndex] = BinaryPrimitives.ReadUInt32LittleEndian(
                sixteenChunks.Slice(start: byteOffset, length: Blake3Constants.WordSizeBytes));
        }

        return Vector512.Create<uint>(scratch);
    }


    private static void StoreChainingValueWord(
        Vector512<uint> lane,
        Span<uint> scratch,
        Span<byte> sixteenChainingValues,
        int wordIndex)
    {
        lane.CopyTo(scratch);
        for(int chunkIndex = 0; chunkIndex < ManyChunksBatchSize; chunkIndex++)
        {
            int byteOffset =
                chunkIndex * Blake3Constants.OutputLength
                + wordIndex * Blake3Constants.WordSizeBytes;
            BinaryPrimitives.WriteUInt32LittleEndian(
                sixteenChainingValues.Slice(start: byteOffset, length: Blake3Constants.WordSizeBytes),
                scratch[chunkIndex]);
        }
    }


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round(
        ref Vector512<uint> s0, ref Vector512<uint> s1, ref Vector512<uint> s2, ref Vector512<uint> s3,
        ref Vector512<uint> s4, ref Vector512<uint> s5, ref Vector512<uint> s6, ref Vector512<uint> s7,
        ref Vector512<uint> s8, ref Vector512<uint> s9, ref Vector512<uint> s10, ref Vector512<uint> s11,
        ref Vector512<uint> s12, ref Vector512<uint> s13, ref Vector512<uint> s14, ref Vector512<uint> s15,
        Vector512<uint> m0, Vector512<uint> m1, Vector512<uint> m2, Vector512<uint> m3,
        Vector512<uint> m4, Vector512<uint> m5, Vector512<uint> m6, Vector512<uint> m7,
        Vector512<uint> m8, Vector512<uint> m9, Vector512<uint> m10, Vector512<uint> m11,
        Vector512<uint> m12, Vector512<uint> m13, Vector512<uint> m14, Vector512<uint> m15)
    {
        G(ref s0, ref s4, ref s8, ref s12, m0, m1);
        G(ref s1, ref s5, ref s9, ref s13, m2, m3);
        G(ref s2, ref s6, ref s10, ref s14, m4, m5);
        G(ref s3, ref s7, ref s11, ref s15, m6, m7);

        G(ref s0, ref s5, ref s10, ref s15, m8, m9);
        G(ref s1, ref s6, ref s11, ref s12, m10, m11);
        G(ref s2, ref s7, ref s8, ref s13, m12, m13);
        G(ref s3, ref s4, ref s9, ref s14, m14, m15);
    }


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G(
        ref Vector512<uint> a,
        ref Vector512<uint> b,
        ref Vector512<uint> c,
        ref Vector512<uint> d,
        Vector512<uint> mx,
        Vector512<uint> my)
    {
        a = a + b + mx;
        d = RotateRight(d ^ a, 16);
        c = c + d;
        b = RotateRight(b ^ c, 12);
        a = a + b + my;
        d = RotateRight(d ^ a, 8);
        c = c + d;
        b = RotateRight(b ^ c, 7);
    }


    /// <summary>
    /// Rotate-right by <paramref name="count"/> bits within each 32-bit
    /// lane. Implemented as the standard shift-or-shift composition;
    /// the JIT lowers this to <c>VPROR</c> when AVX-512F is active.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector512<uint> RotateRight(Vector512<uint> x, byte count) =>
        (x >>> count) | (x << (32 - count));


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void PermuteMessage(
        ref Vector512<uint> m0, ref Vector512<uint> m1, ref Vector512<uint> m2, ref Vector512<uint> m3,
        ref Vector512<uint> m4, ref Vector512<uint> m5, ref Vector512<uint> m6, ref Vector512<uint> m7,
        ref Vector512<uint> m8, ref Vector512<uint> m9, ref Vector512<uint> m10, ref Vector512<uint> m11,
        ref Vector512<uint> m12, ref Vector512<uint> m13, ref Vector512<uint> m14, ref Vector512<uint> m15)
    {
        Vector512<uint> n0 = m2;
        Vector512<uint> n1 = m6;
        Vector512<uint> n2 = m3;
        Vector512<uint> n3 = m10;
        Vector512<uint> n4 = m7;
        Vector512<uint> n5 = m0;
        Vector512<uint> n6 = m4;
        Vector512<uint> n7 = m13;
        Vector512<uint> n8 = m1;
        Vector512<uint> n9 = m11;
        Vector512<uint> n10 = m12;
        Vector512<uint> n11 = m5;
        Vector512<uint> n12 = m9;
        Vector512<uint> n13 = m14;
        Vector512<uint> n14 = m15;
        Vector512<uint> n15 = m8;

        m0 = n0; m1 = n1; m2 = n2; m3 = n3;
        m4 = n4; m5 = n5; m6 = n6; m7 = n7;
        m8 = n8; m9 = n9; m10 = n10; m11 = n11;
        m12 = n12; m13 = n13; m14 = n14; m15 = n15;
    }
}