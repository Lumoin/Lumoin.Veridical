using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Hashing.Internal;

/// <summary>
/// AVX2 backend for BLAKE3. Compresses eight independent chunks in
/// parallel by laying out chunk state across the 8 lanes of a
/// <see cref="Vector256{T}"/>, then running the standard sixteen-block
/// BLAKE3 compression sequence lane-wise.
/// </summary>
/// <remarks>
/// <para>
/// One <see cref="Vector256{T}"/> of <see cref="uint"/> holds the same
/// state-word position across all eight chunks: lane <c>i</c> carries
/// chunk <c>i</c>'s word. The G mixing function and the round
/// structure operate on these vectors directly; the carry, XOR, and
/// rotate operations are all lane-wise so the eight chunks proceed in
/// lockstep without any cross-chunk dependency.
/// </para>
/// <para>
/// The partial-tail block, parent compressions, and root XOF
/// expansion delegate to the portable scalar backend; the many-chunks
/// path covers only the bulk full-chunk hashing where the SIMD
/// parallelism pays off.
/// </para>
/// </remarks>
internal static class Blake3Avx2Backend
{
    /// <summary>Number of chunks processed per parallel batch (AVX2's eight 32-bit lanes).</summary>
    public const int ManyChunksBatchSize = 8;


    /// <summary>True when the host CPU supports the AVX2 instruction set.</summary>
    public static bool IsSupported => Avx2.IsSupported;


    /// <summary>Returns the single-compression delegate (delegated to the portable backend).</summary>
    public static Blake3CompressionDelegate GetCompression() =>
        Blake3PortableBackend.GetCompression();


    /// <summary>Returns the AVX2 chunk-parallel many-chunks delegate.</summary>
    public static Blake3ManyChunksDelegate GetManyChunks() => CompressManyChunks;


    /// <summary>Returns the AVX2 backend bundle.</summary>
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
        if(!Avx2.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "Blake3Avx2Backend requires AVX2; check IsSupported before wiring it as a delegate.");
        }

        int batches = chunkCount / ManyChunksBatchSize;
        for(int batchIndex = 0; batchIndex < batches; batchIndex++)
        {
            int chunkOffset = batchIndex * ManyChunksBatchSize;
            CompressEightChunks(
                chunkInputs.Slice(
                    chunkOffset * Blake3Constants.ChunkLength,
                    ManyChunksBatchSize * Blake3Constants.ChunkLength),
                startChunkCounter + (ulong)chunkOffset,
                keyWords,
                baseFlags,
                chainingValuesOut.Slice(
                    chunkOffset * Blake3Constants.OutputLength,
                    ManyChunksBatchSize * Blake3Constants.OutputLength));
        }

        //Tail: fewer than ManyChunksBatchSize chunks remaining; fall
        //back to the portable single-chunk loop.
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


    /// <summary>
    /// Compresses eight chunks in parallel. Each
    /// <see cref="Vector256{T}"/> of <see cref="uint"/> holds the same
    /// word position across all eight chunks (lane i = chunk i's
    /// word). The 16 blocks of each chunk are processed sequentially,
    /// with CHUNK_START on block 0 and CHUNK_END on block 15. The
    /// eight chaining values are written out at the end.
    /// </summary>
    private static void CompressEightChunks(
        ReadOnlySpan<byte> eightChunks,
        ulong startChunkCounter,
        ReadOnlySpan<uint> keyWords,
        uint baseFlags,
        Span<byte> eightChainingValues)
    {
        //Initial chaining value: keyWords broadcast across all eight
        //lanes (every chunk starts from the same key).
        Vector256<uint> h0 = Vector256.Create(keyWords[0]);
        Vector256<uint> h1 = Vector256.Create(keyWords[1]);
        Vector256<uint> h2 = Vector256.Create(keyWords[2]);
        Vector256<uint> h3 = Vector256.Create(keyWords[3]);
        Vector256<uint> h4 = Vector256.Create(keyWords[4]);
        Vector256<uint> h5 = Vector256.Create(keyWords[5]);
        Vector256<uint> h6 = Vector256.Create(keyWords[6]);
        Vector256<uint> h7 = Vector256.Create(keyWords[7]);

        //Per-chunk counters: lane i = startChunkCounter + i.
        Span<uint> counterLoScratch = stackalloc uint[ManyChunksBatchSize];
        Span<uint> counterHiScratch = stackalloc uint[ManyChunksBatchSize];
        for(int i = 0; i < ManyChunksBatchSize; i++)
        {
            ulong c = startChunkCounter + (ulong)i;
            counterLoScratch[i] = (uint)c;
            counterHiScratch[i] = (uint)(c >> 32);
        }
        Vector256<uint> counterLo = Vector256.Create<uint>(counterLoScratch);
        Vector256<uint> counterHi = Vector256.Create<uint>(counterHiScratch);
        Vector256<uint> blockLenBroadcast = Vector256.Create((uint)Blake3Constants.BlockLength);

        //IV broadcast vectors used in every block compression.
        ReadOnlySpan<uint> iv = Blake3Constants.Iv;
        Vector256<uint> iv0 = Vector256.Create(iv[0]);
        Vector256<uint> iv1 = Vector256.Create(iv[1]);
        Vector256<uint> iv2 = Vector256.Create(iv[2]);
        Vector256<uint> iv3 = Vector256.Create(iv[3]);

        const int blocksPerChunk = Blake3Constants.ChunkLength / Blake3Constants.BlockLength;
        ref byte eightChunksRef = ref MemoryMarshal.GetReference(eightChunks);

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

            //Vector load + 8x8 transpose: load each chunk's 64-byte
            //block as two Vector256<uint> (low 32 B = words 0..7,
            //high 32 B = words 8..15), then transpose to obtain the
            //sixteen column-major message vectors where lane i of
            //m_w holds chunk i's word w. Eliminates the previous
            //scalar-read-per-word pattern entirely.
            LoadAndTransposeBlock(
                ref eightChunksRef, blockIndex,
                out Vector256<uint> m0, out Vector256<uint> m1,
                out Vector256<uint> m2, out Vector256<uint> m3,
                out Vector256<uint> m4, out Vector256<uint> m5,
                out Vector256<uint> m6, out Vector256<uint> m7,
                out Vector256<uint> m8, out Vector256<uint> m9,
                out Vector256<uint> m10, out Vector256<uint> m11,
                out Vector256<uint> m12, out Vector256<uint> m13,
                out Vector256<uint> m14, out Vector256<uint> m15);

            //State: chaining value (rows 0-7) + IV[0..4] (rows 8-11)
            //+ counter low/high (rows 12-13) + block len (row 14) + flags (row 15).
            Vector256<uint> s0 = h0;
            Vector256<uint> s1 = h1;
            Vector256<uint> s2 = h2;
            Vector256<uint> s3 = h3;
            Vector256<uint> s4 = h4;
            Vector256<uint> s5 = h5;
            Vector256<uint> s6 = h6;
            Vector256<uint> s7 = h7;
            Vector256<uint> s8 = iv0;
            Vector256<uint> s9 = iv1;
            Vector256<uint> s10 = iv2;
            Vector256<uint> s11 = iv3;
            Vector256<uint> s12 = counterLo;
            Vector256<uint> s13 = counterHi;
            Vector256<uint> s14 = blockLenBroadcast;
            Vector256<uint> s15 = Vector256.Create(blockFlags);

            //Seven rounds. The message words are permuted between
            //rounds via the BLAKE3 message permutation; we rotate the
            //local message-word variables in-place rather than copying
            //into a fresh array.
            Round(
                ref s0, ref s1, ref s2, ref s3,
                ref s4, ref s5, ref s6, ref s7,
                ref s8, ref s9, ref s10, ref s11,
                ref s12, ref s13, ref s14, ref s15,
                m0, m1, m2, m3, m4, m5, m6, m7,
                m8, m9, m10, m11, m12, m13, m14, m15);
            PermuteMessage(
                ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
                ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
            Round(
                ref s0, ref s1, ref s2, ref s3,
                ref s4, ref s5, ref s6, ref s7,
                ref s8, ref s9, ref s10, ref s11,
                ref s12, ref s13, ref s14, ref s15,
                m0, m1, m2, m3, m4, m5, m6, m7,
                m8, m9, m10, m11, m12, m13, m14, m15);
            PermuteMessage(
                ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
                ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
            Round(
                ref s0, ref s1, ref s2, ref s3,
                ref s4, ref s5, ref s6, ref s7,
                ref s8, ref s9, ref s10, ref s11,
                ref s12, ref s13, ref s14, ref s15,
                m0, m1, m2, m3, m4, m5, m6, m7,
                m8, m9, m10, m11, m12, m13, m14, m15);
            PermuteMessage(
                ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
                ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
            Round(
                ref s0, ref s1, ref s2, ref s3,
                ref s4, ref s5, ref s6, ref s7,
                ref s8, ref s9, ref s10, ref s11,
                ref s12, ref s13, ref s14, ref s15,
                m0, m1, m2, m3, m4, m5, m6, m7,
                m8, m9, m10, m11, m12, m13, m14, m15);
            PermuteMessage(
                ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
                ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
            Round(
                ref s0, ref s1, ref s2, ref s3,
                ref s4, ref s5, ref s6, ref s7,
                ref s8, ref s9, ref s10, ref s11,
                ref s12, ref s13, ref s14, ref s15,
                m0, m1, m2, m3, m4, m5, m6, m7,
                m8, m9, m10, m11, m12, m13, m14, m15);
            PermuteMessage(
                ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
                ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
            Round(
                ref s0, ref s1, ref s2, ref s3,
                ref s4, ref s5, ref s6, ref s7,
                ref s8, ref s9, ref s10, ref s11,
                ref s12, ref s13, ref s14, ref s15,
                m0, m1, m2, m3, m4, m5, m6, m7,
                m8, m9, m10, m11, m12, m13, m14, m15);
            PermuteMessage(
                ref m0, ref m1, ref m2, ref m3, ref m4, ref m5, ref m6, ref m7,
                ref m8, ref m9, ref m10, ref m11, ref m12, ref m13, ref m14, ref m15);
            Round(
                ref s0, ref s1, ref s2, ref s3,
                ref s4, ref s5, ref s6, ref s7,
                ref s8, ref s9, ref s10, ref s11,
                ref s12, ref s13, ref s14, ref s15,
                m0, m1, m2, m3, m4, m5, m6, m7,
                m8, m9, m10, m11, m12, m13, m14, m15);

            //Update chaining value: cv[i] = state[i] XOR state[i+8].
            h0 = s0 ^ s8;
            h1 = s1 ^ s9;
            h2 = s2 ^ s10;
            h3 = s3 ^ s11;
            h4 = s4 ^ s12;
            h5 = s5 ^ s13;
            h6 = s6 ^ s14;
            h7 = s7 ^ s15;
        }

        //Store eight chunks' chaining values. Lane i of (h0,...,h7) is
        //chunk i's 8-word chaining value.
        Span<uint> hScratch = stackalloc uint[ManyChunksBatchSize];
        StoreChainingValueWord(h0, hScratch, eightChainingValues, 0);
        StoreChainingValueWord(h1, hScratch, eightChainingValues, 1);
        StoreChainingValueWord(h2, hScratch, eightChainingValues, 2);
        StoreChainingValueWord(h3, hScratch, eightChainingValues, 3);
        StoreChainingValueWord(h4, hScratch, eightChainingValues, 4);
        StoreChainingValueWord(h5, hScratch, eightChainingValues, 5);
        StoreChainingValueWord(h6, hScratch, eightChainingValues, 6);
        StoreChainingValueWord(h7, hScratch, eightChainingValues, 7);
    }


    /// <summary>
    /// Loads message word <paramref name="wordIndex"/> of block
    /// <paramref name="blockIndex"/> across all eight chunks, packing
    /// them lane-wise into a single <see cref="Vector256{T}"/>.
    /// </summary>
    /// <summary>
    /// Loads the eight chunks' block at <paramref name="blockIndex"/>
    /// and transposes them into the sixteen column-major message
    /// vectors the compression round expects. Each chunk's 64-byte
    /// block is read as two <see cref="Vector256{T}"/> rows (words
    /// 0–7, then words 8–15); two 8×8 transposes produce
    /// <c>m_w[i] = chunk_i.word_w</c> for w in 0..16.
    /// </summary>
    /// <remarks>
    /// On little-endian x86, reading 32 bytes as <see cref="Vector256{T}"/>
    /// of <see cref="byte"/> and reinterpreting as <see cref="uint"/>
    /// reproduces BLAKE3's little-endian word layout without an
    /// explicit byte-swap, so the load is a single MOVDQU per
    /// 32-byte segment.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void LoadAndTransposeBlock(
        ref byte eightChunksRef,
        int blockIndex,
        out Vector256<uint> m0, out Vector256<uint> m1,
        out Vector256<uint> m2, out Vector256<uint> m3,
        out Vector256<uint> m4, out Vector256<uint> m5,
        out Vector256<uint> m6, out Vector256<uint> m7,
        out Vector256<uint> m8, out Vector256<uint> m9,
        out Vector256<uint> m10, out Vector256<uint> m11,
        out Vector256<uint> m12, out Vector256<uint> m13,
        out Vector256<uint> m14, out Vector256<uint> m15)
    {
        int blockOffset = blockIndex * Blake3Constants.BlockLength;
        const int chunkStride = Blake3Constants.ChunkLength;
        const int halfBlock = Blake3Constants.BlockLength / 2;

        //Load low halves (words 0..7) for each of eight chunks.
        Vector256<uint> r0lo = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 0 * chunkStride + blockOffset)).AsUInt32();
        Vector256<uint> r1lo = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 1 * chunkStride + blockOffset)).AsUInt32();
        Vector256<uint> r2lo = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 2 * chunkStride + blockOffset)).AsUInt32();
        Vector256<uint> r3lo = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 3 * chunkStride + blockOffset)).AsUInt32();
        Vector256<uint> r4lo = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 4 * chunkStride + blockOffset)).AsUInt32();
        Vector256<uint> r5lo = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 5 * chunkStride + blockOffset)).AsUInt32();
        Vector256<uint> r6lo = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 6 * chunkStride + blockOffset)).AsUInt32();
        Vector256<uint> r7lo = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 7 * chunkStride + blockOffset)).AsUInt32();

        //Load high halves (words 8..15) for each of eight chunks.
        Vector256<uint> r0hi = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 0 * chunkStride + blockOffset + halfBlock)).AsUInt32();
        Vector256<uint> r1hi = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 1 * chunkStride + blockOffset + halfBlock)).AsUInt32();
        Vector256<uint> r2hi = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 2 * chunkStride + blockOffset + halfBlock)).AsUInt32();
        Vector256<uint> r3hi = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 3 * chunkStride + blockOffset + halfBlock)).AsUInt32();
        Vector256<uint> r4hi = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 4 * chunkStride + blockOffset + halfBlock)).AsUInt32();
        Vector256<uint> r5hi = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 5 * chunkStride + blockOffset + halfBlock)).AsUInt32();
        Vector256<uint> r6hi = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 6 * chunkStride + blockOffset + halfBlock)).AsUInt32();
        Vector256<uint> r7hi = Vector256.LoadUnsafe(
            ref Unsafe.Add(ref eightChunksRef, 7 * chunkStride + blockOffset + halfBlock)).AsUInt32();

        Transpose8x8(
            r0lo, r1lo, r2lo, r3lo, r4lo, r5lo, r6lo, r7lo,
            out m0, out m1, out m2, out m3, out m4, out m5, out m6, out m7);

        Transpose8x8(
            r0hi, r1hi, r2hi, r3hi, r4hi, r5hi, r6hi, r7hi,
            out m8, out m9, out m10, out m11, out m12, out m13, out m14, out m15);
    }


    /// <summary>
    /// Classic AVX2 8×8 32-bit transpose: takes eight row vectors
    /// and produces eight column vectors where <c>t_i[j] = r_j[i]</c>.
    /// Twelve <c>UnpackLow</c>/<c>UnpackHigh</c> pairs followed by
    /// eight <c>Permute2x128</c> ops; the JIT lowers each to a single
    /// AVX2 instruction.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Transpose8x8(
        Vector256<uint> r0, Vector256<uint> r1, Vector256<uint> r2, Vector256<uint> r3,
        Vector256<uint> r4, Vector256<uint> r5, Vector256<uint> r6, Vector256<uint> r7,
        out Vector256<uint> t0, out Vector256<uint> t1, out Vector256<uint> t2, out Vector256<uint> t3,
        out Vector256<uint> t4, out Vector256<uint> t5, out Vector256<uint> t6, out Vector256<uint> t7)
    {
        //Stage 1: interleave 32-bit lanes pairwise (per 128-bit half).
        Vector256<uint> a0 = Avx2.UnpackLow(r0, r1);
        Vector256<uint> a1 = Avx2.UnpackHigh(r0, r1);
        Vector256<uint> a2 = Avx2.UnpackLow(r2, r3);
        Vector256<uint> a3 = Avx2.UnpackHigh(r2, r3);
        Vector256<uint> a4 = Avx2.UnpackLow(r4, r5);
        Vector256<uint> a5 = Avx2.UnpackHigh(r4, r5);
        Vector256<uint> a6 = Avx2.UnpackLow(r6, r7);
        Vector256<uint> a7 = Avx2.UnpackHigh(r6, r7);

        //Stage 2: interleave 64-bit lanes pairwise (per 128-bit half).
        Vector256<uint> b0 = Avx2.UnpackLow(a0.AsUInt64(), a2.AsUInt64()).AsUInt32();
        Vector256<uint> b1 = Avx2.UnpackHigh(a0.AsUInt64(), a2.AsUInt64()).AsUInt32();
        Vector256<uint> b2 = Avx2.UnpackLow(a1.AsUInt64(), a3.AsUInt64()).AsUInt32();
        Vector256<uint> b3 = Avx2.UnpackHigh(a1.AsUInt64(), a3.AsUInt64()).AsUInt32();
        Vector256<uint> b4 = Avx2.UnpackLow(a4.AsUInt64(), a6.AsUInt64()).AsUInt32();
        Vector256<uint> b5 = Avx2.UnpackHigh(a4.AsUInt64(), a6.AsUInt64()).AsUInt32();
        Vector256<uint> b6 = Avx2.UnpackLow(a5.AsUInt64(), a7.AsUInt64()).AsUInt32();
        Vector256<uint> b7 = Avx2.UnpackHigh(a5.AsUInt64(), a7.AsUInt64()).AsUInt32();

        //Stage 3: swap the 128-bit halves to complete the transpose.
        t0 = Avx2.Permute2x128(b0, b4, 0x20);
        t1 = Avx2.Permute2x128(b1, b5, 0x20);
        t2 = Avx2.Permute2x128(b2, b6, 0x20);
        t3 = Avx2.Permute2x128(b3, b7, 0x20);
        t4 = Avx2.Permute2x128(b0, b4, 0x31);
        t5 = Avx2.Permute2x128(b1, b5, 0x31);
        t6 = Avx2.Permute2x128(b2, b6, 0x31);
        t7 = Avx2.Permute2x128(b3, b7, 0x31);
    }


    /// <summary>
    /// Writes word <paramref name="wordIndex"/> of every chunk's
    /// chaining value to the output buffer, in little-endian order.
    /// Lane <c>i</c> of <paramref name="lane"/> is chunk <c>i</c>'s
    /// word at this position.
    /// </summary>
    private static void StoreChainingValueWord(
        Vector256<uint> lane,
        Span<uint> scratch,
        Span<byte> eightChainingValues,
        int wordIndex)
    {
        lane.CopyTo(scratch);
        for(int chunkIndex = 0; chunkIndex < ManyChunksBatchSize; chunkIndex++)
        {
            int byteOffset =
                chunkIndex * Blake3Constants.OutputLength
                + wordIndex * Blake3Constants.WordSizeBytes;
            BinaryPrimitives.WriteUInt32LittleEndian(
                eightChainingValues.Slice(start: byteOffset, length: Blake3Constants.WordSizeBytes),
                scratch[chunkIndex]);
        }
    }


    /// <summary>
    /// Single BLAKE3 round: four column-mixing G calls followed by
    /// four diagonal-mixing G calls. Inlined into the seven-round
    /// loop in <see cref="CompressEightChunks"/> so the JIT can keep
    /// the sixteen state vectors and sixteen message vectors in
    /// registers rather than spilling at every call boundary.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round(
        ref Vector256<uint> s0, ref Vector256<uint> s1, ref Vector256<uint> s2, ref Vector256<uint> s3,
        ref Vector256<uint> s4, ref Vector256<uint> s5, ref Vector256<uint> s6, ref Vector256<uint> s7,
        ref Vector256<uint> s8, ref Vector256<uint> s9, ref Vector256<uint> s10, ref Vector256<uint> s11,
        ref Vector256<uint> s12, ref Vector256<uint> s13, ref Vector256<uint> s14, ref Vector256<uint> s15,
        Vector256<uint> m0, Vector256<uint> m1, Vector256<uint> m2, Vector256<uint> m3,
        Vector256<uint> m4, Vector256<uint> m5, Vector256<uint> m6, Vector256<uint> m7,
        Vector256<uint> m8, Vector256<uint> m9, Vector256<uint> m10, Vector256<uint> m11,
        Vector256<uint> m12, Vector256<uint> m13, Vector256<uint> m14, Vector256<uint> m15)
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


    /// <summary>The G mixing function, operating lane-wise on <see cref="Vector256{T}"/>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G(
        ref Vector256<uint> a,
        ref Vector256<uint> b,
        ref Vector256<uint> c,
        ref Vector256<uint> d,
        Vector256<uint> mx,
        Vector256<uint> my)
    {
        a = Avx2.Add(Avx2.Add(a, b), mx);
        d = RotateRight16(Avx2.Xor(d, a));
        c = Avx2.Add(c, d);
        b = RotateRight12(Avx2.Xor(b, c));
        a = Avx2.Add(Avx2.Add(a, b), my);
        d = RotateRight8(Avx2.Xor(d, a));
        c = Avx2.Add(c, d);
        b = RotateRight7(Avx2.Xor(b, c));
    }


    /// <summary>Rotate-right by 16 — byte shuffle within each 32-bit lane.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotateRight16(Vector256<uint> x) =>
        Avx2.Shuffle(x.AsByte(), RotateRight16ShuffleMask).AsUInt32();


    /// <summary>Rotate-right by 8 — byte shuffle within each 32-bit lane.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotateRight8(Vector256<uint> x) =>
        Avx2.Shuffle(x.AsByte(), RotateRight8ShuffleMask).AsUInt32();


    /// <summary>Rotate-right by 12 — shift-or composition; AVX2 has no native 32-bit rotate.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotateRight12(Vector256<uint> x) =>
        Avx2.Or(Avx2.ShiftRightLogical(x, 12), Avx2.ShiftLeftLogical(x, 20));


    /// <summary>Rotate-right by 7 — shift-or composition; AVX2 has no native 32-bit rotate.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> RotateRight7(Vector256<uint> x) =>
        Avx2.Or(Avx2.ShiftRightLogical(x, 7), Avx2.ShiftLeftLogical(x, 25));


    /// <summary>
    /// Byte-shuffle mask for the 16-bit rotation within each 32-bit
    /// lane: bytes [a,b,c,d] become [c,d,a,b].
    /// </summary>
    private static readonly Vector256<byte> RotateRight16ShuffleMask =
        Vector256.Create<byte>(
        [
            2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
            2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
        ]);


    /// <summary>
    /// Byte-shuffle mask for the 8-bit rotation within each 32-bit
    /// lane: bytes [a,b,c,d] become [b,c,d,a].
    /// </summary>
    private static readonly Vector256<byte> RotateRight8ShuffleMask =
        Vector256.Create<byte>(
        [
            1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
            1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
        ]);


    /// <summary>
    /// Applies the BLAKE3 message permutation in-place to the sixteen
    /// message-word vectors. The permutation table is
    /// <c>[2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]</c>:
    /// new <c>m[i] = old m[perm[i]]</c>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void PermuteMessage(
        ref Vector256<uint> m0, ref Vector256<uint> m1, ref Vector256<uint> m2, ref Vector256<uint> m3,
        ref Vector256<uint> m4, ref Vector256<uint> m5, ref Vector256<uint> m6, ref Vector256<uint> m7,
        ref Vector256<uint> m8, ref Vector256<uint> m9, ref Vector256<uint> m10, ref Vector256<uint> m11,
        ref Vector256<uint> m12, ref Vector256<uint> m13, ref Vector256<uint> m14, ref Vector256<uint> m15)
    {
        Vector256<uint> n0 = m2;
        Vector256<uint> n1 = m6;
        Vector256<uint> n2 = m3;
        Vector256<uint> n3 = m10;
        Vector256<uint> n4 = m7;
        Vector256<uint> n5 = m0;
        Vector256<uint> n6 = m4;
        Vector256<uint> n7 = m13;
        Vector256<uint> n8 = m1;
        Vector256<uint> n9 = m11;
        Vector256<uint> n10 = m12;
        Vector256<uint> n11 = m5;
        Vector256<uint> n12 = m9;
        Vector256<uint> n13 = m14;
        Vector256<uint> n14 = m15;
        Vector256<uint> n15 = m8;

        m0 = n0; m1 = n1; m2 = n2; m3 = n3;
        m4 = n4; m5 = n5; m6 = n6; m7 = n7;
        m8 = n8; m9 = n9; m10 = n10; m11 = n11;
        m12 = n12; m13 = n13; m14 = n14; m15 = n15;
    }
}