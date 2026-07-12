using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Fuzzing;

/// <summary>
/// A deterministic, seed-indexed mutation generator over a byte buffer. There is no
/// randomness anywhere in this type: the same <c>(seed, index)</c> pair always produces
/// the same mutated bytes, so a fuzz finding recorded from an index is reproducible by
/// replaying that index against the same seed.
/// </summary>
/// <remarks>
/// The sweep is partitioned into named families (bit flips, byte pins, truncation,
/// extension, header-window fills, length-field tampering); <see cref="Mutate"/>
/// dispatches an index into exactly one family and one variant within it, so the whole
/// <c>[0, MutationCount)</c> range is a fixed, enumerable catalogue of hostile
/// transformations rather than a probabilistic search.
/// </remarks>
internal static class DeterministicMutations
{
    //A byte is 8 bits; used to convert a bit-walk index into a byte/bit-in-byte pair.
    private const int BitsPerByte = 8;

    //Covers bit positions across the first 128 bytes of a seed (128 * BitsPerByte), deep
    //enough to reach not just the outermost framing (magic, version, section counters) but
    //the fixed-offset count/length fields nested inside a format's first header record
    //(for example a Circom .r1cs header's nWires/nConstraints, which sit past byte 32).
    private const int BitFlipCount = 1024;

    //Enough spread positions to touch header, middle, and tail bytes of a typical
    //fixture-sized seed without becoming a per-byte exhaustive sweep.
    private const int ZeroByteCount = 24;
    private const int FillByteCount = 24;

    //One variant per candidate truncated length in TruncationLengths.
    private const int TruncationCount = 16;

    //One variant per candidate appended-byte count in ExtensionLengths, once for each
    //fill value (0x00 and 0xFF).
    private const int ExtendZeroCount = 8;
    private const int ExtendFillCount = 8;

    //One variant per (window size in HeaderWindowSizes) x (fill value: 0x00, 0xFF).
    private const int HeaderWindowCount = 6;

    //One variant per (4-byte window offset in LengthFieldOffsets) x (tamper mode). The
    //offsets stride every 4 bytes across the first 256 bytes (LengthFieldOffsetStrideCount
    //entries) so a fixed-position count/length field nested anywhere in a format's leading
    //header record — not just its outermost framing — gets tampered directly.
    private const int TamperModeCount = 3;
    private const int LengthFieldOffsetStrideCount = 64;
    private const int LengthFieldOffsetStrideBytes = sizeof(uint);
    private const int LengthFieldTamperCount = LengthFieldOffsetStrideCount * TamperModeCount;

    /// <summary>The total number of distinct, index-addressable mutations the sweep covers.</summary>
    public const int MutationCount =
        BitFlipCount + ZeroByteCount + FillByteCount + TruncationCount +
        ExtendZeroCount + ExtendFillCount + HeaderWindowCount + LengthFieldTamperCount;

    //A huge-but-bounded standalone input: large enough to exercise length-overrun
    //rejection paths without exhausting memory or time in a test run.
    private const int HugeButBoundedLengthBytes = 1 << 16;

    private static readonly int[] TruncationLengths =
    [
        0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192
    ];

    private static readonly int[] ExtensionLengths = [1, 2, 4, 8, 16, 32, 64, 128];

    private static readonly int[] HeaderWindowSizes = [4, 8, 16];

    private static readonly int[] LengthFieldOffsets = BuildLengthFieldOffsets();


    /// <summary>
    /// Produces the mutation at <paramref name="index"/> (in <c>[0, MutationCount)</c>)
    /// applied to <paramref name="seed"/>. Every mutation returns a fresh, independent
    /// buffer; the family boundaries are fixed, so a given index always names the same
    /// family and variant regardless of seed contents.
    /// </summary>
    public static byte[] Mutate(ReadOnlySpan<byte> seed, int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, MutationCount);

        int cursor = index;

        if(cursor < BitFlipCount)
        {
            return FlipBit(seed, cursor);
        }

        cursor -= BitFlipCount;

        if(cursor < ZeroByteCount)
        {
            return SetByte(seed, cursor, ZeroByteCount, 0x00);
        }

        cursor -= ZeroByteCount;

        if(cursor < FillByteCount)
        {
            return SetByte(seed, cursor, FillByteCount, 0xFF);
        }

        cursor -= FillByteCount;

        if(cursor < TruncationCount)
        {
            return Truncate(seed, cursor);
        }

        cursor -= TruncationCount;

        if(cursor < ExtendZeroCount)
        {
            return Extend(seed, cursor, 0x00);
        }

        cursor -= ExtendZeroCount;

        if(cursor < ExtendFillCount)
        {
            return Extend(seed, cursor, 0xFF);
        }

        cursor -= ExtendFillCount;

        if(cursor < HeaderWindowCount)
        {
            return TamperHeaderWindow(seed, cursor);
        }

        cursor -= HeaderWindowCount;

        return TamperLengthField(seed, cursor);
    }


    /// <summary>
    /// Fixed pathological standalone inputs for decoders with no natural seed corpus:
    /// empty, one byte, all-zero and all-0xFF buffers of <paramref name="lengthHint"/>
    /// bytes, and a huge-but-bounded all-zero buffer.
    /// </summary>
    public static IEnumerable<byte[]> EdgeCaseInputs(int lengthHint)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(lengthHint);

        yield return [];
        yield return [0x00];
        yield return new byte[lengthHint];

        byte[] allFill = new byte[lengthHint];
        allFill.AsSpan().Fill(0xFF);
        yield return allFill;

        yield return new byte[HugeButBoundedLengthBytes];
    }


    private static byte[] FlipBit(ReadOnlySpan<byte> seed, int localIndex)
    {
        byte[] mutated = seed.ToArray();
        if(mutated.Length == 0)
        {
            return mutated;
        }

        int bitPosition = localIndex % (mutated.Length * BitsPerByte);
        int byteIndex = bitPosition / BitsPerByte;
        int bitInByte = bitPosition % BitsPerByte;
        mutated[byteIndex] ^= (byte)(1 << bitInByte);

        return mutated;
    }


    private static byte[] SetByte(ReadOnlySpan<byte> seed, int localIndex, int familyCount, byte value)
    {
        byte[] mutated = seed.ToArray();
        if(mutated.Length == 0)
        {
            return mutated;
        }

        //Spread positions across the whole buffer rather than clustering near the front.
        int stride = Math.Max(1, mutated.Length / familyCount);
        int position = (localIndex * stride) % mutated.Length;
        mutated[position] = value;

        return mutated;
    }


    private static byte[] Truncate(ReadOnlySpan<byte> seed, int localIndex)
    {
        int requestedLength = TruncationLengths[localIndex % TruncationLengths.Length];
        int length = Math.Min(requestedLength, seed.Length);

        return seed[..length].ToArray();
    }


    private static byte[] Extend(ReadOnlySpan<byte> seed, int localIndex, byte fillByte)
    {
        int appended = ExtensionLengths[localIndex % ExtensionLengths.Length];
        byte[] mutated = new byte[seed.Length + appended];
        seed.CopyTo(mutated);
        mutated.AsSpan(seed.Length).Fill(fillByte);

        return mutated;
    }


    private static byte[] TamperHeaderWindow(ReadOnlySpan<byte> seed, int localIndex)
    {
        int sizeIndex = localIndex / 2;
        byte fillByte = localIndex % 2 == 0 ? (byte)0x00 : (byte)0xFF;
        int windowSize = Math.Min(HeaderWindowSizes[sizeIndex % HeaderWindowSizes.Length], seed.Length);

        byte[] mutated = seed.ToArray();
        mutated.AsSpan(0, windowSize).Fill(fillByte);

        return mutated;
    }


    private static byte[] TamperLengthField(ReadOnlySpan<byte> seed, int localIndex)
    {
        byte[] mutated = seed.ToArray();
        if(mutated.Length < sizeof(uint))
        {
            return mutated;
        }

        int offsetIndex = localIndex / TamperModeCount;
        var mode = (LengthFieldTamperMode)(localIndex % TamperModeCount);
        int offset = LengthFieldOffsets[offsetIndex % LengthFieldOffsets.Length];
        if(offset + sizeof(uint) > mutated.Length)
        {
            offset = mutated.Length - sizeof(uint);
        }

        Span<byte> window = mutated.AsSpan(offset, sizeof(uint));
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(window);
        uint tampered = mode switch
        {
            LengthFieldTamperMode.Increment => value + 1,
            LengthFieldTamperMode.Decrement => value - 1,
            LengthFieldTamperMode.SetHuge => uint.MaxValue,
            _ => value,
        };

        BinaryPrimitives.WriteUInt32LittleEndian(window, tampered);

        return mutated;
    }


    private static int[] BuildLengthFieldOffsets()
    {
        var offsets = new int[LengthFieldOffsetStrideCount];
        for(int i = 0; i < offsets.Length; i++)
        {
            offsets[i] = i * LengthFieldOffsetStrideBytes;
        }

        return offsets;
    }


    private enum LengthFieldTamperMode
    {
        Increment,
        Decrement,
        SetHuge,
    }
}
