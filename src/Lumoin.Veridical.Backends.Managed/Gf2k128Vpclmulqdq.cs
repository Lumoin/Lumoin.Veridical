using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The AVX-512 VPCLMULQDQ four-element kernels behind the regular-shape batch
/// loops of <see cref="Gf2k128BatchBackend"/>: each 128-bit lane of a
/// <see cref="Vector512{T}"/> holds one GF(2^128) element as the
/// <c>(low, high)</c> qword pair, so the four 64×64 carry-less halves of four
/// independent products cost four VPCLMULQDQ instructions (immediates
/// <c>0x00</c>, <c>0x10</c>, <c>0x01</c>, <c>0x11</c>) instead of sixteen
/// serial PCLMULQDQ.
/// </summary>
/// <remarks>
/// Carry-less multiplication and XOR are exact, and the lane arithmetic —
/// the three-lane unreduced accumulator and the two-stage <c>0x87</c> fold —
/// composes the identical operations in the identical order as the scalar
/// path, so the wide kernels are byte-identical by construction; the
/// agreement tests gate that on VPCLMULQDQ hardware. The irregular-access
/// shapes (gather runs, the bind-quad chain) stay on the scalar path.
/// </remarks>
internal static class Gf2k128Vpclmulqdq
{
    private const int ScalarSize = 32;

    /// <summary>The number of GF(2^128) elements one 512-bit kernel pass handles.</summary>
    public const int WideElementCount = 4;

    /// <summary>
    /// The reduction constant <c>0x87</c> in each lane's low qword; the carry
    /// multiply selects it with <c>imm8[4] = 0</c>.
    /// </summary>
    private static Vector512<ulong> ReductionPolynomial { get; } =
        Vector512.Create(0x87UL, 0UL, 0x87UL, 0UL, 0x87UL, 0UL, 0x87UL, 0UL);


    /// <summary>Whether the AVX-512 foundation, the 512-bit carry-less multiply and the per-lane byte shift are all available.</summary>
    public static bool IsSupported => Avx512F.IsSupported && Pclmulqdq.V512.IsSupported && Avx512BW.IsSupported;


    /// <summary>
    /// Multiplies full four-element groups (<c>results[i] = left[i]·right[i]</c>)
    /// and returns the element count consumed; the caller's scalar loop takes
    /// the tail.
    /// </summary>
    /// <param name="leftOperandsConcatenated">The left operands, canonical 32-byte slots.</param>
    /// <param name="rightOperandsConcatenated">The right operands, canonical 32-byte slots.</param>
    /// <param name="resultsConcatenated">Receives the reduced products.</param>
    /// <param name="count">The total element count of the batch.</param>
    /// <returns>The number of elements handled here: <c>count</c> rounded down to a multiple of four.</returns>
    public static int BatchMultiply(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count)
    {
        int wideCount = count & ~(WideElementCount - 1);
        for(int group = 0; group < wideCount; group += WideElementCount)
        {
            Vector512<ulong> left = LoadGroup(leftOperandsConcatenated, group);
            Vector512<ulong> right = LoadGroup(rightOperandsConcatenated, group);
            StoreGroup(MultiplyReduce(left, right), resultsConcatenated, group);
        }

        return wideCount;
    }


    /// <summary>
    /// Fused multiply-accumulate over full four-element groups
    /// (<c>acc[i] ^= left[i]·right[i]</c>, or overwrite) and returns the
    /// element count consumed.
    /// </summary>
    /// <param name="leftOperandsConcatenated">The left operands, canonical 32-byte slots.</param>
    /// <param name="rightOperandsConcatenated">The right operands, canonical 32-byte slots.</param>
    /// <param name="accumulatorsConcatenated">The accumulator slots, read-modify-written when <paramref name="accumulate"/> is set.</param>
    /// <param name="accumulate">Whether to XOR into the existing slots instead of overwriting.</param>
    /// <param name="count">The total element count of the batch.</param>
    /// <returns>The number of elements handled here.</returns>
    public static int BatchMultiplyAccumulate(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> accumulatorsConcatenated,
        bool accumulate,
        int count)
    {
        int wideCount = count & ~(WideElementCount - 1);
        for(int group = 0; group < wideCount; group += WideElementCount)
        {
            Vector512<ulong> left = LoadGroup(leftOperandsConcatenated, group);
            Vector512<ulong> right = LoadGroup(rightOperandsConcatenated, group);
            Vector512<ulong> product = MultiplyReduce(left, right);
            if(accumulate)
            {
                product ^= LoadGroup(accumulatorsConcatenated, group);
            }

            StoreGroup(product, accumulatorsConcatenated, group);
        }

        return wideCount;
    }


    /// <summary>
    /// Broadcast fused multiply-accumulate over full four-element groups
    /// (<c>acc[i] ^= scalar·operand[i]</c>, or overwrite) and returns the
    /// element count consumed.
    /// </summary>
    /// <param name="scalarHigh">The broadcast multiplier's high limb.</param>
    /// <param name="scalarLow">The broadcast multiplier's low limb.</param>
    /// <param name="operandsConcatenated">The operands, canonical 32-byte slots.</param>
    /// <param name="accumulatorsConcatenated">The accumulator slots.</param>
    /// <param name="accumulate">Whether to XOR into the existing slots instead of overwriting.</param>
    /// <param name="count">The total element count of the batch.</param>
    /// <returns>The number of elements handled here.</returns>
    public static int BroadcastMultiplyAccumulate(
        ulong scalarHigh,
        ulong scalarLow,
        ReadOnlySpan<byte> operandsConcatenated,
        Span<byte> accumulatorsConcatenated,
        bool accumulate,
        int count)
    {
        Vector512<ulong> scalar = Vector512.Create(scalarLow, scalarHigh, scalarLow, scalarHigh, scalarLow, scalarHigh, scalarLow, scalarHigh);
        int wideCount = count & ~(WideElementCount - 1);
        for(int group = 0; group < wideCount; group += WideElementCount)
        {
            Vector512<ulong> operands = LoadGroup(operandsConcatenated, group);
            Vector512<ulong> product = MultiplyReduce(scalar, operands);
            if(accumulate)
            {
                product ^= LoadGroup(accumulatorsConcatenated, group);
            }

            StoreGroup(product, accumulatorsConcatenated, group);
        }

        return wideCount;
    }


    /// <summary>
    /// LCH14 forward butterflies over full four-element groups
    /// (<c>low ^= twiddle·high; high ^= low</c>) and returns the element count
    /// consumed.
    /// </summary>
    /// <param name="twiddleHigh">The broadcast twiddle's high limb.</param>
    /// <param name="twiddleLow">The broadcast twiddle's low limb.</param>
    /// <param name="lowConcatenated">The low half of the butterfly group.</param>
    /// <param name="highConcatenated">The high half of the butterfly group.</param>
    /// <param name="stride">The total element count of each half.</param>
    /// <returns>The number of elements handled here.</returns>
    public static int ButterflyBatch(
        ulong twiddleHigh,
        ulong twiddleLow,
        Span<byte> lowConcatenated,
        Span<byte> highConcatenated,
        int stride)
    {
        Vector512<ulong> twiddle = Vector512.Create(twiddleLow, twiddleHigh, twiddleLow, twiddleHigh, twiddleLow, twiddleHigh, twiddleLow, twiddleHigh);
        int wideCount = stride & ~(WideElementCount - 1);
        for(int group = 0; group < wideCount; group += WideElementCount)
        {
            Vector512<ulong> low = LoadGroup(lowConcatenated, group);
            Vector512<ulong> high = LoadGroup(highConcatenated, group);

            Vector512<ulong> newLow = low ^ MultiplyReduce(twiddle, high);
            Vector512<ulong> newHigh = high ^ newLow;

            StoreGroup(newLow, lowConcatenated, group);
            StoreGroup(newHigh, highConcatenated, group);
        }

        return wideCount;
    }


    /// <summary>
    /// Four reduced GF(2^128) products at once: the four carry-less halves per
    /// element via one VPCLMULQDQ each (<c>imm8[0]</c> selects the left
    /// operand's qword, <c>imm8[4]</c> the right's), XOR-folded through the
    /// same three-lane accumulator and two-stage <c>0x87</c> reduction as the
    /// scalar path.
    /// </summary>
    /// <param name="left">Four left operands, one per 128-bit lane as <c>(low, high)</c> qwords.</param>
    /// <param name="right">Four right operands in the same lane layout.</param>
    /// <returns>The four reduced products, lane-aligned with the inputs.</returns>
    private static Vector512<ulong> MultiplyReduce(Vector512<ulong> left, Vector512<ulong> right)
    {
        Vector512<ulong> lane0 = Pclmulqdq.V512.CarrylessMultiply(left, right, 0x00);
        Vector512<ulong> lane1 = Pclmulqdq.V512.CarrylessMultiply(left, right, 0x10)
            ^ Pclmulqdq.V512.CarrylessMultiply(left, right, 0x01);
        Vector512<ulong> lane2 = Pclmulqdq.V512.CarrylessMultiply(left, right, 0x11);

        Vector512<ulong> middle = Reduce(lane1, lane2);

        return Reduce(lane0, middle);
    }


    /// <summary>
    /// The per-lane image of the scalar reduce: <c>carry = clmul(high qword of
    /// highValue, 0x87)</c>; shifting each lane left by eight bytes moves the
    /// low qword to the high position; lane qword0 becomes
    /// <c>lowLow ^ carryLow</c> and qword1 <c>lowHigh ^ highLow ^ carryHigh</c>
    /// — exactly the scalar fold.
    /// </summary>
    /// <param name="lowValue">Four 128-bit values of weight one.</param>
    /// <param name="highValue">Four 128-bit values of weight <c>x^64</c>.</param>
    /// <returns>The four folded values, lane-aligned with the inputs.</returns>
    private static Vector512<ulong> Reduce(Vector512<ulong> lowValue, Vector512<ulong> highValue)
    {
        Vector512<ulong> carry = Pclmulqdq.V512.CarrylessMultiply(highValue, ReductionPolynomial, 0x01);
        Vector512<ulong> shifted = Avx512BW.ShiftLeftLogical128BitLane(highValue.AsByte(), 8).AsUInt64();

        return lowValue ^ shifted ^ carry;
    }


    /// <summary>
    /// Unpacks four consecutive canonical slots into lanes of <c>(low, high)</c>
    /// qwords; the big-endian slot conversion stays per element.
    /// </summary>
    /// <param name="slots">The concatenated canonical 32-byte slots.</param>
    /// <param name="firstElementIndex">The element index of the group's first slot.</param>
    /// <returns>The four elements as 128-bit lanes.</returns>
    private static Vector512<ulong> LoadGroup(ReadOnlySpan<byte> slots, int firstElementIndex)
    {
        (ulong high0, ulong low0) = Gf2k128BatchBackend.Unpack(slots.Slice(firstElementIndex * ScalarSize, ScalarSize));
        (ulong high1, ulong low1) = Gf2k128BatchBackend.Unpack(slots.Slice((firstElementIndex + 1) * ScalarSize, ScalarSize));
        (ulong high2, ulong low2) = Gf2k128BatchBackend.Unpack(slots.Slice((firstElementIndex + 2) * ScalarSize, ScalarSize));
        (ulong high3, ulong low3) = Gf2k128BatchBackend.Unpack(slots.Slice((firstElementIndex + 3) * ScalarSize, ScalarSize));

        return Vector512.Create(low0, high0, low1, high1, low2, high2, low3, high3);
    }


    /// <summary>
    /// Packs the four 128-bit lanes back into four consecutive canonical
    /// 32-byte big-endian slots.
    /// </summary>
    /// <param name="lanes">The four elements as 128-bit lanes.</param>
    /// <param name="slots">The concatenated canonical 32-byte slots to write.</param>
    /// <param name="firstElementIndex">The element index of the group's first slot.</param>
    private static void StoreGroup(Vector512<ulong> lanes, Span<byte> slots, int firstElementIndex)
    {
        for(int i = 0; i < WideElementCount; i++)
        {
            Gf2k128BatchBackend.Pack(
                lanes.GetElement((2 * i) + 1),
                lanes.GetElement(2 * i),
                slots.Slice((firstElementIndex + i) * ScalarSize, ScalarSize));
        }
    }
}
