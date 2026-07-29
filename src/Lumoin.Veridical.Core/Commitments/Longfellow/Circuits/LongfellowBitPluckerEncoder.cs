using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The witness-side counterpart to <see cref="LongfellowBitPlucker"/>, a faithful port of
/// google/longfellow-zk's <c>BitPluckerEncoder&lt;Field, LOGN&gt;</c>
/// (<c>circuits/logic/bit_plucker_encoder.h</c>): computes the same evaluation points the in-circuit
/// plucker interpolates over, out of circuit, so a witness filler can produce the packed field-element
/// inputs the compiled circuit later plucks bits back out of.
/// </summary>
/// <remarks>
/// Field-only: unlike <see cref="LongfellowBitPlucker"/> this needs no <see cref="LongfellowLogic"/>
/// gadget layer or backend, since every member here runs out of circuit over raw field constants; it
/// shares <see cref="LongfellowBitPlucker.PluckerPoint"/> with the circuit side rather than
/// re-deriving the same formula.
/// </remarks>
internal sealed class LongfellowBitPluckerEncoder
{
    private readonly LongfellowLogicFieldOperations field;

    /// <summary>The bit width <c>LOGN</c> this encoder packs (matching a paired <see cref="LongfellowBitPlucker"/>'s <see cref="LongfellowBitPlucker.LogPointCount"/>).</summary>
    public int LogPointCount { get; }

    /// <summary>The point count <c>kN = 2^LOGN</c>.</summary>
    public int PointCount { get; }

    /// <summary>The packed element count for a 32-bit quantity (the reference's <c>kNv32Elts</c>).</summary>
    public int PackedV32ElementCount { get; }

    /// <summary>The packed element count for a 128-bit quantity (the reference's <c>kNv128Elts</c>).</summary>
    public int PackedV128ElementCount { get; }

    /// <summary>The packed element count for a 256-bit quantity (the reference's <c>kNv256Elts</c>).</summary>
    public int PackedV256ElementCount { get; }


    /// <summary>
    /// Constructs the encoder over a field-operation bundle and a bit width.
    /// </summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="logPointCount">The bit width <c>LOGN</c>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="field"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="logPointCount"/> is not positive.</exception>
    public LongfellowBitPluckerEncoder(LongfellowLogicFieldOperations field, int logPointCount)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentOutOfRangeException.ThrowIfLessThan(logPointCount, 1);

        //The same cap as LongfellowBitPlucker: the reference never packs beyond eight bits per
        //element, and the point count doubles per step.
        const int MaxLogPointCount = 8;
        ArgumentOutOfRangeException.ThrowIfGreaterThan(logPointCount, MaxLogPointCount);

        this.field = field;
        LogPointCount = logPointCount;
        PointCount = 1 << logPointCount;

        const int PackedV32BitWidth = 32;
        const int PackedV128BitWidth = 128;
        const int PackedV256BitWidth = 256;

        PackedV32ElementCount = CeilingDivide(PackedV32BitWidth, logPointCount);
        PackedV128ElementCount = CeilingDivide(PackedV128BitWidth, logPointCount);
        PackedV256ElementCount = CeilingDivide(PackedV256BitWidth, logPointCount);
    }


    /// <summary>
    /// The reference's <c>encode</c>: the same evaluation point <see cref="LongfellowBitPlucker"/>
    /// interpolates its polynomials over, for a given packed value.
    /// </summary>
    /// <param name="index">The packed value, ordinarily <c>0 &lt;= index &lt; PointCount</c>.</param>
    /// <returns>The field element, canonical big-endian.</returns>
    public ReadOnlyMemory<byte> Encode(int index) => LongfellowBitPlucker.PluckerPoint(field, PointCount, index);


    /// <summary>
    /// The reference's <c>mkpacked_v32</c>: slices a 32-bit quantity into <see cref="LogPointCount"/>-bit
    /// groups, least significant first, and encodes each group as a point.
    /// </summary>
    /// <param name="value">The 32-bit quantity to pack.</param>
    /// <returns>The packed field elements, <see cref="PackedV32ElementCount"/> of them.</returns>
    public ReadOnlyMemory<byte>[] MakePackedV32(uint value)
    {
        var result = new ReadOnlyMemory<byte>[PackedV32ElementCount];
        uint remaining = value;
        for(int i = 0; i < PackedV32ElementCount; i++)
        {
            result[i] = Encode((int)(remaining & (uint)(PointCount - 1)));
            remaining >>= LogPointCount;
        }

        return result;
    }


    /// <summary>
    /// The reference's generic <c>pack</c>: slices the first <paramref name="bitCount"/> bits of
    /// <paramref name="bits"/> into <see cref="LogPointCount"/>-bit groups, least significant bit
    /// first within each group, and encodes each group as a point; a group whose bits run past
    /// <paramref name="bitCount"/> contributes zero for those missing positions.
    /// </summary>
    /// <param name="bits">The bit source, one byte per bit — the low bit of each byte is read.</param>
    /// <param name="bitCount">The number of leading bits of <paramref name="bits"/> to consider.</param>
    /// <param name="elementCount">The number of packed elements to produce.</param>
    /// <returns>The packed field elements, <paramref name="elementCount"/> of them.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="bitCount"/> or <paramref name="elementCount"/> is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bits"/> is shorter than <paramref name="bitCount"/>.</exception>
    public ReadOnlyMemory<byte>[] Pack(ReadOnlySpan<byte> bits, int bitCount, int elementCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bitCount);
        ArgumentOutOfRangeException.ThrowIfNegative(elementCount);

        if(bits.Length < bitCount)
        {
            throw new ArgumentException("The bit source needs at least bitCount bytes.", nameof(bits));
        }

        var result = new ReadOnlyMemory<byte>[elementCount];
        for(int i = 0; i < elementCount; i++)
        {
            int value = 0;
            for(int j = 0; j < LogPointCount; j++)
            {
                if((i * LogPointCount) + j < bitCount)
                {
                    value += (bits[(i * LogPointCount) + j] & 1) << j;
                }
            }

            result[i] = Encode(value);
        }

        return result;
    }


    /// <summary>The ceiling of <paramref name="numerator"/> divided by <paramref name="denominator"/> (the reference's inline <c>kNv32Elts</c>/<c>kNv128Elts</c>/<c>kNv256Elts</c> arithmetic).</summary>
    /// <param name="numerator">The numerator.</param>
    /// <param name="denominator">The denominator.</param>
    /// <returns>The ceiling quotient.</returns>
    private static int CeilingDivide(int numerator, int denominator)
    {
        return (numerator + denominator - 1) / denominator;
    }
}
