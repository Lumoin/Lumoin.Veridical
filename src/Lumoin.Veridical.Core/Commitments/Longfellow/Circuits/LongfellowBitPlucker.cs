using System;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// Maps a field element known to lie in a set of <c>2^LOGN</c> distinguished points to
/// <c>LOGN</c> bit wires, a faithful port of google/longfellow-zk's <c>BitPlucker&lt;Logic,
/// LOGN&gt;</c> (<c>circuits/logic/bit_plucker.h</c>): each output bit is its own interpolated
/// polynomial of the packed element, evaluated in the circuit and asserted to be genuinely a bit.
/// Packing several bits into one field element this way trades interpolation and evaluation cost for
/// fewer witness inputs, worthwhile whenever the field needs far more bits to represent than the
/// quantity being packed does.
/// </summary>
/// <remarks>
/// <see cref="PluckerPoint"/> is the reference's free <c>bit_plucker_point&lt;Field, N&gt;</c> functor,
/// shared here as a public static method so <see cref="LongfellowBitPluckerEncoder"/> (the witness-side
/// counterpart, which has no <see cref="LongfellowLogic"/> gadget layer to build on) computes the exact
/// same evaluation points without duplicating the formula.
/// </remarks>
internal sealed class LongfellowBitPlucker
{
    private readonly LongfellowLogic logic;
    private readonly LongfellowLogicBackend backend;
    private readonly LongfellowLogicFieldOperations field;
    private readonly LongfellowCircuitPolynomial polynomial;
    private readonly ReadOnlyMemory<byte>[][] pluckerPolynomials;

    /// <summary>The bit width <c>LOGN</c> this plucker extracts (the reference's template parameter).</summary>
    public int LogPointCount { get; }

    /// <summary>The point count <c>kN = 2^LOGN</c> the packed field element is drawn from.</summary>
    public int PointCount { get; }

    /// <summary>The packed element count for a 32-bit quantity (the reference's <c>kNv32Elts</c>).</summary>
    public int PackedV32ElementCount { get; }

    /// <summary>The packed element count for a 128-bit quantity (the reference's <c>kNv128Elts</c>).</summary>
    public int PackedV128ElementCount { get; }

    /// <summary>The packed element count for a 256-bit quantity (the reference's <c>kNv256Elts</c>).</summary>
    public int PackedV256ElementCount { get; }


    /// <summary>
    /// Constructs the plucker over a bit width, interpolating <see cref="LogPointCount"/> polynomials
    /// at construction time: for output bit <c>k</c>, the unique polynomial through
    /// <c>(PluckerPoint(i), OfScalar((i &gt;&gt; k) &amp; 1))</c> for every <c>i &lt; PointCount</c>.
    /// </summary>
    /// <param name="logic">The gadget layer this plucker builds on.</param>
    /// <param name="logPointCount">The bit width <c>LOGN</c>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="logPointCount"/> is not positive.</exception>
    public LongfellowBitPlucker(LongfellowLogic logic, int logPointCount)
    {
        ArgumentNullException.ThrowIfNull(logic);
        ArgumentOutOfRangeException.ThrowIfLessThan(logPointCount, 1);

        //The reference instantiates pluckers only up to eight packed bits, and the construction-time
        //interpolation grows as the square of the point count; the cap keeps a hostile width from
        //driving an unbounded allocation.
        const int MaxLogPointCount = 8;
        ArgumentOutOfRangeException.ThrowIfGreaterThan(logPointCount, MaxLogPointCount);

        this.logic = logic;
        backend = logic.Backend;
        field = logic.Field;
        polynomial = new LongfellowCircuitPolynomial(backend);

        LogPointCount = logPointCount;
        PointCount = 1 << logPointCount;

        const int PackedV32BitWidth = 32;
        const int PackedV128BitWidth = 128;
        const int PackedV256BitWidth = 256;

        PackedV32ElementCount = CeilingDivide(PackedV32BitWidth, logPointCount);
        PackedV128ElementCount = CeilingDivide(PackedV128BitWidth, logPointCount);
        PackedV256ElementCount = CeilingDivide(PackedV256BitWidth, logPointCount);

        var points = new ReadOnlyMemory<byte>[PointCount];
        for(int i = 0; i < PointCount; i++)
        {
            points[i] = PluckerPoint(field, PointCount, i);
        }

        pluckerPolynomials = new ReadOnlyMemory<byte>[logPointCount][];
        for(int k = 0; k < logPointCount; k++)
        {
            var values = new ReadOnlyMemory<byte>[PointCount];
            for(int i = 0; i < PointCount; i++)
            {
                values[i] = field.OfScalar((ulong)((i >> k) & 1));
            }

            pluckerPolynomials[k] = LongfellowMonomialInterpolation.MonomialOfLagrange(field, values, points);
        }
    }


    /// <summary>
    /// The reference's <c>bit_plucker_point&lt;Field, N&gt;</c>: the evaluation point standing for the
    /// packed value <paramref name="bits"/> among <paramref name="pointCount"/> points, computed as
    /// <c>OfScalar(2·bits) − OfScalar(pointCount − 1)</c> entirely through the field's own operations.
    /// Over a characteristic-two field <see cref="LongfellowLogicFieldOperations.OfScalar"/> is the
    /// beta-basis map and subtraction is addition, so no characteristic-specific branch is needed here.
    /// </summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="pointCount">The total point count the packed value is drawn from.</param>
    /// <param name="bits">The packed value.</param>
    /// <returns>The evaluation point, canonical big-endian.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="field"/> is <see langword="null"/>.</exception>
    public static ReadOnlyMemory<byte> PluckerPoint(LongfellowLogicFieldOperations field, int pointCount, int bits)
    {
        ArgumentNullException.ThrowIfNull(field);

        ReadOnlyMemory<byte> doubled = field.OfScalar(2UL * (ulong)bits);
        ReadOnlyMemory<byte> offset = field.OfScalar((ulong)(pointCount - 1));

        var difference = new byte[Scalar.SizeBytes];
        field.Subtract(doubled.Span, offset.Span, difference, field.Compiler.Curve);

        return difference;
    }


    /// <summary>
    /// The reference's <c>pluck</c>: extracts the <see cref="LogPointCount"/> bits packed into
    /// <paramref name="wire"/>, evaluating each interpolated polynomial via
    /// <see cref="LongfellowCircuitPolynomial.Evaluate"/> (never <see cref="LongfellowCircuitPolynomial.EvaluateHorner"/>)
    /// and asserting every result is genuinely a bit.
    /// </summary>
    /// <param name="wire">The wire holding the packed field element.</param>
    /// <returns>The extracted bit vector, <see cref="LogPointCount"/> bits, least significant first.</returns>
    public LongfellowBitWire[] Pluck(int wire)
    {
        var result = new LongfellowBitWire[LogPointCount];
        for(int k = 0; k < LogPointCount; k++)
        {
            int v = polynomial.Evaluate(pluckerPolynomials[k], wire);
            _ = logic.AssertIsBit(v);
            result[k] = new LongfellowBitWire(field, v);
        }

        return result;
    }


    /// <summary>The reference's <c>unpack_v32</c>: <see cref="Unpack"/> specialized to a 32-bit destination.</summary>
    /// <param name="packed">The packed wires, <see cref="PackedV32ElementCount"/> of them.</param>
    /// <returns>The unpacked 32-bit vector.</returns>
    public LongfellowBitWire[] UnpackV32(int[] packed) => Unpack(packed, LongfellowLogic.BitWidth32);


    /// <summary>
    /// The reference's generic <c>unpack</c>: plucks every packed wire in order and scatters its bits
    /// into a destination of <paramref name="width"/> bits, dropping any bits beyond
    /// <paramref name="width"/> that the last packed element's plucked bits would otherwise overrun.
    /// </summary>
    /// <param name="packed">The packed wires, exactly the ceiling of <paramref name="width"/> over <see cref="LogPointCount"/> of them.</param>
    /// <param name="width">The destination bit width.</param>
    /// <returns>The unpacked bit vector, <paramref name="width"/> bits, least significant first.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="packed"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="width"/> is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="packed"/>'s length does not cover <paramref name="width"/> exactly; a shorter array would silently leave trailing destination bits as trap values.</exception>
    public LongfellowBitWire[] Unpack(int[] packed, int width)
    {
        ArgumentNullException.ThrowIfNull(packed);
        ArgumentOutOfRangeException.ThrowIfNegative(width);

        if(packed.Length != CeilingDivide(width, LogPointCount))
        {
            throw new ArgumentException($"Unpacking {width} bits at {LogPointCount} bits per element needs exactly {CeilingDivide(width, LogPointCount)} packed elements.", nameof(packed));
        }

        var result = new LongfellowBitWire[width];
        for(int i = 0; i < packed.Length; i++)
        {
            LongfellowBitWire[] plucked = Pluck(packed[i]);
            for(int j = 0; j < LogPointCount; j++)
            {
                if((LogPointCount * i) + j < width)
                {
                    result[(LogPointCount * i) + j] = plucked[j];
                }
            }
        }

        return result;
    }


    /// <summary>
    /// The reference's <c>packed_input</c>: declares <paramref name="elementCount"/> witness wires with
    /// no bitness assertion, the bitness instead following from <see cref="Pluck"/>'s own
    /// <see cref="LongfellowLogic.AssertIsBit(int)"/> on each extracted bit.
    /// </summary>
    /// <param name="elementCount">The number of packed input wires to declare.</param>
    /// <returns>The declared wires.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="elementCount"/> is negative.</exception>
    public int[] PackedInput(int elementCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(elementCount);

        var result = new int[elementCount];
        for(int i = 0; i < elementCount; i++)
        {
            result[i] = logic.InputElement();
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
