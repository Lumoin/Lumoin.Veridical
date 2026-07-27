using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// The LogUp-GKR per-layer sumcheck computation: one round's univariate
/// polynomial, in evaluation form at the integer points <c>0..3</c>, of the
/// batched layer identity
/// <c>P + λ·Q = Σ_y eq(r,y)·( A(y)·D(y) + B(y)·C(y) + λ·C(y)·D(y) )</c>
/// where <c>A/B</c> are the split-bit-0/1 halves of the upper layer's
/// numerator table and <c>C/D</c> the halves of its denominator table
/// (Papini–Haböck, ePrint 2023/1284, Section 3.3's <c>Q</c> form).
/// </summary>
/// <remarks>
/// Degree 3 per round — <c>eq</c> times a product of two multilinears — so
/// each round message is four evaluations. Pure over spans and delegates like
/// the other round computations; the drivers compose transcript traffic
/// around it, and folding reuses <see cref="LogUpSumcheck.FoldInPlace"/>.
/// </remarks>
internal static class LogUpGkrSumcheck
{
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The per-round evaluation count: degree 3 plus one.</summary>
    public const int RoundEvaluationCount = 4;

    //Five tables advance together through every round: the kernel and the
    //four upper-layer halves.
    private const int TrackedColumnCount = 5;


    /// <summary>
    /// Computes one round's evaluations <c>s(0..3)</c> into
    /// <paramref name="roundEvaluations"/> (cleared by this method).
    /// </summary>
    /// <param name="kernel">The current folded <c>eq(r, ·)</c> table, <c>2^remainingVariables × 32</c> bytes.</param>
    /// <param name="numeratorLow">The current folded split-bit-0 numerator half <c>A</c>.</param>
    /// <param name="numeratorHigh">The current folded split-bit-1 numerator half <c>B</c>.</param>
    /// <param name="denominatorLow">The current folded split-bit-0 denominator half <c>C</c>.</param>
    /// <param name="denominatorHigh">The current folded split-bit-1 denominator half <c>D</c>.</param>
    /// <param name="remainingVariables">The variable count of the current folded tables; at least 1.</param>
    /// <param name="foldingChallenge">The layer's batching challenge <c>λ</c>.</param>
    /// <param name="roundEvaluations">Receives the four summed evaluations, <c>4 × 32</c> bytes.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="curve">The curve whose scalar field the tables live in.</param>
    public static void ComputeRoundEvaluations(
        ReadOnlySpan<byte> kernel,
        ReadOnlySpan<byte> numeratorLow,
        ReadOnlySpan<byte> numeratorHigh,
        ReadOnlySpan<byte> denominatorLow,
        ReadOnlySpan<byte> denominatorHigh,
        int remainingVariables,
        ReadOnlySpan<byte> foldingChallenge,
        Span<byte> roundEvaluations,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentOutOfRangeException.ThrowIfLessThan(remainingVariables, 1);

        int size = 1 << remainingVariables;
        int pairCount = size >> 1;
        ValidateColumnLength(kernel, size, nameof(kernel));
        ValidateColumnLength(numeratorLow, size, nameof(numeratorLow));
        ValidateColumnLength(numeratorHigh, size, nameof(numeratorHigh));
        ValidateColumnLength(denominatorLow, size, nameof(denominatorLow));
        ValidateColumnLength(denominatorHigh, size, nameof(denominatorHigh));
        if(roundEvaluations.Length != RoundEvaluationCount * ScalarSize)
        {
            throw new ArgumentException($"Round evaluations need {RoundEvaluationCount * ScalarSize} bytes; received {roundEvaluations.Length}.", nameof(roundEvaluations));
        }

        roundEvaluations.Clear();

        Span<byte> values = stackalloc byte[TrackedColumnCount * ScalarSize];
        Span<byte> slopes = stackalloc byte[TrackedColumnCount * ScalarSize];
        Span<byte> temp1 = stackalloc byte[ScalarSize];
        Span<byte> temp2 = stackalloc byte[ScalarSize];

        for(int j = 0; j < pairCount; j++)
        {
            LoadPair(kernel, j, values[..ScalarSize], slopes[..ScalarSize], subtract, curve);
            LoadPair(numeratorLow, j, values.Slice(ScalarSize, ScalarSize), slopes.Slice(ScalarSize, ScalarSize), subtract, curve);
            LoadPair(numeratorHigh, j, values.Slice(2 * ScalarSize, ScalarSize), slopes.Slice(2 * ScalarSize, ScalarSize), subtract, curve);
            LoadPair(denominatorLow, j, values.Slice(3 * ScalarSize, ScalarSize), slopes.Slice(3 * ScalarSize, ScalarSize), subtract, curve);
            LoadPair(denominatorHigh, j, values.Slice(4 * ScalarSize, ScalarSize), slopes.Slice(4 * ScalarSize, ScalarSize), subtract, curve);

            for(int point = 0; point < RoundEvaluationCount; point++)
            {
                if(point > 0)
                {
                    for(int slot = 0; slot < TrackedColumnCount; slot++)
                    {
                        Span<byte> value = values.Slice(slot * ScalarSize, ScalarSize);
                        add(value, slopes.Slice(slot * ScalarSize, ScalarSize), temp1, curve);
                        temp1.CopyTo(value);
                    }
                }

                ReadOnlySpan<byte> kernelValue = values[..ScalarSize];
                ReadOnlySpan<byte> a = values.Slice(ScalarSize, ScalarSize);
                ReadOnlySpan<byte> b = values.Slice(2 * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> c = values.Slice(3 * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> d = values.Slice(4 * ScalarSize, ScalarSize);

                //term = eq·(A·D + B·C + λ·C·D).
                multiply(a, d, temp1, curve);
                multiply(b, c, temp2, curve);
                add(temp1, temp2, temp1, curve);
                multiply(c, d, temp2, curve);
                multiply(foldingChallenge, temp2, temp2, curve);
                add(temp1, temp2, temp1, curve);
                multiply(kernelValue, temp1, temp1, curve);

                Span<byte> evaluation = roundEvaluations.Slice(point * ScalarSize, ScalarSize);
                add(evaluation, temp1, temp2, curve);
                temp2.CopyTo(evaluation);
            }
        }
    }


    /// <summary>
    /// Builds the <c>eq(point, ·)</c> table over <c>2^coordinateCount</c>
    /// entries by tensor doubling, variable <c>i</c> of the point pairing
    /// with bit <c>i</c> of the table index.
    /// </summary>
    /// <param name="point">The point coordinates, <c>coordinateCount × 32</c> bytes in variable order.</param>
    /// <param name="coordinateCount">The coordinate count; non-negative.</param>
    /// <param name="destination">Receives the <c>2^coordinateCount × 32</c>-byte table.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="curve">The curve whose scalar field the table lives in.</param>
    public static void BuildKernelTable(
        ReadOnlySpan<byte> point,
        int coordinateCount,
        Span<byte> destination,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentOutOfRangeException.ThrowIfNegative(coordinateCount);

        int size = 1 << coordinateCount;
        if(point.Length != coordinateCount * ScalarSize)
        {
            throw new ArgumentException($"A {coordinateCount}-coordinate point needs {coordinateCount * ScalarSize} bytes; received {point.Length}.", nameof(point));
        }

        if(destination.Length != size * ScalarSize)
        {
            throw new ArgumentException($"The kernel table needs {size * ScalarSize} bytes; received {destination.Length}.", nameof(destination));
        }

        destination.Clear();
        SumcheckChallenge.EncodeOne(destination[..ScalarSize]);

        Span<byte> scratch = stackalloc byte[ScalarSize];
        int currentSize = 1;
        for(int coordinate = 0; coordinate < coordinateCount; coordinate++)
        {
            ReadOnlySpan<byte> z = point.Slice(coordinate * ScalarSize, ScalarSize);
            for(int index = 0; index < currentSize; index++)
            {
                Span<byte> low = destination.Slice(index * ScalarSize, ScalarSize);
                Span<byte> high = destination.Slice((currentSize + index) * ScalarSize, ScalarSize);
                multiply(low, z, high, curve);
                subtract(low, high, scratch, curve);
                scratch.CopyTo(low);
            }

            currentSize <<= 1;
        }
    }


    /// <summary>
    /// Evaluates <c>eq(left, right)</c> for two points of equal coordinate
    /// count: <c>Π_i (left_i·right_i + (1 − left_i)·(1 − right_i))</c>.
    /// </summary>
    /// <param name="left">The first point's coordinates.</param>
    /// <param name="right">The second point's coordinates.</param>
    /// <param name="coordinateCount">The shared coordinate count.</param>
    /// <param name="destination">Receives the 32-byte product.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="curve">The curve whose scalar field the points live in.</param>
    public static void EvaluateKernel(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right,
        int coordinateCount,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(one);
        Span<byte> product = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(product);
        Span<byte> factor = stackalloc byte[ScalarSize];
        Span<byte> complementLeft = stackalloc byte[ScalarSize];
        Span<byte> complementRight = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];

        for(int coordinate = 0; coordinate < coordinateCount; coordinate++)
        {
            ReadOnlySpan<byte> l = left.Slice(coordinate * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> r = right.Slice(coordinate * ScalarSize, ScalarSize);
            multiply(l, r, factor, curve);
            subtract(one, l, complementLeft, curve);
            subtract(one, r, complementRight, curve);
            multiply(complementLeft, complementRight, scratch, curve);
            add(factor, scratch, factor, curve);
            multiply(product, factor, scratch, curve);
            scratch.CopyTo(product);
        }

        product.CopyTo(destination);
    }


    private static void LoadPair(ReadOnlySpan<byte> column, int pairIndex, Span<byte> value, Span<byte> slope, ScalarSubtractDelegate subtract, CurveParameterSet curve)
    {
        ReadOnlySpan<byte> low = column.Slice(2 * pairIndex * ScalarSize, ScalarSize);
        ReadOnlySpan<byte> high = column.Slice(((2 * pairIndex) + 1) * ScalarSize, ScalarSize);
        low.CopyTo(value);
        subtract(high, low, slope, curve);
    }


    private static void ValidateColumnLength(ReadOnlySpan<byte> column, int size, string parameterName)
    {
        if(column.Length != size * ScalarSize)
        {
            throw new ArgumentException($"A table over {size} evaluations needs {size * ScalarSize} bytes; received {column.Length}.", parameterName);
        }
    }
}
