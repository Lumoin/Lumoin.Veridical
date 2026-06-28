using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The multilinear equality polynomial <c>eq_g(x) = Π_b (g_b·x_b + (1−g_b)(1−x_b))</c> — the
/// selector GKR multiplies into a layer's sum to pin an output coordinate, and the same shape the
/// data-parallel copy variable uses. <see cref="BuildTable"/> materialises its 2^v hypercube
/// evaluations for a fixed point <c>g</c> into a caller-supplied (typically pooled) buffer:
/// <c>table[x] = Π_b (g_b if bit b of x is set else 1 − g_b)</c>, built by the standard tensor
/// doubling so each variable costs one pass. The result is a multilinear factor table the
/// <see cref="ProductSumcheck"/> consumes directly. Over the P-256 base field Fp256
/// (<see cref="CurveParameterSet.None"/> + the P256BaseFieldReference delegates).
/// </summary>
public static class EqualityPolynomial
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    /// <summary>
    /// Materialises the <c>2^variableCount</c> hypercube evaluations of the equality polynomial
    /// <c>eq_g</c> for the fixed point <paramref name="point"/> into <paramref name="destination"/>,
    /// built by tensor doubling so each variable costs one pass.
    /// </summary>
    public static void BuildTable(
        ReadOnlySpan<byte> point,
        int variableCount,
        Span<byte> destination,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        if(point.Length != variableCount * ScalarSize)
        {
            throw new ArgumentException($"A {variableCount}-variable point must be {variableCount * ScalarSize} bytes; received {point.Length}.", nameof(point));
        }

        int size = 1 << variableCount;
        if(destination.Length != size * ScalarSize)
        {
            throw new ArgumentException($"A {variableCount}-variable table needs {size * ScalarSize} bytes; received {destination.Length}.", nameof(destination));
        }

        //Start from the empty product (one entry equal to 1), then fold in each coordinate: an
        //existing entry e splits into e·(1−g_b) at bit b = 0 and e·g_b at bit b = 1.
        destination.Clear();
        SumcheckChallenge.EncodeOne(destination[..ScalarSize]);

        Span<byte> one = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(one);
        Span<byte> oneMinusCoordinate = stackalloc byte[ScalarSize];
        Span<byte> lowProduct = stackalloc byte[ScalarSize];
        Span<byte> highProduct = stackalloc byte[ScalarSize];

        int active = 1;
        for(int b = 0; b < variableCount; b++)
        {
            ReadOnlySpan<byte> coordinate = point.Slice(b * ScalarSize, ScalarSize);
            subtract(one, coordinate, oneMinusCoordinate, curve);

            //Walk high index to low so each entry is read before its (lower) slot is overwritten.
            for(int j = active - 1; j >= 0; j--)
            {
                Span<byte> entry = destination.Slice(j * ScalarSize, ScalarSize);
                multiply(entry, oneMinusCoordinate, lowProduct, curve);
                multiply(entry, coordinate, highProduct, curve);
                highProduct.CopyTo(destination.Slice((j + active) * ScalarSize, ScalarSize));
                lowProduct.CopyTo(entry);
            }

            active <<= 1;
        }
    }
}
