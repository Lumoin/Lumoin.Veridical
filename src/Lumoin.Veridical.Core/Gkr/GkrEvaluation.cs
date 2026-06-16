using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// Shared point and evaluation helpers the GKR prover and verifier both use, so the two sides
/// compute identical values from identical conventions: dotting a table with an equality table
/// (a multilinear evaluation), evaluating <c>eq</c> at one boolean index, squeezing a multi-
/// coordinate Fiat-Shamir point, splitting a joint sumcheck challenge into the two hands'
/// eq-convention points, and the <c>α·x + β·y</c> combinations the layer walk uses.
/// </summary>
/// <remarks>
/// Conventions (the load-bearing part): a table index's bit <c>b</c> corresponds to coordinate
/// <c>b</c> (<c>point[b]</c> in <see cref="EqualityPolynomial.BuildTable"/>'s layout), while the
/// sumcheck binds the most-significant bit first, so a returned challenge sequence has the
/// challenge for bit <c>b</c> at position <c>v − 1 − b</c>. <see cref="SplitJointPoint"/> performs
/// exactly that reversal per hand for the joint <c>(left, right)</c> wire space, where the left
/// hand owns the high bits.
/// </remarks>
internal static class GkrEvaluation
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    //destination = Σ_i weights[i]·values[i] — with an equality table as weights this is the
    //multilinear extension of values at the table's point.
    public static void Dot(
        ReadOnlySpan<byte> weights,
        ReadOnlySpan<byte> values,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        int count = values.Length / ScalarSize;
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];
        destination.Clear();
        for(int i = 0; i < count; i++)
        {
            multiply(weights.Slice(i * ScalarSize, ScalarSize), values.Slice(i * ScalarSize, ScalarSize), term, curve);
            add(destination, term, sum, curve);
            sum.CopyTo(destination);
        }
    }


    //destination = eq_point(index) = Π_b (point[b] if bit b of index is set else 1 − point[b]).
    public static void EvaluateEqAt(
        int index,
        ReadOnlySpan<byte> point,
        Span<byte> destination,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        int coordinateCount = point.Length / ScalarSize;
        Span<byte> one = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(one);
        Span<byte> factor = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(destination);
        for(int b = 0; b < coordinateCount; b++)
        {
            ReadOnlySpan<byte> coordinate = point.Slice(b * ScalarSize, ScalarSize);
            if(((index >> b) & 1) == 1)
            {
                coordinate.CopyTo(factor);
            }
            else
            {
                subtract(one, coordinate, factor, curve);
            }

            multiply(destination, factor, product, curve);
            product.CopyTo(destination);
        }
    }


    //Squeezes a point (coordinate b at offset b·32) under the label into the destination.
    public static void SqueezePoint(
        FiatShamirTranscript transcript,
        FiatShamirOperationLabel label,
        int coordinateCount,
        Span<byte> destination,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve)
    {
        for(int b = 0; b < coordinateCount; b++)
        {
            SumcheckChallenge.Squeeze(transcript, label, destination.Slice(b * ScalarSize, ScalarSize), squeeze, hash, reduce, curve);
        }
    }


    //Splits a joint sumcheck challenge sequence over (left, right) wire variables — left owning
    //the high logWidth bits — into the two hands' eq-convention points. The sumcheck binds the
    //most-significant joint bit first, so left[b] = joint[logWidth − 1 − b] and
    //right[b] = joint[2·logWidth − 1 − b].
    public static void SplitJointPoint(ReadOnlySpan<byte> jointChallenges, int logWidth, Span<byte> left, Span<byte> right)
    {
        for(int b = 0; b < logWidth; b++)
        {
            jointChallenges.Slice((logWidth - 1 - b) * ScalarSize, ScalarSize).CopyTo(left.Slice(b * ScalarSize, ScalarSize));
            jointChallenges.Slice(((2 * logWidth) - 1 - b) * ScalarSize, ScalarSize).CopyTo(right.Slice(b * ScalarSize, ScalarSize));
        }
    }


    //destination = eq~(a, b) = Π_b (a_b·b_b + (1−a_b)(1−b_b)) for two field points of equal
    //coordinate count — the multilinear eq with both arguments non-boolean (e.g. the layer's copy
    //point against the copy-round challenges).
    public static void EvaluateEqBetween(
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        int coordinateCount = first.Length / ScalarSize;
        Span<byte> one = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(one);
        Span<byte> matchOne = stackalloc byte[ScalarSize];
        Span<byte> oneMinusFirst = stackalloc byte[ScalarSize];
        Span<byte> oneMinusSecond = stackalloc byte[ScalarSize];
        Span<byte> matchZero = stackalloc byte[ScalarSize];
        Span<byte> factor = stackalloc byte[ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(destination);
        for(int b = 0; b < coordinateCount; b++)
        {
            ReadOnlySpan<byte> a = first.Slice(b * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> c = second.Slice(b * ScalarSize, ScalarSize);
            multiply(a, c, matchOne, curve);
            subtract(one, a, oneMinusFirst, curve);
            subtract(one, c, oneMinusSecond, curve);
            multiply(oneMinusFirst, oneMinusSecond, matchZero, curve);
            add(matchOne, matchZero, factor, curve);
            multiply(destination, factor, product, curve);
            product.CopyTo(destination);
        }
    }


    //Reverses challenge order into eq convention: a sumcheck over v variables binds the
    //most-significant table bit first, so destination[b] = challenges[v − 1 − b].
    public static void ReversePoint(ReadOnlySpan<byte> challenges, int coordinateCount, Span<byte> destination)
    {
        for(int b = 0; b < coordinateCount; b++)
        {
            challenges.Slice((coordinateCount - 1 - b) * ScalarSize, ScalarSize).CopyTo(destination.Slice(b * ScalarSize, ScalarSize));
        }
    }


    //destination = Σ_{c,h} copyWeights[c]·wireWeights[h]·values[c·width + h] — the multilinear
    //extension of a copy×wire table at the tensor point, without materialising the joint table.
    public static void TensorDot(
        ReadOnlySpan<byte> copyWeights,
        ReadOnlySpan<byte> wireWeights,
        ReadOnlySpan<byte> values,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        int copyCount = copyWeights.Length / ScalarSize;
        int width = wireWeights.Length / ScalarSize;
        Span<byte> rowSum = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];
        destination.Clear();
        for(int c = 0; c < copyCount; c++)
        {
            GkrEvaluation.Dot(wireWeights, values.Slice(c * width * ScalarSize, width * ScalarSize), rowSum, add, multiply, curve);
            multiply(copyWeights.Slice(c * ScalarSize, ScalarSize), rowSum, term, curve);
            add(destination, term, sum, curve);
            sum.CopyTo(destination);
        }
    }


    //destination = alpha·x + beta·y.
    public static void CombinePair(
        ReadOnlySpan<byte> alpha,
        ReadOnlySpan<byte> x,
        ReadOnlySpan<byte> beta,
        ReadOnlySpan<byte> y,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> first = stackalloc byte[ScalarSize];
        Span<byte> second = stackalloc byte[ScalarSize];
        multiply(alpha, x, first, curve);
        multiply(beta, y, second, curve);
        add(first, second, destination, curve);
    }


    //destination = alpha·first + beta·second, elementwise over equal-length scalar tables.
    public static void CombineTables(
        ReadOnlySpan<byte> alpha,
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> beta,
        ReadOnlySpan<byte> second,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        int count = first.Length / ScalarSize;
        for(int i = 0; i < count; i++)
        {
            CombinePair(
                alpha, first.Slice(i * ScalarSize, ScalarSize),
                beta, second.Slice(i * ScalarSize, ScalarSize),
                destination.Slice(i * ScalarSize, ScalarSize), add, multiply, curve);
        }
    }
}
