using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// Lagrange interpolation over the small integer evaluation points <c>0..d</c> the sumcheck round
/// polynomials are sent at: the verifier reduces a running claim to <c>s(r)</c> from the d+1
/// transmitted evaluations. Shared by the product sumcheck verifier and the data-parallel GKR
/// copy-round verifier (whose copy rounds are degree-3).
/// </summary>
internal static class SumcheckInterpolation
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    //Lagrange-interpolates the degree-d polynomial given by its evaluations at 0..d, at the point r,
    //writing s(r) to destination: s(r) = Σ_i s(i)·invDenom[i]·Π_{j≠i}(r − j).
    public static void Interpolate(
        ReadOnlySpan<byte> evaluations, int evaluationCount, ReadOnlySpan<byte> r, ReadOnlySpan<byte> inverseDenominators, Span<byte> destination,
        ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, CurveParameterSet curve)
    {
        Span<byte> result = stackalloc byte[ScalarSize];
        result.Clear();
        Span<byte> numerator = stackalloc byte[ScalarSize];
        Span<byte> pointJ = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];

        for(int i = 0; i < evaluationCount; i++)
        {
            SumcheckChallenge.EncodeOne(numerator);
            for(int j = 0; j < evaluationCount; j++)
            {
                if(j == i)
                {
                    continue;
                }

                SumcheckChallenge.EncodeConstant((uint)j, pointJ);
                subtract(r, pointJ, difference, curve);
                multiply(numerator, difference, scratch, curve);
                scratch.CopyTo(numerator);
            }

            multiply(evaluations.Slice(i * ScalarSize, ScalarSize), numerator, scratch, curve);
            multiply(scratch, inverseDenominators.Slice(i * ScalarSize, ScalarSize), numerator, curve);
            add(result, numerator, scratch, curve);
            scratch.CopyTo(result);
        }

        result.CopyTo(destination);
    }


    //invDenom[i] = 1 / Π_{j≠i}(i − j) for the points 0..d — the constant Lagrange denominators.
    public static void ComputeInverseDenominators(
        Span<byte> inverseDenominators, int evaluationCount,
        ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert, CurveParameterSet curve)
    {
        Span<byte> pointI = stackalloc byte[ScalarSize];
        Span<byte> pointJ = stackalloc byte[ScalarSize];
        Span<byte> denominator = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];

        for(int i = 0; i < evaluationCount; i++)
        {
            SumcheckChallenge.EncodeConstant((uint)i, pointI);
            SumcheckChallenge.EncodeOne(denominator);
            for(int j = 0; j < evaluationCount; j++)
            {
                if(j == i)
                {
                    continue;
                }

                SumcheckChallenge.EncodeConstant((uint)j, pointJ);
                subtract(pointI, pointJ, difference, curve);
                multiply(denominator, difference, scratch, curve);
                scratch.CopyTo(denominator);
            }

            invert(denominator, inverseDenominators.Slice(i * ScalarSize, ScalarSize), curve);
        }
    }
}
