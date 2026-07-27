using System;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// Computes the monomial-basis coefficients of the unique polynomial interpolating a set of
/// (point, value) pairs, a faithful port of google/longfellow-zk's <c>Interpolation&lt;N,
/// Field&gt;::monomial_of_lagrange</c> (<c>algebra/interpolation.h</c>): a Lagrange-to-Newton basis
/// change (<c>newton_of_lagrange_inplace</c>) that caches one point difference and its inverse across
/// consecutive iterations, since arithmetic-sequence evaluation points repeat it, followed by a
/// Newton-to-monomial basis change (<c>monomial_of_newton_inplace</c>).
/// </summary>
/// <remarks>
/// The interpolating polynomial through a given point set is mathematically unique, so any correct
/// algorithm reproduces the same coefficients the reference does; this port still follows the
/// reference's exact two-pass divided-difference construction rather than an independently designed
/// one, since it is already loop-based (no recursion to rewrite) and its cached-inverse optimization is
/// worth preserving.
/// </remarks>
internal static class LongfellowMonomialInterpolation
{
    /// <summary>
    /// Computes the monomial coefficients of the polynomial <c>P</c>, of degree below
    /// <paramref name="values"/>'s length, such that <c>P(points[i]) == values[i]</c> for every index.
    /// </summary>
    /// <param name="field">The field-operation bundle supplying subtraction, multiplication and inversion.</param>
    /// <param name="values">The interpolated values (the reference's Lagrange-basis coefficients <c>L</c>), one per point.</param>
    /// <param name="points">The evaluation points (the reference's <c>X</c>), the same length as <paramref name="values"/>.</param>
    /// <returns>The monomial coefficients, least significant first, the same length as <paramref name="values"/>.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="field"/>, <paramref name="values"/> or <paramref name="points"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="values"/> and <paramref name="points"/> differ in length.</exception>
    public static ReadOnlyMemory<byte>[] MonomialOfLagrange(LongfellowLogicFieldOperations field, ReadOnlyMemory<byte>[] values, ReadOnlyMemory<byte>[] points)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(values);
        ArgumentNullException.ThrowIfNull(points);

        if(values.Length != points.Length)
        {
            throw new ArgumentException("The interpolated values and evaluation points carry the same length.");
        }

        int n = values.Length;
        var coefficients = new byte[n][];
        for(int i = 0; i < n; i++)
        {
            coefficients[i] = values[i].ToArray();
        }

        ConvertLagrangeToNewtonInPlace(field, coefficients, points, n);
        ConvertNewtonToMonomialInPlace(field, coefficients, points, n);

        var result = new ReadOnlyMemory<byte>[n];
        for(int i = 0; i < n; i++)
        {
            result[i] = coefficients[i];
        }

        return result;
    }


    /// <summary>
    /// The reference's <c>newton_of_lagrange_inplace</c>: converts the Lagrange-basis coefficients in
    /// place into Newton-basis (divided-difference) coefficients, caching the most recent nonzero point
    /// difference and its inverse across the inner loop's iterations.
    /// </summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="coefficients">The coefficients, mutated in place.</param>
    /// <param name="points">The evaluation points.</param>
    /// <param name="n">The coefficient count.</param>
    private static void ConvertLagrangeToNewtonInPlace(LongfellowLogicFieldOperations field, byte[][] coefficients, ReadOnlyMemory<byte>[] points, int n)
    {
        byte[] cachedDifference = field.Compiler.One.ToArray();
        byte[] cachedInverse = field.Compiler.One.ToArray();

        for(int i = 1; i < n; i++)
        {
            for(int k = n - 1; k >= i; k--)
            {
                byte[] difference = Subtract(field, points[k].Span, points[k - i].Span);
                if(!LongfellowCompilerFieldOperations.ElementsEqual(difference, cachedDifference))
                {
                    cachedDifference = difference;
                    cachedInverse = Invert(field, difference);
                }

                coefficients[k] = Multiply(field, Subtract(field, coefficients[k], coefficients[k - 1]), cachedInverse);
            }
        }
    }


    /// <summary>
    /// The reference's <c>monomial_of_newton_inplace</c>: converts the Newton-basis coefficients in
    /// place into monomial-basis coefficients via synthetic-division-style back-substitution.
    /// </summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="coefficients">The coefficients, mutated in place.</param>
    /// <param name="points">The evaluation points.</param>
    /// <param name="n">The coefficient count.</param>
    private static void ConvertNewtonToMonomialInPlace(LongfellowLogicFieldOperations field, byte[][] coefficients, ReadOnlyMemory<byte>[] points, int n)
    {
        for(int i = n - 1; i >= 0; i--)
        {
            for(int k = i + 1; k < n; k++)
            {
                coefficients[k - 1] = Subtract(field, coefficients[k - 1], Multiply(field, coefficients[k], points[i].Span));
            }
        }
    }


    /// <summary>Subtracts two field constants out of circuit.</summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="left">The minuend, canonical big-endian.</param>
    /// <param name="right">The subtrahend, canonical big-endian.</param>
    /// <returns>The difference, canonical big-endian.</returns>
    private static byte[] Subtract(LongfellowLogicFieldOperations field, ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var difference = new byte[Scalar.SizeBytes];
        field.Subtract(left, right, difference, field.Compiler.Curve);

        return difference;
    }


    /// <summary>Multiplies two field constants out of circuit.</summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="left">The first factor, canonical big-endian.</param>
    /// <param name="right">The second factor, canonical big-endian.</param>
    /// <returns>The product, canonical big-endian.</returns>
    private static byte[] Multiply(LongfellowLogicFieldOperations field, ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var product = new byte[Scalar.SizeBytes];
        field.Compiler.Multiply(left, right, product, field.Compiler.Curve);

        return product;
    }


    /// <summary>Inverts a field constant out of circuit.</summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="value">The value to invert, canonical big-endian.</param>
    /// <returns>The multiplicative inverse, canonical big-endian.</returns>
    private static byte[] Invert(LongfellowLogicFieldOperations field, ReadOnlySpan<byte> value)
    {
        var inverse = new byte[Scalar.SizeBytes];
        field.Invert(value, inverse, field.Compiler.Curve);

        return inverse;
    }
}
