using System;
using System.Buffers;
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
    /// <param name="storage">Owns the returned coefficient bytes until disposal.</param>
    /// <returns>The monomial coefficients, least significant first, borrowed from <paramref name="storage"/>. A single value retains its supplied byte length.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="field"/>, <paramref name="values"/>, <paramref name="points"/> or <paramref name="storage"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="values"/> and <paramref name="points"/> differ in length.</exception>
    public static ReadOnlyMemory<byte>[] MonomialOfLagrange(LongfellowLogicFieldOperations field, ReadOnlyMemory<byte>[] values, ReadOnlyMemory<byte>[] points, LongfellowCircuitStorage storage)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(values);
        ArgumentNullException.ThrowIfNull(points);
        ArgumentNullException.ThrowIfNull(storage);

        if(values.Length != points.Length)
        {
            throw new ArgumentException("The interpolated values and evaluation points carry the same length.");
        }

        int n = values.Length;
        if(n == 0)
        {
            return [];
        }

        if(n == 1)
        {
            return [storage.Copy(values[0].Span)];
        }

        //Each slot preserves the input's byte length until arithmetic replaces it with a scalar.
        int byteLength = 0;
        for(int i = 0; i < n; i++)
        {
            byteLength = checked(byteLength + Math.Max(Scalar.SizeBytes, values[i].Length));
        }

        using IMemoryOwner<byte> owner = field.Pool.Rent(byteLength);
        Span<byte> buffer = owner.Memory.Span[..byteLength];
        buffer.Clear();
        var coefficients = new Memory<byte>[n];
        var slots = new Memory<byte>[n];
        int offset = 0;
        for(int i = 0; i < n; i++)
        {
            int slotLength = Math.Max(Scalar.SizeBytes, values[i].Length);
            Memory<byte> slot = owner.Memory.Slice(offset, slotLength);
            values[i].Span.CopyTo(slot.Span);
            coefficients[i] = slot[..values[i].Length];
            slots[i] = slot[..Scalar.SizeBytes];
            offset += slotLength;
        }

        ConvertLagrangeToNewtonInPlace(field, coefficients, slots, points, n);
        ConvertNewtonToMonomialInPlace(field, coefficients, slots, points, n);

        var result = new ReadOnlyMemory<byte>[n];
        for(int i = 0; i < n; i++)
        {
            result[i] = storage.Copy(coefficients[i].Span);
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
    /// <param name="slots">The full scalar destinations backing each coefficient.</param>
    /// <param name="points">The evaluation points.</param>
    /// <param name="n">The coefficient count.</param>
    private static void ConvertLagrangeToNewtonInPlace(LongfellowLogicFieldOperations field, Memory<byte>[] coefficients, Memory<byte>[] slots, ReadOnlyMemory<byte>[] points, int n)
    {
        //The two cached scalars and two arithmetic temporaries never alias active operands.
        const int ScratchScalarCount = 4;
        using IMemoryOwner<byte> owner = field.Pool.Rent(ScratchScalarCount * Scalar.SizeBytes);
        Span<byte> buffer = owner.Memory.Span[..(ScratchScalarCount * Scalar.SizeBytes)];
        Span<byte> cachedDifference = buffer[..Scalar.SizeBytes];
        Span<byte> cachedInverse = buffer.Slice(Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> difference = buffer.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes);
        Span<byte> intermediate = buffer.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes);
        field.Compiler.One.Span.CopyTo(cachedDifference);
        field.Compiler.One.Span.CopyTo(cachedInverse);

        for(int i = 1; i < n; i++)
        {
            for(int k = n - 1; k >= i; k--)
            {
                Subtract(field, points[k].Span, points[k - i].Span, difference);
                if(!LongfellowCompilerFieldOperations.ElementsEqual(difference, cachedDifference))
                {
                    difference.CopyTo(cachedDifference);
                    Invert(field, difference, cachedInverse);
                }

                Subtract(field, coefficients[k].Span, coefficients[k - 1].Span, intermediate);
                Multiply(field, intermediate, cachedInverse, difference);
                difference.CopyTo(slots[k].Span);
                coefficients[k] = slots[k];
            }
        }
    }


    /// <summary>
    /// The reference's <c>monomial_of_newton_inplace</c>: converts the Newton-basis coefficients in
    /// place into monomial-basis coefficients via synthetic-division-style back-substitution.
    /// </summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="coefficients">The coefficients, mutated in place.</param>
    /// <param name="slots">The full scalar destinations backing each coefficient.</param>
    /// <param name="points">The evaluation points.</param>
    /// <param name="n">The coefficient count.</param>
    private static void ConvertNewtonToMonomialInPlace(LongfellowLogicFieldOperations field, Memory<byte>[] coefficients, Memory<byte>[] slots, ReadOnlyMemory<byte>[] points, int n)
    {
        //The product and difference stay separate from the coefficients until each update completes.
        const int ScratchScalarCount = 2;
        using IMemoryOwner<byte> owner = field.Pool.Rent(ScratchScalarCount * Scalar.SizeBytes);
        Span<byte> buffer = owner.Memory.Span[..(ScratchScalarCount * Scalar.SizeBytes)];
        Span<byte> product = buffer[..Scalar.SizeBytes];
        Span<byte> difference = buffer[Scalar.SizeBytes..];
        for(int i = n - 1; i >= 0; i--)
        {
            for(int k = i + 1; k < n; k++)
            {
                Multiply(field, coefficients[k].Span, points[i].Span, product);
                Subtract(field, coefficients[k - 1].Span, product, difference);
                difference.CopyTo(slots[k - 1].Span);
                coefficients[k - 1] = slots[k - 1];
            }
        }
    }


    /// <summary>Subtracts two field constants out of circuit.</summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="left">The minuend, canonical big-endian.</param>
    /// <param name="right">The subtrahend, canonical big-endian.</param>
    /// <param name="difference">Receives the canonical difference, separate from the inputs.</param>
    private static void Subtract(LongfellowLogicFieldOperations field, ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> difference)
    {
        difference.Clear();
        field.Subtract(left, right, difference, field.Compiler.Curve);
    }


    /// <summary>Multiplies two field constants out of circuit.</summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="left">The first factor, canonical big-endian.</param>
    /// <param name="right">The second factor, canonical big-endian.</param>
    /// <param name="product">Receives the canonical product, separate from the inputs.</param>
    private static void Multiply(LongfellowLogicFieldOperations field, ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> product)
    {
        product.Clear();
        field.Compiler.Multiply(left, right, product, field.Compiler.Curve);
    }


    /// <summary>Inverts a field constant out of circuit.</summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <param name="value">The value to invert, canonical big-endian.</param>
    /// <param name="inverse">Receives the canonical inverse, separate from the input.</param>
    private static void Invert(LongfellowLogicFieldOperations field, ReadOnlySpan<byte> value, Span<byte> inverse)
    {
        inverse.Clear();
        field.Invert(value, inverse, field.Compiler.Curve);
    }
}
