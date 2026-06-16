using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The equality-tensor and row-combination arithmetic the Ligero
/// polynomial-commitment argument needs: expanding half of an evaluation point
/// into a multilinear equality (Lagrange-basis) weight vector, and combining the
/// matrix rows under such a weight vector. The construction mirrors the Hyrax
/// matrix split exactly so that <c>⟨L·M, R⟩</c> equals the multilinear
/// extension evaluated at the point, where <c>R</c> is the equality tensor of
/// the lower (column) variables and <c>L</c> of the upper (row) variables.
/// </summary>
internal static class LigeroEvaluationTensor
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Builds the equality-tensor weight vector
    /// <c>w[i] = ∏_k (i_k ? var[k] : (1 − var[k]))</c> over the
    /// <paramref name="count"/> point coordinates starting at
    /// <paramref name="variableOffset"/>, with bit 0 of <c>i</c> the LSB. The
    /// result has <c>2^count</c> scalars and matches Hyrax's
    /// <c>ComputeLagrangeVector</c> (variables iterated in reverse so
    /// <c>bit_0(i)</c> encodes the first coordinate of the slice).
    /// </summary>
    public static void ComputeEqualityWeights(
        ReadOnlySpan<Scalar> evaluationPoint,
        int variableOffset,
        int count,
        Span<byte> destination,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int expectedLength = (1 << count) * ScalarSize;
        if(destination.Length != expectedLength)
        {
            throw new ArgumentException($"Destination must be {expectedLength} bytes for {count} variables; received {destination.Length}.", nameof(destination));
        }

        //Initialise w = [1].
        destination.Clear();
        destination[ScalarSize - 1] = 0x01;
        int currentLength = 1;

        using IMemoryOwner<byte> oneOwner = pool.Rent(ScalarSize);
        using IMemoryOwner<byte> oneMinusVarOwner = pool.Rent(ScalarSize);
        using IMemoryOwner<byte> productOwner = pool.Rent(ScalarSize);
        Span<byte> one = oneOwner.Memory.Span[..ScalarSize];
        Span<byte> oneMinusVar = oneMinusVarOwner.Memory.Span[..ScalarSize];
        Span<byte> product = productOwner.Memory.Span[..ScalarSize];
        one.Clear();
        one[ScalarSize - 1] = 0x01;

        for(int k = 0; k < count; k++)
        {
            Scalar variable = evaluationPoint[variableOffset + count - 1 - k];
            ArgumentNullException.ThrowIfNull(variable);
            ReadOnlySpan<byte> variableBytes = variable.AsReadOnlySpan();
            subtract(one, variableBytes, oneMinusVar, curve);

            for(int i = currentLength - 1; i >= 0; i--)
            {
                ReadOnlySpan<byte> slot = destination.Slice(i * ScalarSize, ScalarSize);
                multiply(slot, variableBytes, product, curve);
                product.CopyTo(destination.Slice(((2 * i) + 1) * ScalarSize, ScalarSize));

                multiply(slot, oneMinusVar, product, curve);
                product.CopyTo(destination.Slice(2 * i * ScalarSize, ScalarSize));
            }

            currentLength <<= 1;
        }
    }


    /// <summary>
    /// Computes the row-combination <c>f[j] = Σ_i weights[i] · matrix[i][j]</c>
    /// for the row-major matrix (<paramref name="rowCount"/> ×
    /// <paramref name="columnCount"/>).
    /// </summary>
    public static void CombineRows(
        ReadOnlySpan<byte> weights,
        ReadOnlySpan<byte> matrix,
        int rowCount,
        int columnCount,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        destination[..(columnCount * ScalarSize)].Clear();
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];
        for(int j = 0; j < columnCount; j++)
        {
            Span<byte> slot = destination.Slice(j * ScalarSize, ScalarSize);
            for(int i = 0; i < rowCount; i++)
            {
                multiply(weights.Slice(i * ScalarSize, ScalarSize), matrix.Slice(((i * columnCount) + j) * ScalarSize, ScalarSize), term, curve);
                add(slot, term, sum, curve);
                sum.CopyTo(slot);
            }
        }
    }


    /// <summary>Computes the inner product <c>Σ_i a[i] · b[i]</c> of two <paramref name="count"/>-scalar vectors.</summary>
    public static void InnerProduct(
        ReadOnlySpan<byte> a,
        ReadOnlySpan<byte> b,
        int count,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        destination[..ScalarSize].Clear();
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];
        for(int i = 0; i < count; i++)
        {
            multiply(a.Slice(i * ScalarSize, ScalarSize), b.Slice(i * ScalarSize, ScalarSize), term, curve);
            add(destination[..ScalarSize], term, sum, curve);
            sum.CopyTo(destination[..ScalarSize]);
        }
    }
}
