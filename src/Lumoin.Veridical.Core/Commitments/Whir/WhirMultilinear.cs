using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// Multilinear table arithmetic for the WHIR sumcheck interleave. Every table
/// is indexed least-significant-variable first, matching the coefficient
/// vector's monomial indexing under WHIR Definition 4.2: bit <c>l</c> of a
/// table index is the value of variable <c>X_(l+1)</c>, so binding
/// <c>X_1</c> pairs even and odd entries in every representation and the
/// sumcheck challenge order coincides with the folding order of
/// <see cref="WhirFold"/>.
/// </summary>
internal static class WhirMultilinear
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Transforms a multilinear coefficient vector into its evaluation table
    /// over the boolean cube, in place: on exit entry <c>b</c> holds
    /// <c>Σ_(t ⊆ b) c_t</c>, the evaluation at the point whose coordinates
    /// are the bits of <c>b</c>.
    /// </summary>
    /// <param name="table">The coefficient vector, <c>2^variableCount</c> elements; becomes the evaluation table.</param>
    /// <param name="variableCount">The variable count, non-negative.</param>
    /// <param name="add">Scalar addition.</param>
    /// <param name="curve">The wired curve the delegate routes over.</param>
    public static void CoefficientsToCubeEvaluations(
        Span<byte> table,
        int variableCount,
        ScalarAddDelegate add,
        CurveParameterSet curve)
    {
        int size = 1 << variableCount;
        for(int variable = 0; variable < variableCount; variable++)
        {
            int bit = 1 << variable;
            for(int index = 0; index < size; index++)
            {
                if((index & bit) != 0)
                {
                    Span<byte> entry = table.Slice(index * ScalarSize, ScalarSize);
                    ReadOnlySpan<byte> subset = table.Slice((index ^ bit) * ScalarSize, ScalarSize);
                    add(entry, subset, entry, curve);
                }
            }
        }
    }


    /// <summary>
    /// Accumulates a scaled equality kernel into a weight table:
    /// <c>table[b] += coefficient·eq(point, b)</c> for every cube vertex
    /// <c>b</c>, the per-constraint term of the WHIR weight update.
    /// </summary>
    /// <param name="table">The weight table, <c>2^variableCount</c> elements.</param>
    /// <param name="point">The kernel point, <c>variableCount</c> elements, first variable first.</param>
    /// <param name="coefficient">The scale <c>λ</c>, one element.</param>
    /// <param name="variableCount">The variable count, non-negative.</param>
    /// <param name="add">Scalar addition.</param>
    /// <param name="subtract">Scalar subtraction.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="curve">The wired curve the delegates route over.</param>
    /// <param name="pool">The pool the kernel scratch rents from.</param>
    public static void AccumulateScaledEqTable(
        Span<byte> table,
        ReadOnlySpan<byte> point,
        ReadOnlySpan<byte> coefficient,
        int variableCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int size = 1 << variableCount;
        using IMemoryOwner<byte> kernelOwner = pool.Rent(size * ScalarSize);
        Span<byte> kernel = kernelOwner.Memory.Span[..(size * ScalarSize)];

        //The doubling build seeded with λ: after step l the table over the
        //first l variables carries λ·eq(point[..l], ·). Descending order
        //lets each step split an entry into its (1 − p)/p halves in place.
        coefficient.CopyTo(kernel[..ScalarSize]);
        for(int variable = 0; variable < variableCount; variable++)
        {
            int half = 1 << variable;
            ReadOnlySpan<byte> coordinate = point.Slice(variable * ScalarSize, ScalarSize);
            for(int index = half - 1; index >= 0; index--)
            {
                Span<byte> low = kernel.Slice(index * ScalarSize, ScalarSize);
                Span<byte> high = kernel.Slice((index + half) * ScalarSize, ScalarSize);
                multiply(low, coordinate, high, curve);
                subtract(low, high, low, curve);
            }
        }

        for(int index = 0; index < size; index++)
        {
            Span<byte> entry = table.Slice(index * ScalarSize, ScalarSize);
            add(entry, kernel.Slice(index * ScalarSize, ScalarSize), entry, curve);
        }
    }


    /// <summary>
    /// Binds the first variable of a cube evaluation table to a challenge, in
    /// place: <c>table[i] ← table[2i] + challenge·(table[2i+1] − table[2i])</c>,
    /// leaving the folded table in the first half.
    /// </summary>
    /// <param name="table">The evaluation table; the leading <c>size</c> elements are consumed.</param>
    /// <param name="size">The current table size; a positive even count.</param>
    /// <param name="challenge">The bound value, one element.</param>
    /// <param name="add">Scalar addition.</param>
    /// <param name="subtract">Scalar subtraction.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="curve">The wired curve the delegates route over.</param>
    public static void BindFirstVariable(
        Span<byte> table,
        int size,
        ReadOnlySpan<byte> challenge,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> difference = stackalloc byte[ScalarSize];
        int half = size / 2;
        for(int index = 0; index < half; index++)
        {
            ReadOnlySpan<byte> even = table.Slice(2 * index * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> odd = table.Slice(((2 * index) + 1) * ScalarSize, ScalarSize);

            //Ascending order keeps the write at index behind the reads at
            //2·index and 2·index + 1, so the fold is alias-safe in place.
            subtract(odd, even, difference, curve);
            multiply(difference, challenge, difference, curve);
            add(even, difference, table.Slice(index * ScalarSize, ScalarSize), curve);
        }
    }


    /// <summary>
    /// Evaluates a multilinear coefficient vector at an arbitrary point by
    /// folding one variable at a time on a scratch copy.
    /// </summary>
    /// <param name="coefficients">The coefficient vector, <c>2^variableCount</c> elements.</param>
    /// <param name="point">The evaluation point, <c>variableCount</c> elements, first variable first.</param>
    /// <param name="variableCount">The variable count, non-negative.</param>
    /// <param name="result">Receives the evaluation, one element.</param>
    /// <param name="add">Scalar addition.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="curve">The wired curve the delegates route over.</param>
    /// <param name="pool">The pool the scratch copy rents from.</param>
    public static void EvaluateCoefficientsAtPoint(
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> point,
        int variableCount,
        Span<byte> result,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int size = 1 << variableCount;
        using IMemoryOwner<byte> scratchOwner = pool.Rent(size * ScalarSize);
        Span<byte> scratch = scratchOwner.Memory.Span[..(size * ScalarSize)];
        coefficients.CopyTo(scratch);
        for(int variable = 0; variable < variableCount; variable++)
        {
            int currentSize = size >> variable;
            WhirFold.FoldCoefficients(
                scratch[..(currentSize * ScalarSize)],
                point.Slice(variable * ScalarSize, ScalarSize),
                scratch[..(currentSize / 2 * ScalarSize)],
                add,
                multiply,
                curve);
        }

        scratch[..ScalarSize].CopyTo(result);
    }


    /// <summary>
    /// Expands a field element into the multilinear point WHIR identifies it
    /// with: <c>pow(value, variableCount) = (value^(2^0), ..., value^(2^(variableCount−1)))</c>
    /// by successive squaring.
    /// </summary>
    /// <param name="value">The field element, one element.</param>
    /// <param name="variableCount">The coordinate count, non-negative.</param>
    /// <param name="coordinates">Receives the <c>variableCount</c> coordinates.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="curve">The wired curve the delegate routes over.</param>
    public static void ExpandPowPoint(
        ReadOnlySpan<byte> value,
        int variableCount,
        Span<byte> coordinates,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        if(variableCount == 0)
        {
            return;
        }

        value.CopyTo(coordinates[..ScalarSize]);
        for(int variable = 1; variable < variableCount; variable++)
        {
            ReadOnlySpan<byte> previous = coordinates.Slice((variable - 1) * ScalarSize, ScalarSize);
            multiply(previous, previous, coordinates.Slice(variable * ScalarSize, ScalarSize), curve);
        }
    }
}
