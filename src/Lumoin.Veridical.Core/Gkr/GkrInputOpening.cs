using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// Builds the two Ligero linear constraints that open a committed copy×wire witness at the GKR
/// walk's final tensor points: <c>Σ_{c,h} eq_rc(c)·eq_r(h)·W[c·width + h] = claim</c> for the left
/// and right input claims. The coefficients are the tensor of the two equality tables — public
/// values both sides derive from the transcript — so the committed-witness check is exactly two
/// dense linear constraints over the commitment, Ligero's native statement shape. When several
/// circuit instances share one commitment, each instance's input table is a segment of the
/// witness and its openings re-base via <c>constraintIndexBase</c> and
/// <c>witnessIndexOffset</c>.
/// </summary>
internal static class GkrInputOpening
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    //Fills the 2·copyCount·width coefficient scalars (constraint base then base + 1) and the
    //matching LigeroLinearConstraint entries referencing them.
    public static void BuildConstraints(
        ReadOnlySpan<byte> copyPoint,
        ReadOnlySpan<byte> leftPoint,
        ReadOnlySpan<byte> rightPoint,
        int copyCount,
        int width,
        Memory<byte> coefficients,
        Span<LigeroLinearConstraint> constraints,
        int constraintIndexBase,
        int witnessIndexOffset,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);

        int witnessCount = copyCount * width;
        if(coefficients.Length != 2 * witnessCount * ScalarSize || constraints.Length != 2 * witnessCount)
        {
            throw new ArgumentException($"Two dense constraints over {witnessCount} witnesses need {2 * witnessCount * ScalarSize} coefficient bytes and {2 * witnessCount} entries.", nameof(coefficients));
        }

        int logCopies = BitOperations.Log2((uint)copyCount);
        int logWidth = BitOperations.Log2((uint)width);

        using IMemoryOwner<byte> tableOwner = pool.Rent((copyCount + (2 * width)) * ScalarSize);
        Span<byte> copyTable = tableOwner.Memory.Span[..(copyCount * ScalarSize)];
        Span<byte> leftTable = tableOwner.Memory.Span.Slice(copyCount * ScalarSize, width * ScalarSize);
        Span<byte> rightTable = tableOwner.Memory.Span.Slice((copyCount + width) * ScalarSize, width * ScalarSize);
        EqualityPolynomial.BuildTable(copyPoint, logCopies, copyTable, subtract, multiply, curve);
        EqualityPolynomial.BuildTable(leftPoint, logWidth, leftTable, subtract, multiply, curve);
        EqualityPolynomial.BuildTable(rightPoint, logWidth, rightTable, subtract, multiply, curve);

        Span<byte> coefficientSpan = coefficients.Span;
        for(int c = 0; c < copyCount; c++)
        {
            for(int h = 0; h < width; h++)
            {
                int witnessIndex = (c * width) + h;
                multiply(copyTable.Slice(c * ScalarSize, ScalarSize), leftTable.Slice(h * ScalarSize, ScalarSize), coefficientSpan.Slice(witnessIndex * ScalarSize, ScalarSize), curve);
                multiply(copyTable.Slice(c * ScalarSize, ScalarSize), rightTable.Slice(h * ScalarSize, ScalarSize), coefficientSpan.Slice((witnessCount + witnessIndex) * ScalarSize, ScalarSize), curve);
                constraints[witnessIndex] = new LigeroLinearConstraint(constraintIndexBase, witnessIndexOffset + witnessIndex, coefficients.Slice(witnessIndex * ScalarSize, ScalarSize));
                constraints[witnessCount + witnessIndex] = new LigeroLinearConstraint(constraintIndexBase + 1, witnessIndexOffset + witnessIndex, coefficients.Slice((witnessCount + witnessIndex) * ScalarSize, ScalarSize));
            }
        }
    }
}
