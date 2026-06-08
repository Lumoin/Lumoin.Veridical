using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Multilinear-extension evaluation operations against a sparse R1CS
/// matrix viewed as a <see cref="MatrixMleEvaluation"/>.
/// </summary>
/// <remarks>
/// <para>
/// Both operations walk the COO triples once. They use the fact that
/// the triples are sorted by <c>(row, column)</c> so consecutive triples
/// in the same row share their <c>eq(r_y, bits(row))</c> factor — the
/// computation caches the last-seen row's factor instead of
/// recomputing it per triple.
/// </para>
/// <para>
/// All scalar arithmetic dispatches through the supplied delegates.
/// The verbs themselves do not allocate beyond pool-rented scratch
/// buffers and the destination of the operation.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class MatrixMleEvaluationExtensions
{
    extension(MatrixMleEvaluation evaluation)
    {
        /// <summary>
        /// Evaluates the matrix MLE at the supplied row and column
        /// challenge vectors: <c>A~(r_y, r_x) = Σ_{(i,j,v)} v · eq(r_y, bits(i)) · eq(r_x, bits(j))</c>.
        /// </summary>
        /// <param name="rowChallenges">The row-side challenge vector; length must equal <see cref="MatrixMleEvaluation.RowVariableCount"/>.</param>
        /// <param name="columnChallenges">The column-side challenge vector; length must equal <see cref="MatrixMleEvaluation.ColumnVariableCount"/>.</param>
        /// <param name="add">Scalar-add backend.</param>
        /// <param name="subtract">Scalar-subtract backend (used inside <c>(1 − r[b])</c>).</param>
        /// <param name="multiply">Scalar-multiply backend.</param>
        /// <param name="pool">The pool to rent scratch buffers and the result buffer from.</param>
        /// <returns>A scalar carrying the canonical-form evaluation result.</returns>
        public Scalar Evaluate(
            ReadOnlySpan<Scalar> rowChallenges,
            ReadOnlySpan<Scalar> columnChallenges,
            ScalarAddDelegate add,
            ScalarSubtractDelegate subtract,
            ScalarMultiplyDelegate multiply,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(evaluation);
            ArgumentNullException.ThrowIfNull(add);
            ArgumentNullException.ThrowIfNull(subtract);
            ArgumentNullException.ThrowIfNull(multiply);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(evaluation.Matrix.Curve);
            ValidateChallengeVector(rowChallenges, evaluation.RowVariableCount, nameof(rowChallenges));
            ValidateChallengeVector(columnChallenges, evaluation.ColumnVariableCount, nameof(columnChallenges));

            CryptographicOperationCounters.Increment(CryptographicOperationKind.SparseMatrixMleEvaluate, evaluation.Matrix.Curve);

            int elementSize = Scalar.SizeBytes;
            CurveParameterSet curve = evaluation.Matrix.Curve;

            //Pack the row challenges, column challenges, and their (1 − r) complements
            //into contiguous byte buffers indexed by [variable * 2 + bit] so the
            //per-triple eq computation looks up factors with a single Slice.
            using IMemoryOwner<byte> rowFactorsOwner = pool.Rent(2 * evaluation.RowVariableCount * elementSize);
            using IMemoryOwner<byte> columnFactorsOwner = pool.Rent(2 * evaluation.ColumnVariableCount * elementSize);
            Span<byte> rowFactors = rowFactorsOwner.Memory.Span[..(2 * evaluation.RowVariableCount * elementSize)];
            Span<byte> columnFactors = columnFactorsOwner.Memory.Span[..(2 * evaluation.ColumnVariableCount * elementSize)];
            BuildBitFactors(rowChallenges, rowFactors, elementSize, subtract, curve);
            BuildBitFactors(columnChallenges, columnFactors, elementSize, subtract, curve);

            using IMemoryOwner<byte> accumulatorOwner = pool.Rent(elementSize);
            using IMemoryOwner<byte> eqRowOwner = pool.Rent(elementSize);
            using IMemoryOwner<byte> eqColumnOwner = pool.Rent(elementSize);
            using IMemoryOwner<byte> termOwner = pool.Rent(elementSize);
            Span<byte> accumulator = accumulatorOwner.Memory.Span[..elementSize];
            Span<byte> eqRow = eqRowOwner.Memory.Span[..elementSize];
            Span<byte> eqColumn = eqColumnOwner.Memory.Span[..elementSize];
            Span<byte> term = termOwner.Memory.Span[..elementSize];
            accumulator.Clear();

            ReadOnlySpan<byte> rowIndicesBytes = evaluation.Matrix.GetRowIndicesBytes();
            ReadOnlySpan<byte> columnIndicesBytes = evaluation.Matrix.GetColumnIndicesBytes();
            ReadOnlySpan<byte> valuesBytes = evaluation.Matrix.GetValuesBytes();

            int lastRow = -1;
            for(int t = 0; t < evaluation.Matrix.NonzeroCount; t++)
            {
                int row = BinaryPrimitives.ReadInt32BigEndian(rowIndicesBytes.Slice(t * sizeof(int), sizeof(int)));
                int column = BinaryPrimitives.ReadInt32BigEndian(columnIndicesBytes.Slice(t * sizeof(int), sizeof(int)));
                ReadOnlySpan<byte> value = valuesBytes.Slice(t * elementSize, elementSize);

                if(row != lastRow)
                {
                    ComputeEqAtIndex(row, evaluation.RowVariableCount, rowFactors, eqRow, elementSize, multiply, curve);
                    lastRow = row;
                }

                //Column eq cannot be cached at this granularity because the
                //triples are sorted by (row, column); within one row each
                //column index appears at most once, so caching gives no win.
                ComputeEqAtIndex(column, evaluation.ColumnVariableCount, columnFactors, eqColumn, elementSize, multiply, curve);

                multiply(value, eqRow, term, curve);
                multiply(term, eqColumn, term, curve);
                add(accumulator, term, accumulator, curve);
            }

            IMemoryOwner<byte> resultOwner = pool.Rent(elementSize);
            accumulator.CopyTo(resultOwner.Memory.Span[..elementSize]);
            return new Scalar(resultOwner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
        }


        /// <summary>
        /// Computes the column-side row slice of the matrix MLE at the
        /// supplied row challenge vector: returns the length-<c>cols</c>
        /// dense MLE
        /// <c>out[j] = A~(r_y, j) = Σ_{(i, j, v) | column = j} v · eq(r_y, bits(i))</c>.
        /// </summary>
        /// <param name="rowChallenges">The row-side challenge vector; length must equal <see cref="MatrixMleEvaluation.RowVariableCount"/>.</param>
        /// <param name="add">Scalar-add backend.</param>
        /// <param name="subtract">Scalar-subtract backend.</param>
        /// <param name="multiply">Scalar-multiply backend.</param>
        /// <param name="pool">The pool to rent scratch buffers and the result MLE's buffer from.</param>
        /// <returns>A multilinear extension over <see cref="MatrixMleEvaluation.ColumnVariableCount"/> variables representing the row-slice.</returns>
        public MultilinearExtension EvaluateRowSlice(
            ReadOnlySpan<Scalar> rowChallenges,
            ScalarAddDelegate add,
            ScalarSubtractDelegate subtract,
            ScalarMultiplyDelegate multiply,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(evaluation);
            ArgumentNullException.ThrowIfNull(add);
            ArgumentNullException.ThrowIfNull(subtract);
            ArgumentNullException.ThrowIfNull(multiply);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(evaluation.Matrix.Curve);
            ValidateChallengeVector(rowChallenges, evaluation.RowVariableCount, nameof(rowChallenges));

            CryptographicOperationCounters.Increment(CryptographicOperationKind.SparseMatrixMleEvaluate, evaluation.Matrix.Curve);

            int elementSize = Scalar.SizeBytes;
            CurveParameterSet curve = evaluation.Matrix.Curve;
            int columnCount = evaluation.Matrix.ColumnCount;
            int outputSize = columnCount * elementSize;

            using IMemoryOwner<byte> rowFactorsOwner = pool.Rent(2 * evaluation.RowVariableCount * elementSize);
            Span<byte> rowFactors = rowFactorsOwner.Memory.Span[..(2 * evaluation.RowVariableCount * elementSize)];
            BuildBitFactors(rowChallenges, rowFactors, elementSize, subtract, curve);

            using IMemoryOwner<byte> eqRowOwner = pool.Rent(elementSize);
            using IMemoryOwner<byte> termOwner = pool.Rent(elementSize);
            Span<byte> eqRow = eqRowOwner.Memory.Span[..elementSize];
            Span<byte> term = termOwner.Memory.Span[..elementSize];

            using IMemoryOwner<byte> evaluationsOwner = pool.Rent(outputSize);
            Span<byte> evaluations = evaluationsOwner.Memory.Span[..outputSize];
            evaluations.Clear();

            ReadOnlySpan<byte> rowIndicesBytes = evaluation.Matrix.GetRowIndicesBytes();
            ReadOnlySpan<byte> columnIndicesBytes = evaluation.Matrix.GetColumnIndicesBytes();
            ReadOnlySpan<byte> valuesBytes = evaluation.Matrix.GetValuesBytes();

            int lastRow = -1;
            for(int t = 0; t < evaluation.Matrix.NonzeroCount; t++)
            {
                int row = BinaryPrimitives.ReadInt32BigEndian(rowIndicesBytes.Slice(t * sizeof(int), sizeof(int)));
                int column = BinaryPrimitives.ReadInt32BigEndian(columnIndicesBytes.Slice(t * sizeof(int), sizeof(int)));
                ReadOnlySpan<byte> value = valuesBytes.Slice(t * elementSize, elementSize);

                if(row != lastRow)
                {
                    ComputeEqAtIndex(row, evaluation.RowVariableCount, rowFactors, eqRow, elementSize, multiply, curve);
                    lastRow = row;
                }

                multiply(value, eqRow, term, curve);
                Span<byte> outputSlot = evaluations.Slice(column * elementSize, elementSize);
                add(outputSlot, term, outputSlot, curve);
            }


            return MultilinearExtension.FromEvaluations(
                evaluations,
                evaluation.ColumnVariableCount,
                curve,
                pool);
        }
    }


    private static void ValidateChallengeVector(
        ReadOnlySpan<Scalar> challenges,
        int expectedLength,
        string parameterName)
    {
        if(challenges.Length != expectedLength)
        {
            throw new ArgumentException(
                $"Challenge vector length {challenges.Length} does not match the expected variable count {expectedLength}.",
                parameterName);
        }

        for(int i = 0; i < challenges.Length; i++)
        {
            ArgumentNullException.ThrowIfNull(challenges[i]);
        }
    }


    /// <summary>
    /// Writes the per-variable bit factors into <paramref name="destination"/>:
    /// for variable <c>b</c>, slot <c>b*2 + 0</c> holds <c>(1 − r[b])</c>
    /// and slot <c>b*2 + 1</c> holds <c>r[b]</c>. The eq computation
    /// looks these up by bit value without recomputing <c>(1 − r)</c>.
    /// </summary>
    private static void BuildBitFactors(
        ReadOnlySpan<Scalar> challenges,
        Span<byte> destination,
        int elementSize,
        ScalarSubtractDelegate subtract,
        CurveParameterSet curve)
    {
        //Reusable "1" scalar in canonical big-endian: all zero bytes
        //except the last byte = 0x01.
        Span<byte> one = stackalloc byte[Scalar.SizeBytes];
        one.Clear();
        one[^1] = 0x01;

        for(int b = 0; b < challenges.Length; b++)
        {
            ReadOnlySpan<byte> rb = challenges[b].AsReadOnlySpan();

            //slot 0: (1 - r[b]).
            subtract(one, rb, destination.Slice(b * 2 * elementSize, elementSize), curve);
            //slot 1: r[b].
            rb.CopyTo(destination.Slice((b * 2 + 1) * elementSize, elementSize));
        }
    }


    /// <summary>
    /// Computes <c>eq(r, bits(index)) = Π_b factor[b][bit_b(index)]</c>
    /// using the bit factors prebuilt by
    /// <see cref="BuildBitFactors"/>. Writes the canonical-form scalar
    /// into <paramref name="destination"/>.
    /// </summary>
    private static void ComputeEqAtIndex(
        int index,
        int variableCount,
        ReadOnlySpan<byte> bitFactors,
        Span<byte> destination,
        int elementSize,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        if(variableCount == 0)
        {
            //eq over no variables: the empty product is the field one.
            destination.Clear();
            destination[^1] = 0x01;
            return;
        }

        //Bit 0 of the index addresses the first variable. The bit-factor
        //layout has [(1-r_b) at slot 2b][r_b at slot 2b + 1]; combine the
        //index's bit-0 lookup directly into destination, then multiply in
        //each subsequent variable's factor.
        int initialBit = index & 1;
        bitFactors.Slice(initialBit * elementSize, elementSize).CopyTo(destination);

        for(int b = 1; b < variableCount; b++)
        {
            int bit = (index >> b) & 1;
            int factorSlotIndex = (b * 2) + bit;
            ReadOnlySpan<byte> factor = bitFactors.Slice(factorSlotIndex * elementSize, elementSize);
            multiply(destination, factor, destination, curve);
        }
    }
}