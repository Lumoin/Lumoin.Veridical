using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// The LogUp sumcheck's round-polynomial computation: one round's univariate
/// polynomial, in evaluation form at the integer points <c>0..degree</c>, of
/// the combined identity
/// <c>P(Y) = h(Y) + λ·eq(z,Y)·( h(Y)·Π_i φ_i(Y) − Σ_i m_i(Y)·Π_{j≠i} φ_j(Y) )</c>
/// with slot 0 the table term (<c>m_0 = m</c>, <c>φ_0 = x − t</c>) and slots
/// <c>i ≥ 1</c> the witness terms (<c>m_i = −1</c>, <c>φ_i = x − w_i</c>).
/// </summary>
/// <remarks>
/// <para>
/// The unweighted <c>h</c> part carries the log-derivative zero-sum; the
/// λ-weighted part carries the helper well-formedness identity reduced to a
/// sumcheck by the Lagrange kernel. Every column is multilinear, so the
/// per-round degree is <c>witnessColumnCount + 3</c> — one from <c>h</c>, one
/// from the kernel, and <c>witnessColumnCount + 1</c> from the φ product — and
/// each round message is its <c>witnessColumnCount + 4</c> evaluations.
/// </para>
/// <para>
/// Like the Spartan round computations this is a bespoke routine for its one
/// identity, pure over spans and delegates: no transcript parameter, no label
/// constants. The prover and verifier drivers compose transcript traffic
/// around it. Rounds bind the pair-adjacent variable
/// (<c>(2j, 2j+1)</c> slicing), matching the Spartan fold convention so the
/// collected challenges form the polynomial-commitment opening point directly.
/// </para>
/// </remarks>
internal static class LogUpSumcheck
{
    private const int ScalarSize = Scalar.SizeBytes;

    //Fixed column slots ahead of the witness columns in the φ/numerator
    //ordering: the table slot. The evaluation-point count is the round degree
    //plus one.
    private const int TableSlotCount = 1;

    //The accumulator columns tracked alongside the φ columns in every round:
    //the helper, the multiplicity and the Lagrange kernel.
    private const int AccumulatorColumnCount = 3;

    /// <summary>
    /// The committed columns the argument adds beyond the witness columns:
    /// the multiplicity column and the helper column.
    /// </summary>
    public const int AuxiliaryColumnCount = 2;


    /// <summary>The per-round polynomial degree for the supplied witness-column count.</summary>
    public static int RoundDegree(int witnessColumnCount) => witnessColumnCount + 3;


    /// <summary>The evaluation count each round message carries: degree + 1.</summary>
    public static int RoundEvaluationCount(int witnessColumnCount) => RoundDegree(witnessColumnCount) + 1;


    /// <summary>
    /// Computes one round's evaluations <c>s(0), …, s(degree)</c> and adds them
    /// into <paramref name="roundEvaluations"/> (which the caller clears).
    /// </summary>
    /// <param name="helper">The current folded helper column, <c>2^remainingVariables × 32</c> bytes.</param>
    /// <param name="multiplicities">The current folded multiplicity column.</param>
    /// <param name="kernel">The current folded Lagrange-kernel column <c>eq(z, ·)</c>.</param>
    /// <param name="table">The current folded table column.</param>
    /// <param name="witnesses">The witness columns, concatenated at a fixed per-column stride; only the folded front of each segment is read.</param>
    /// <param name="witnessStrideEvaluations">The per-column segment stride in evaluations — the original (unfolded) column size.</param>
    /// <param name="remainingVariables">The variable count of the current folded columns; at least 1.</param>
    /// <param name="witnessColumnCount">The witness-column count.</param>
    /// <param name="denominatorChallenge">The challenge <c>x</c>.</param>
    /// <param name="foldingChallenge">The challenge <c>λ</c>.</param>
    /// <param name="roundEvaluations">Receives the summed evaluations, <c>RoundEvaluationCount × 32</c> bytes; cleared by this method.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="curve">The curve whose scalar field the columns live in.</param>
    /// <param name="pool">The pool to rent per-round scratch from.</param>
    public static void ComputeRoundEvaluations(
        ReadOnlySpan<byte> helper,
        ReadOnlySpan<byte> multiplicities,
        ReadOnlySpan<byte> kernel,
        ReadOnlySpan<byte> table,
        ReadOnlySpan<byte> witnesses,
        int witnessStrideEvaluations,
        int remainingVariables,
        int witnessColumnCount,
        ReadOnlySpan<byte> denominatorChallenge,
        ReadOnlySpan<byte> foldingChallenge,
        Span<byte> roundEvaluations,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(remainingVariables, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(witnessColumnCount, 1);

        int size = 1 << remainingVariables;
        int pairCount = size >> 1;
        int columnCount = TableSlotCount + witnessColumnCount;
        int evaluationCount = RoundEvaluationCount(witnessColumnCount);
        ValidateColumnLength(helper, size, nameof(helper));
        ValidateColumnLength(multiplicities, size, nameof(multiplicities));
        ValidateColumnLength(kernel, size, nameof(kernel));
        ValidateColumnLength(table, size, nameof(table));
        ArgumentOutOfRangeException.ThrowIfLessThan(witnessStrideEvaluations, size);
        long expectedWitnessBytes = (long)witnessColumnCount * witnessStrideEvaluations * ScalarSize;
        if(witnesses.Length != expectedWitnessBytes)
        {
            throw new ArgumentException($"{witnessColumnCount} witness segments of stride {witnessStrideEvaluations} need {expectedWitnessBytes} bytes; received {witnesses.Length}.", nameof(witnesses));
        }

        if(roundEvaluations.Length != evaluationCount * ScalarSize)
        {
            throw new ArgumentException($"Round evaluations need {evaluationCount * ScalarSize} bytes; received {roundEvaluations.Length}.", nameof(roundEvaluations));
        }

        roundEvaluations.Clear();

        //Scratch layout: per-column low values and slopes for the accumulator
        //columns (h, m, eq) and the φ columns (t, w_1..w_M), the running
        //per-point values, the φ values at the current point, and the
        //prefix/suffix product ladders for the leave-one-out sums.
        int trackedColumns = AccumulatorColumnCount + columnCount;
        using IMemoryOwner<byte> scratchOwner = pool.Rent((2 * trackedColumns + 3 * (columnCount + 1) + 2) * ScalarSize);
        Span<byte> scratch = scratchOwner.Memory.Span;
        Span<byte> values = scratch[..(trackedColumns * ScalarSize)];
        Span<byte> slopes = scratch.Slice(trackedColumns * ScalarSize, trackedColumns * ScalarSize);
        Span<byte> phis = scratch.Slice(2 * trackedColumns * ScalarSize, columnCount * ScalarSize);
        Span<byte> prefixes = scratch.Slice((2 * trackedColumns + columnCount) * ScalarSize, (columnCount + 1) * ScalarSize);
        Span<byte> suffixes = scratch.Slice((2 * trackedColumns + (2 * columnCount) + 1) * ScalarSize, (columnCount + 1) * ScalarSize);
        Span<byte> temp1 = scratch.Slice((2 * trackedColumns + (3 * columnCount) + 2) * ScalarSize, ScalarSize);
        Span<byte> temp2 = scratch.Slice((2 * trackedColumns + (3 * columnCount) + 3) * ScalarSize, ScalarSize);

        for(int j = 0; j < pairCount; j++)
        {
            //Load the pair's low values and slopes: value(Y) = low + Y·slope
            //on the bound variable. Tracked order: h, m, eq, then the φ
            //columns t, w_1..w_M.
            LoadPair(helper, j, values[..ScalarSize], slopes[..ScalarSize], subtract, curve);
            LoadPair(multiplicities, j, values.Slice(ScalarSize, ScalarSize), slopes.Slice(ScalarSize, ScalarSize), subtract, curve);
            LoadPair(kernel, j, values.Slice(2 * ScalarSize, ScalarSize), slopes.Slice(2 * ScalarSize, ScalarSize), subtract, curve);
            LoadPair(table, j, values.Slice(3 * ScalarSize, ScalarSize), slopes.Slice(3 * ScalarSize, ScalarSize), subtract, curve);
            for(int column = 0; column < witnessColumnCount; column++)
            {
                int slot = AccumulatorColumnCount + TableSlotCount + column;
                LoadPair(witnesses.Slice(column * witnessStrideEvaluations * ScalarSize, size * ScalarSize), j, values.Slice(slot * ScalarSize, ScalarSize), slopes.Slice(slot * ScalarSize, ScalarSize), subtract, curve);
            }

            for(int point = 0; point < evaluationCount; point++)
            {
                //Advance every tracked value by its slope past the first point
                //— evaluating at successive integers costs one add per column.
                if(point > 0)
                {
                    for(int slot = 0; slot < trackedColumns; slot++)
                    {
                        Span<byte> value = values.Slice(slot * ScalarSize, ScalarSize);
                        add(value, slopes.Slice(slot * ScalarSize, ScalarSize), temp1, curve);
                        temp1.CopyTo(value);
                    }
                }

                ReadOnlySpan<byte> helperValue = values[..ScalarSize];
                ReadOnlySpan<byte> multiplicityValue = values.Slice(ScalarSize, ScalarSize);
                ReadOnlySpan<byte> kernelValue = values.Slice(2 * ScalarSize, ScalarSize);

                //φ_0 = x − t, φ_i = x − w_i at this point.
                for(int slot = 0; slot < columnCount; slot++)
                {
                    subtract(denominatorChallenge, values.Slice((AccumulatorColumnCount + slot) * ScalarSize, ScalarSize), phis.Slice(slot * ScalarSize, ScalarSize), curve);
                }

                //Prefix and suffix φ products bracket every leave-one-out term.
                SumcheckChallenge.EncodeOne(prefixes[..ScalarSize]);
                for(int slot = 0; slot < columnCount; slot++)
                {
                    multiply(prefixes.Slice(slot * ScalarSize, ScalarSize), phis.Slice(slot * ScalarSize, ScalarSize), prefixes.Slice((slot + 1) * ScalarSize, ScalarSize), curve);
                }

                SumcheckChallenge.EncodeOne(suffixes.Slice(columnCount * ScalarSize, ScalarSize));
                for(int slot = columnCount - 1; slot >= 0; slot--)
                {
                    multiply(phis.Slice(slot * ScalarSize, ScalarSize), suffixes.Slice((slot + 1) * ScalarSize, ScalarSize), suffixes.Slice(slot * ScalarSize, ScalarSize), curve);
                }

                //S = m·Π_{j≠0} φ_j − Σ_{i≥1} Π_{j≠i} φ_j.
                multiply(multiplicityValue, suffixes.Slice(ScalarSize, ScalarSize), temp1, curve);
                for(int slot = 1; slot < columnCount; slot++)
                {
                    multiply(prefixes.Slice(slot * ScalarSize, ScalarSize), suffixes.Slice((slot + 1) * ScalarSize, ScalarSize), temp2, curve);
                    subtract(temp1, temp2, temp1, curve);
                }

                //inner = h·Πφ − S; term = h + λ·eq·inner.
                multiply(helperValue, prefixes.Slice(columnCount * ScalarSize, ScalarSize), temp2, curve);
                subtract(temp2, temp1, temp1, curve);
                multiply(foldingChallenge, kernelValue, temp2, curve);
                multiply(temp2, temp1, temp1, curve);
                add(helperValue, temp1, temp1, curve);

                Span<byte> evaluation = roundEvaluations.Slice(point * ScalarSize, ScalarSize);
                add(evaluation, temp1, temp2, curve);
                temp2.CopyTo(evaluation);
            }
        }
    }


    /// <summary>
    /// Folds a column in place by the round challenge on the pair-adjacent
    /// variable: <c>folded[j] = column[2j] + r·(column[2j+1] − column[2j])</c>.
    /// The folded half occupies the front of the span.
    /// </summary>
    /// <param name="column">The column evaluations; the front half receives the fold.</param>
    /// <param name="currentSize">The current evaluation count; an even positive number.</param>
    /// <param name="challenge">The round challenge <c>r</c>.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="curve">The curve whose scalar field the column lives in.</param>
    public static void FoldInPlace(
        Span<byte> column,
        int currentSize,
        ReadOnlySpan<byte> challenge,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> slope = stackalloc byte[ScalarSize];
        Span<byte> scaled = stackalloc byte[ScalarSize];
        int half = currentSize >> 1;
        for(int j = 0; j < half; j++)
        {
            ReadOnlySpan<byte> low = column.Slice(2 * j * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> high = column.Slice(((2 * j) + 1) * ScalarSize, ScalarSize);
            subtract(high, low, slope, curve);
            multiply(challenge, slope, scaled, curve);
            add(low, scaled, slope, curve);
            slope.CopyTo(column.Slice(j * ScalarSize, ScalarSize));
        }
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
            throw new ArgumentException($"A column over {size} evaluations needs {size * ScalarSize} bytes; received {column.Length}.", parameterName);
        }
    }
}
