using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// A Hyrax commitment to a multilinear extension: one Pedersen vector
/// commitment per row of the underlying <c>RowCount × ColumnCount</c>
/// matrix decomposition of the MLE's evaluations.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout: <c>RowCount</c> canonical 48-byte compressed G1
/// points concatenated, slot <c>i</c> holding the commitment to the
/// MLE row <c>M[i] = mle.evaluations[i · ColumnCount .. i · ColumnCount + ColumnCount - 1]</c>.
/// </para>
/// <para>
/// The decomposition convention is documented on
/// <see cref="HyraxCommitmentDimensions"/>: the lower <c>⌊n/2⌋</c>
/// bits of the storage index determine the column, the upper
/// <c>⌈n/2⌉</c> bits determine the row. The commitment is hiding
/// (one Pedersen blinding factor per row, kept by the prover in
/// the corresponding <see cref="HyraxOpeningWitness"/>) and binding
/// under the discrete-log assumption on the underlying group.
/// </para>
/// </remarks>
public sealed class HyraxCommitment: SensitiveMemory
{
    /// <summary>The number of matrix rows (one Pedersen commitment per row).</summary>
    public int RowCount { get; }

    /// <summary>The number of matrix columns; matches the Pedersen vector length used.</summary>
    public int ColumnCount { get; }

    /// <summary>The number of variables <c>n</c> of the committed MLE.</summary>
    public int VariableCount { get; }

    /// <summary>The curve identifying the group the commitments live in.</summary>
    public CurveParameterSet Curve { get; }


    internal HyraxCommitment(
        IMemoryOwner<byte> owner,
        int rowCount,
        int columnCount,
        int variableCount,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, tag)
    {
        RowCount = rowCount;
        ColumnCount = columnCount;
        VariableCount = variableCount;
        Curve = curve;
    }


    /// <summary>
    /// Returns the canonical compressed bytes of the row commitment
    /// <c>C_rows[i]</c>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="rowIndex"/> is outside <c>[0, RowCount)</c>.</exception>
    public ReadOnlySpan<byte> GetRowCommitment(int rowIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(rowIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(rowIndex, RowCount);

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        return AsReadOnlySpan().Slice(rowIndex * g1Size, g1Size);
    }


    /// <summary>Returns the total buffer size for the supplied row count on the given curve.</summary>
    public static int GetBufferSizeBytes(int rowCount, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rowCount);

        return rowCount * WellKnownCurves.GetG1CompressedSizeBytes(curve);
    }


    /// <summary>
    /// Reconstructs a Hyrax commitment from its canonical wire bytes
    /// (typically extracted from a Spartan2 proof). Copies the bytes
    /// into a pool-rented buffer; the caller retains ownership of
    /// <paramref name="commitmentBytes"/>.
    /// </summary>
    /// <param name="commitmentBytes">Exactly <c>rowCount × 48</c> bytes — the concatenated canonical compressed-G1 row commitments.</param>
    /// <param name="rowCount">The number of rows; equals the row count of the underlying Hyrax matrix decomposition.</param>
    /// <param name="columnCount">The number of columns; equals the column count of the decomposition.</param>
    /// <param name="variableCount">The variable count of the original committed MLE; <c>RowCount · ColumnCount = 2^variableCount</c>.</param>
    /// <param name="curve">The curve. Currently only <see cref="CurveParameterSet.Bls12Curve381"/> is supported.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A commitment wrapping a fresh copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When dimensions are non-positive.</exception>
    /// <exception cref="ArgumentException">When the byte length does not match the supplied dimensions or the curve is not BLS12-381.</exception>
    public static HyraxCommitment FromBytes(
        ReadOnlySpan<byte> commitmentBytes,
        int rowCount,
        int columnCount,
        int variableCount,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rowCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(columnCount);
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);

        WellKnownCurves.ThrowIfCurveNotWired(curve);

        int expectedLength = GetBufferSizeBytes(rowCount, curve);
        if(commitmentBytes.Length != expectedLength)
        {
            throw new ArgumentException(
                $"Hyrax commitment bytes must be exactly {expectedLength} bytes ({rowCount} × {WellKnownCurves.GetG1CompressedSizeBytes(curve)}); received {commitmentBytes.Length}.",
                nameof(commitmentBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expectedLength);
        commitmentBytes.CopyTo(owner.Memory.Span[..expectedLength]);

        Tag tag = Tag.Create(AlgebraicRole.Commitment)
            .With(curve)
            .With(CommitmentScheme.Hyrax)
            .With(new HyraxCommitmentDimensions(variableCount, rowCount, columnCount));

        return new HyraxCommitment(owner, rowCount, columnCount, variableCount, curve, tag);
    }
}