using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The prover-side witness that accompanies a
/// <see cref="HyraxCommitment"/>: the Pedersen blinding factor used for
/// each row commitment. Required at <c>Open</c> time so the prover can
/// derive the row-combined blinding <c>r_combined = ⟨L, r_rows⟩</c> that
/// links the row commitments to the row-folded vector commitment.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout: <c>RowCount</c> canonical 32-byte big-endian scalars
/// concatenated. Slot <c>i</c> holds the blinding factor for the
/// matching row commitment in <see cref="HyraxCommitment.GetRowCommitment(int)"/>.
/// </para>
/// <para>
/// The witness is never sent to the verifier. It exists only on the
/// prover side and is consumed by the opening protocol; once the
/// opening proof is constructed, the witness can be disposed.
/// </para>
/// </remarks>
public sealed class HyraxOpeningWitness: SensitiveMemory
{
    /// <summary>The number of row blinding factors held.</summary>
    public int RowCount { get; }

    /// <summary>The curve identifying the scalar field the blindings live in.</summary>
    public CurveParameterSet Curve { get; }


    internal HyraxOpeningWitness(
        IMemoryOwner<byte> owner,
        int rowCount,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, GetBufferSizeBytes(rowCount), tag)
    {
        RowCount = rowCount;
        Curve = curve;
    }


    /// <summary>
    /// Creates an opening witness with all-zero row blinding factors.
    /// This is the opening witness that matches the identity Hyrax
    /// commitment to a zero vector — the error commitment a raw
    /// instance carries after <c>Prepare</c> (<c>E = 0</c>, zero
    /// blinding). Folded instances (Nova) carry real per-row blinding;
    /// their opening witness is produced by combining the folded
    /// instances' blinding factors homomorphically, not by this helper.
    /// </summary>
    /// <param name="rowCount">The number of rows; matches the matching commitment's <see cref="HyraxCommitment.RowCount"/>.</param>
    /// <param name="curve">The curve. Currently only <see cref="CurveParameterSet.Bls12Curve381"/> is supported.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>An opening witness whose every row blinding factor is the field zero.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="rowCount"/> is non-positive.</exception>
    public static HyraxOpeningWitness CreateZero(
        int rowCount,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rowCount);

        IMemoryOwner<byte> owner = pool.Rent(GetBufferSizeBytes(rowCount));
        owner.Memory.Span[..GetBufferSizeBytes(rowCount)].Clear();

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.CommitmentWitness),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax));

        return new HyraxOpeningWitness(owner, rowCount, curve, tag);
    }


    /// <summary>
    /// Reconstructs an opening witness from its canonical row-blinding
    /// bytes. Used when a folded opening witness is assembled from the
    /// homomorphic combination of the folded instances' blinding
    /// factors (<c>r_combined[i] = r_1[i] + r · r_T[i] + r² · r_2[i]</c>).
    /// </summary>
    /// <param name="blindingBytes">Exactly <c>rowCount × 32</c> bytes — the concatenated canonical big-endian row blinding factors.</param>
    /// <param name="curve">The curve. Currently only <see cref="CurveParameterSet.Bls12Curve381"/> is supported.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>An opening witness wrapping a fresh copy of the supplied blinding bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the byte length is not a positive multiple of the scalar size.</exception>
    public static HyraxOpeningWitness FromCanonical(
        ReadOnlySpan<byte> blindingBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int scalarSize = Scalar.SizeBytes;
        if(blindingBytes.Length == 0 || blindingBytes.Length % scalarSize != 0)
        {
            throw new ArgumentException(
                $"Blinding bytes length {blindingBytes.Length} must be a positive multiple of the scalar size {scalarSize}.",
                nameof(blindingBytes));
        }

        int rowCount = blindingBytes.Length / scalarSize;
        IMemoryOwner<byte> owner = pool.Rent(blindingBytes.Length);
        blindingBytes.CopyTo(owner.Memory.Span[..blindingBytes.Length]);

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.CommitmentWitness),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax));

        return new HyraxOpeningWitness(owner, rowCount, curve, tag);
    }


    /// <summary>
    /// Returns the canonical big-endian bytes of the blinding factor
    /// for row <paramref name="rowIndex"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="rowIndex"/> is outside <c>[0, RowCount)</c>.</exception>
    public ReadOnlySpan<byte> GetRowBlinding(int rowIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(rowIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(rowIndex, RowCount);

        int scalarSize = Scalar.SizeBytes;
        return AsReadOnlySpan().Slice(rowIndex * scalarSize, scalarSize);
    }


    /// <summary>Returns the total buffer size for the supplied row count.</summary>
    public static int GetBufferSizeBytes(int rowCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rowCount);

        return rowCount * Scalar.SizeBytes;
    }
}