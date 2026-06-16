using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// A Hyrax opening proof: the prover-supplied evidence that a
/// committed multilinear extension evaluates to a specific claimed
/// value at a specific point. Verified against the original
/// <see cref="HyraxCommitment"/> and <see cref="HyraxCommitmentKey"/>
/// via the inner-product argument.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in order:
/// </para>
/// <list type="number">
///   <item><description>Fresh Pedersen commitment <c>C_f</c> to the row-folded vector <c>f = L · M</c>. One canonical 48-byte compressed G1 point.</description></item>
///   <item><description>IPA proof elements: <c>IpaRoundCount</c> pairs of <c>(L_round, R_round)</c> G1 points, each pair occupying <c>2 × 48 = 96</c> bytes.</description></item>
///   <item><description>Final scalar <c>a'</c> from the IPA's terminating round: one 32-byte big-endian scalar.</description></item>
///   <item><description>Final blinding <c>r_f</c>: one 32-byte big-endian scalar carrying the original fresh blinding chosen at <c>Open</c> time. The IPA preserves the blinding factor through every fold; this value is what the verifier substitutes into the final algebraic check.</description></item>
///   <item><description>Blinding correction <c>Δr = r_f − r_combined</c>: one 32-byte big-endian scalar. The verifier checks <c>C_f − C_combined == Δr · H</c> to confirm the prover's fresh <c>C_f</c> commits to the same vector as the row-combined commitment <c>sum_i L[i] · C_rows[i]</c>.</description></item>
/// </list>
/// <para>
/// Total size: <c>48 + 96 · IpaRoundCount + 96</c> bytes (the trailing
/// <c>96</c> is <c>32 + 32 + 32</c> for the three scalar fields). For
/// the canonical Hyrax sizes — column count 4 (rounds=2), 256
/// (rounds=8), etc. — this is a few hundred bytes for small MLEs and
/// a few kilobytes for production-sized ones.
/// </para>
/// </remarks>
public sealed class HyraxOpeningProof: SensitiveMemory
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int TrailingScalarCount = 3;

    //The leading C_f commitment and each IPA (L, R) pair are G1 points, so
    //their byte sizes follow the curve. Computed per-instance from Curve
    //rather than pinned to a constant; the static sizer takes the curve.
    private int FCommitmentSize => WellKnownCurves.GetG1CompressedSizeBytes(Curve);
    private int IpaPairSize => 2 * WellKnownCurves.GetG1CompressedSizeBytes(Curve);


    /// <summary>The number of IPA rounds in this proof. Equals <c>⌈log_2(ColumnCount)⌉</c> of the originating commitment.</summary>
    public int IpaRoundCount { get; }

    /// <summary>The curve identifying the group / scalar field.</summary>
    public CurveParameterSet Curve { get; }


    internal HyraxOpeningProof(
        IMemoryOwner<byte> owner,
        int ipaRoundCount,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, GetBufferSizeBytes(ipaRoundCount, curve), tag)
    {
        IpaRoundCount = ipaRoundCount;
        Curve = curve;
    }


    /// <summary>Returns the canonical compressed bytes of <c>C_f</c>, the fresh Pedersen commitment to the row-folded vector.</summary>
    public ReadOnlySpan<byte> GetFCommitment()
    {
        return AsReadOnlySpan()[..FCommitmentSize];
    }


    /// <summary>Returns the canonical compressed bytes of the IPA round <paramref name="round"/> left point.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="round"/> is outside <c>[0, IpaRoundCount)</c>.</exception>
    public ReadOnlySpan<byte> GetIpaLeftPoint(int round)
    {
        ValidateRound(round);
        int offset = FCommitmentSize + round * IpaPairSize;
        return AsReadOnlySpan().Slice(offset, WellKnownCurves.GetG1CompressedSizeBytes(Curve));
    }


    /// <summary>Returns the canonical compressed bytes of the IPA round <paramref name="round"/> right point.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="round"/> is outside <c>[0, IpaRoundCount)</c>.</exception>
    public ReadOnlySpan<byte> GetIpaRightPoint(int round)
    {
        ValidateRound(round);
        int offset = FCommitmentSize + round * IpaPairSize + WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        return AsReadOnlySpan().Slice(offset, WellKnownCurves.GetG1CompressedSizeBytes(Curve));
    }


    /// <summary>Returns the canonical big-endian bytes of the IPA's final scalar <c>a'</c>.</summary>
    public ReadOnlySpan<byte> GetFinalScalar()
    {
        int offset = FCommitmentSize + IpaRoundCount * IpaPairSize;
        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical big-endian bytes of the IPA's final blinding <c>r_f</c>.</summary>
    public ReadOnlySpan<byte> GetFinalBlinding()
    {
        int offset = FCommitmentSize + IpaRoundCount * IpaPairSize + ScalarSize;
        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>
    /// Returns the canonical big-endian bytes of the blinding-correction
    /// scalar <c>Δr = r_f − r_combined</c>. The verifier uses this to
    /// confirm <c>C_f − C_combined == Δr · H</c>.
    /// </summary>
    public ReadOnlySpan<byte> GetBlindingCorrection()
    {
        int offset = FCommitmentSize + IpaRoundCount * IpaPairSize + 2 * ScalarSize;
        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the total proof buffer size for the supplied IPA round count on the given curve.</summary>
    public static int GetBufferSizeBytes(int ipaRoundCount, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(ipaRoundCount);
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        return g1Size + ipaRoundCount * (2 * g1Size) + TrailingScalarCount * ScalarSize;
    }


    /// <summary>
    /// Reconstructs a Hyrax opening proof from its canonical wire bytes
    /// (typically extracted from a Spartan2 proof). Copies the bytes
    /// into a pool-rented buffer; the caller retains ownership of
    /// <paramref name="proofBytes"/>.
    /// </summary>
    /// <param name="proofBytes">Exactly <see cref="GetBufferSizeBytes"/>(<paramref name="ipaRoundCount"/>) bytes — the concatenated wire-format proof.</param>
    /// <param name="ipaRoundCount">The number of IPA rounds the proof was generated for; must match the originating commitment's <c>⌈log_2(ColumnCount)⌉</c>.</param>
    /// <param name="curve">The curve. Currently only <see cref="CurveParameterSet.Bls12Curve381"/> is supported.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>An opening proof wrapping a fresh copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="ipaRoundCount"/> is negative.</exception>
    /// <exception cref="ArgumentException">When the byte length does not match the supplied round count, or the curve is not BLS12-381.</exception>
    public static HyraxOpeningProof FromBytes(
        ReadOnlySpan<byte> proofBytes,
        int ipaRoundCount,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(ipaRoundCount);

        WellKnownCurves.ThrowIfCurveNotWired(curve);

        int expectedLength = GetBufferSizeBytes(ipaRoundCount, curve);
        if(proofBytes.Length != expectedLength)
        {
            throw new ArgumentException(
                $"Hyrax opening proof bytes must be exactly {expectedLength} bytes; received {proofBytes.Length}.",
                nameof(proofBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expectedLength);
        proofBytes.CopyTo(owner.Memory.Span[..expectedLength]);

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.OpeningProof),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax));

        return new HyraxOpeningProof(owner, ipaRoundCount, curve, tag);
    }


    private void ValidateRound(int round)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(round);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(round, IpaRoundCount);
    }
}