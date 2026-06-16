using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// A Spartan2 wire-format proof produced by <c>MaskedSpartanProver</c>:
/// the base proof's contents augmented with the per-sumcheck statistical
/// mask sections (SM.7b, design v3 of <c>ZK-STATMASK-DESIGN.md</c>;
/// lineage Libra §4.1 / CFS 2017): the two mask coefficient-vector
/// commitments (single Pedersen rows), the sums <c>σ</c> and filler sums
/// <c>σ_F</c>, and the two weighted-opening IPA proofs binding the masks'
/// terminal evaluations.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in order:
/// </para>
/// <list type="number">
///   <item><description>Witness commitment: <c>witnessCommitmentRowCount × 48</c> bytes (Hyrax over the witness MLE).</description></item>
///   <item><description>Outer mask commitment: <c>outerMaskCommitmentRowCount × 48</c> bytes (the single-row vector commitment of <c>C*_outer</c>; one row).</description></item>
///   <item><description>Inner mask commitment: <c>innerMaskCommitmentRowCount × 48</c> bytes (the single-row vector commitment of <c>C*_inner</c>; one row).</description></item>
///   <item><description>Outer mask sum <c>σ_outer</c> = Σ_{x ∈ {0,1}^{OuterRoundCount}} g_outer(x): 32 bytes.</description></item>
///   <item><description>Inner mask sum <c>σ_inner</c> = Σ_{y ∈ {0,1}^{InnerRoundCount}} g_inner(y): 32 bytes.</description></item>
///   <item><description>Outer mask filler sum <c>σ_F</c>: 32 bytes.</description></item>
///   <item><description>Inner mask filler sum <c>σ_F</c>: 32 bytes.</description></item>
///   <item><description>Outer sumcheck rounds: <c>OuterRoundCount</c> degree-3 compressed polynomials, <c>3 × 32 = 96</c> bytes each. The polynomials are the blended ones (base round polynomial plus <c>ρ_outer ·</c> masking-polynomial round contribution); the byte size matches the base shape.</description></item>
///   <item><description>Outer terminating evaluations <c>(claim_Az, claim_Bz, claim_Cz)</c>: <c>3 × 32 = 96</c> bytes.</description></item>
///   <item><description>Relaxed error-MLE evaluation <c>E(r_x)</c>: 32 bytes.</description></item>
///   <item><description>Inner sumcheck rounds: <c>InnerRoundCount</c> degree-2 compressed polynomials, <c>2 × 32 = 64</c> bytes each. Blended as above.</description></item>
///   <item><description>Witness evaluation <c>eval_W = z_W(r_y)</c>: 32 bytes.</description></item>
///   <item><description>Error-commitment opening proof at <c>r_x</c>: <see cref="HyraxOpeningProof.GetBufferSizeBytes"/>(<see cref="ErrorIpaRoundCount"/>) bytes.</description></item>
///   <item><description>Outer masking opening proof: <see cref="HyraxOpeningProof.GetBufferSizeBytes"/>(<see cref="OuterMaskIpaRoundCount"/>) bytes.</description></item>
///   <item><description>Inner masking opening proof: <see cref="HyraxOpeningProof.GetBufferSizeBytes"/>(<see cref="InnerMaskIpaRoundCount"/>) bytes.</description></item>
///   <item><description>Witness Hyrax opening proof: <see cref="HyraxOpeningProof.GetBufferSizeBytes"/>(<see cref="WitnessIpaRoundCount"/>) bytes.</description></item>
/// </list>
/// <para>
/// The blending scalars <c>ρ_outer</c> and <c>ρ_inner</c> are not
/// embedded in the proof bytes. The verifier squeezes them from
/// the same Fiat-Shamir transcript state as the prover, reading
/// them at the appropriate transcript positions; no on-wire
/// disclosure is needed and including them would be redundant.
/// The mask sums <c>σ_outer</c> and <c>σ_inner</c> are embedded
/// because the verifier needs them to compute the initial blended
/// sumcheck claims (<c>0 + ρ_outer · σ_outer</c> for the outer
/// sumcheck, <c>joint + ρ_inner · σ_inner</c> for the inner) before
/// running the per-round identity checks; the filler sums <c>σ_F</c>
/// are embedded because the weighted-opening claims
/// <c>v = g(r) + σ_F</c> depend on them (design v3).
/// </para>
/// </remarks>
public sealed class MaskedSpartanProof: SensitiveMemory, IMaskedSpartanProofView
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int OuterRoundCompressedSize = 3 * ScalarSize;
    private const int InnerRoundCompressedSize = 2 * ScalarSize;
    private const int OuterClaimsSize = 3 * ScalarSize;

    //The commitment G1 rows are sized by the curve; computed per-instance
    //from Curve rather than pinned to a constant.
    private int G1Size => WellKnownCurves.GetG1CompressedSizeBytes(Curve);


    /// <summary>The number of rows in the witness Hyrax commitment.</summary>
    public int WitnessCommitmentRowCount { get; }

    /// <summary>The number of rows in the outer masking polynomial's Hyrax commitment.</summary>
    public int OuterMaskCommitmentRowCount { get; }

    /// <summary>The number of rows in the inner masking polynomial's Hyrax commitment.</summary>
    public int InnerMaskCommitmentRowCount { get; }

    /// <summary>The number of outer sumcheck rounds; equals <c>log_2(rows)</c> of the underlying R1CS instance.</summary>
    public int OuterRoundCount { get; }

    /// <summary>The number of inner sumcheck rounds; equals <c>log_2(columns)</c>.</summary>
    public int InnerRoundCount { get; }

    /// <summary>The IPA round count of the embedded witness opening proof.</summary>
    public int WitnessIpaRoundCount { get; }

    /// <summary>The IPA round count of the embedded outer masking opening proof.</summary>
    public int OuterMaskIpaRoundCount { get; }

    /// <summary>The IPA round count of the embedded inner masking opening proof.</summary>
    public int InnerMaskIpaRoundCount { get; }

    /// <summary>The IPA round count of the embedded error-commitment opening proof at <c>r_x</c>.</summary>
    public int ErrorIpaRoundCount { get; }

    /// <summary>The curve identifying the scalar field and group operations.</summary>
    public CurveParameterSet Curve { get; }


    internal MaskedSpartanProof(
        IMemoryOwner<byte> owner,
        int witnessCommitmentRowCount,
        int outerMaskCommitmentRowCount,
        int innerMaskCommitmentRowCount,
        int outerRoundCount,
        int innerRoundCount,
        int witnessIpaRoundCount,
        int outerMaskIpaRoundCount,
        int innerMaskIpaRoundCount,
        int errorIpaRoundCount,
        CurveParameterSet curve,
        Tag tag)
        : base(
            owner,
            GetBufferSizeBytes(
                witnessCommitmentRowCount,
                outerMaskCommitmentRowCount,
                innerMaskCommitmentRowCount,
                outerRoundCount,
                innerRoundCount,
                witnessIpaRoundCount,
                outerMaskIpaRoundCount,
                innerMaskIpaRoundCount,
                errorIpaRoundCount,
                curve),
            tag)
    {
        WitnessCommitmentRowCount = witnessCommitmentRowCount;
        OuterMaskCommitmentRowCount = outerMaskCommitmentRowCount;
        InnerMaskCommitmentRowCount = innerMaskCommitmentRowCount;
        OuterRoundCount = outerRoundCount;
        InnerRoundCount = innerRoundCount;
        WitnessIpaRoundCount = witnessIpaRoundCount;
        OuterMaskIpaRoundCount = outerMaskIpaRoundCount;
        InnerMaskIpaRoundCount = innerMaskIpaRoundCount;
        ErrorIpaRoundCount = errorIpaRoundCount;
        Curve = curve;
    }


    /// <summary>
    /// Packs the per-section inputs into one wire-format proof buffer.
    /// All input bytes are copied; the caller retains ownership of the
    /// input objects and may dispose them after this call returns.
    /// </summary>
    public static MaskedSpartanProof Build(
        PolynomialCommitment witnessCommitment,
        PolynomialCommitment outerMaskCommitment,
        PolynomialCommitment innerMaskCommitment,
        Scalar outerMaskSum,
        Scalar innerMaskSum,
        Scalar outerMaskFillerSum,
        Scalar innerMaskFillerSum,
        IReadOnlyList<SumcheckRound> outerRounds,
        Scalar claimAz,
        Scalar claimBz,
        Scalar claimCz,
        Scalar errorEvaluation,
        IReadOnlyList<SumcheckRound> innerRounds,
        Scalar evalW,
        PolynomialOpening errorOpening,
        PolynomialOpening outerMaskOpening,
        PolynomialOpening innerMaskOpening,
        PolynomialOpening witnessOpening,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(witnessCommitment);
        ArgumentNullException.ThrowIfNull(outerMaskCommitment);
        ArgumentNullException.ThrowIfNull(innerMaskCommitment);
        ArgumentNullException.ThrowIfNull(outerMaskSum);
        ArgumentNullException.ThrowIfNull(innerMaskSum);
        ArgumentNullException.ThrowIfNull(outerMaskFillerSum);
        ArgumentNullException.ThrowIfNull(innerMaskFillerSum);
        ArgumentNullException.ThrowIfNull(outerRounds);
        ArgumentNullException.ThrowIfNull(claimAz);
        ArgumentNullException.ThrowIfNull(claimBz);
        ArgumentNullException.ThrowIfNull(claimCz);
        ArgumentNullException.ThrowIfNull(errorEvaluation);
        ArgumentNullException.ThrowIfNull(innerRounds);
        ArgumentNullException.ThrowIfNull(evalW);
        ArgumentNullException.ThrowIfNull(errorOpening);
        ArgumentNullException.ThrowIfNull(outerMaskOpening);
        ArgumentNullException.ThrowIfNull(innerMaskOpening);
        ArgumentNullException.ThrowIfNull(witnessOpening);
        ArgumentNullException.ThrowIfNull(pool);

        CurveParameterSet curve = witnessCommitment.Curve;

        //The broad commitment/opening types carry only bytes; recover the
        //Hyrax-shaped layout dimensions from the section byte lengths.
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int witnessRowCount = witnessCommitment.AsReadOnlySpan().Length / g1Size;
        int outerMaskRowCount = outerMaskCommitment.AsReadOnlySpan().Length / g1Size;
        int innerMaskRowCount = innerMaskCommitment.AsReadOnlySpan().Length / g1Size;
        int outerRoundCount = outerRounds.Count;
        int innerRoundCount = innerRounds.Count;
        int witnessIpaRoundCount = IpaRoundCountFromBytes(witnessOpening.AsReadOnlySpan().Length, curve);
        int outerMaskIpaRoundCount = IpaRoundCountFromBytes(outerMaskOpening.AsReadOnlySpan().Length, curve);
        int innerMaskIpaRoundCount = IpaRoundCountFromBytes(innerMaskOpening.AsReadOnlySpan().Length, curve);
        int errorIpaRoundCount = IpaRoundCountFromBytes(errorOpening.AsReadOnlySpan().Length, curve);

        ValidateRoundShape(outerRounds, expectedDegree: 3, "outer", curve);
        ValidateRoundShape(innerRounds, expectedDegree: 2, "inner", curve);

        int bufferSize = GetBufferSizeBytes(
            witnessRowCount,
            outerMaskRowCount,
            innerMaskRowCount,
            outerRoundCount,
            innerRoundCount,
            witnessIpaRoundCount,
            outerMaskIpaRoundCount,
            innerMaskIpaRoundCount,
            errorIpaRoundCount,
            curve);
        IMemoryOwner<byte> owner = pool.Rent(bufferSize);
        Span<byte> buffer = owner.Memory.Span[..bufferSize];

        int offset = 0;
        int witnessCommitmentSize = witnessCommitment.AsReadOnlySpan().Length;
        witnessCommitment.AsReadOnlySpan().CopyTo(buffer.Slice(offset, witnessCommitmentSize));
        offset += witnessCommitmentSize;

        int outerMaskCommitmentSize = outerMaskCommitment.AsReadOnlySpan().Length;
        outerMaskCommitment.AsReadOnlySpan().CopyTo(buffer.Slice(offset, outerMaskCommitmentSize));
        offset += outerMaskCommitmentSize;

        int innerMaskCommitmentSize = innerMaskCommitment.AsReadOnlySpan().Length;
        innerMaskCommitment.AsReadOnlySpan().CopyTo(buffer.Slice(offset, innerMaskCommitmentSize));
        offset += innerMaskCommitmentSize;

        outerMaskSum.AsReadOnlySpan().CopyTo(buffer.Slice(offset, ScalarSize));
        offset += ScalarSize;
        innerMaskSum.AsReadOnlySpan().CopyTo(buffer.Slice(offset, ScalarSize));
        offset += ScalarSize;
        outerMaskFillerSum.AsReadOnlySpan().CopyTo(buffer.Slice(offset, ScalarSize));
        offset += ScalarSize;
        innerMaskFillerSum.AsReadOnlySpan().CopyTo(buffer.Slice(offset, ScalarSize));
        offset += ScalarSize;

        for(int i = 0; i < outerRoundCount; i++)
        {
            outerRounds[i].GetCompressedPolynomialBytes()
                .CopyTo(buffer.Slice(offset, OuterRoundCompressedSize));
            offset += OuterRoundCompressedSize;
        }

        claimAz.AsReadOnlySpan().CopyTo(buffer.Slice(offset, ScalarSize));
        offset += ScalarSize;
        claimBz.AsReadOnlySpan().CopyTo(buffer.Slice(offset, ScalarSize));
        offset += ScalarSize;
        claimCz.AsReadOnlySpan().CopyTo(buffer.Slice(offset, ScalarSize));
        offset += ScalarSize;
        errorEvaluation.AsReadOnlySpan().CopyTo(buffer.Slice(offset, ScalarSize));
        offset += ScalarSize;

        for(int i = 0; i < innerRoundCount; i++)
        {
            innerRounds[i].GetCompressedPolynomialBytes()
                .CopyTo(buffer.Slice(offset, InnerRoundCompressedSize));
            offset += InnerRoundCompressedSize;
        }

        evalW.AsReadOnlySpan().CopyTo(buffer.Slice(offset, ScalarSize));
        offset += ScalarSize;

        ReadOnlySpan<byte> errorOpeningBytes = errorOpening.AsReadOnlySpan();
        errorOpeningBytes.CopyTo(buffer.Slice(offset, errorOpeningBytes.Length));
        offset += errorOpeningBytes.Length;

        ReadOnlySpan<byte> outerMaskOpeningBytes = outerMaskOpening.AsReadOnlySpan();
        outerMaskOpeningBytes.CopyTo(buffer.Slice(offset, outerMaskOpeningBytes.Length));
        offset += outerMaskOpeningBytes.Length;

        ReadOnlySpan<byte> innerMaskOpeningBytes = innerMaskOpening.AsReadOnlySpan();
        innerMaskOpeningBytes.CopyTo(buffer.Slice(offset, innerMaskOpeningBytes.Length));
        offset += innerMaskOpeningBytes.Length;

        ReadOnlySpan<byte> witnessOpeningBytes = witnessOpening.AsReadOnlySpan();
        witnessOpeningBytes.CopyTo(buffer.Slice(offset, witnessOpeningBytes.Length));

        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(curve)
            : MergeWithAlgebraicTag(tag, curve);

        return new MaskedSpartanProof(
            owner,
            witnessRowCount,
            outerMaskRowCount,
            innerMaskRowCount,
            outerRoundCount,
            innerRoundCount,
            witnessIpaRoundCount,
            outerMaskIpaRoundCount,
            innerMaskIpaRoundCount,
            errorIpaRoundCount,
            curve,
            effectiveTag);
    }


    /// <summary>
    /// Reconstructs a proof from its canonical wire bytes given the dimensions
    /// (recovered by the verifier from the instance shape and the commitment
    /// key). Copies the bytes into a fresh pool-rented buffer — the sibling of
    /// <see cref="BaseFoldMaskedSpartanProof.FromBytes"/> for the Hyrax-shaped
    /// masked proof, and the entry point for proofs that arrive over a wire or
    /// from storage.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bytes"/> does not have the exact expected length.</exception>
    public static MaskedSpartanProof FromBytes(
        ReadOnlySpan<byte> bytes,
        int witnessCommitmentRowCount,
        int outerMaskCommitmentRowCount,
        int innerMaskCommitmentRowCount,
        int outerRoundCount,
        int innerRoundCount,
        int witnessIpaRoundCount,
        int outerMaskIpaRoundCount,
        int innerMaskIpaRoundCount,
        int errorIpaRoundCount,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(witnessCommitmentRowCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outerMaskCommitmentRowCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(innerMaskCommitmentRowCount);
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(witnessIpaRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(outerMaskIpaRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerMaskIpaRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(errorIpaRoundCount);

        int expected = GetBufferSizeBytes(
            witnessCommitmentRowCount,
            outerMaskCommitmentRowCount,
            innerMaskCommitmentRowCount,
            outerRoundCount,
            innerRoundCount,
            witnessIpaRoundCount,
            outerMaskIpaRoundCount,
            innerMaskIpaRoundCount,
            errorIpaRoundCount,
            curve);
        if(bytes.Length != expected)
        {
            throw new ArgumentException(
                $"Masked Spartan proof must be {expected} bytes for the supplied dimensions; received {bytes.Length}.",
                nameof(bytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expected);
        bytes.CopyTo(owner.Memory.Span[..expected]);

        return new MaskedSpartanProof(
            owner,
            witnessCommitmentRowCount,
            outerMaskCommitmentRowCount,
            innerMaskCommitmentRowCount,
            outerRoundCount,
            innerRoundCount,
            witnessIpaRoundCount,
            outerMaskIpaRoundCount,
            innerMaskIpaRoundCount,
            errorIpaRoundCount,
            curve,
            ComposeAlgebraicTag(curve));
    }


    /// <summary>Returns the embedded witness Hyrax commitment bytes.</summary>
    public ReadOnlySpan<byte> GetWitnessCommitmentBytes()
    {
        int length = CommitmentSizeBytes(WitnessCommitmentRowCount, Curve);

        return AsReadOnlySpan()[..length];
    }


    /// <summary>Returns the embedded outer masking commitment bytes.</summary>
    public ReadOnlySpan<byte> GetOuterMaskCommitmentBytes()
    {
        int offset = WitnessCommitmentSize();
        int length = CommitmentSizeBytes(OuterMaskCommitmentRowCount, Curve);

        return AsReadOnlySpan().Slice(offset, length);
    }


    /// <summary>Returns the embedded inner masking commitment bytes.</summary>
    public ReadOnlySpan<byte> GetInnerMaskCommitmentBytes()
    {
        int offset = WitnessCommitmentSize() + OuterMaskCommitmentSize();
        int length = CommitmentSizeBytes(InnerMaskCommitmentRowCount, Curve);

        return AsReadOnlySpan().Slice(offset, length);
    }


    /// <summary>Returns the canonical bytes of the outer masking-polynomial sum <c>z_outer</c>.</summary>
    public ReadOnlySpan<byte> GetOuterMaskSumBytes()
    {
        int offset = WitnessCommitmentSize() + OuterMaskCommitmentSize() + InnerMaskCommitmentSize();

        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical bytes of the inner masking-polynomial sum <c>z_inner</c>.</summary>
    public ReadOnlySpan<byte> GetInnerMaskSumBytes()
    {
        int offset = WitnessCommitmentSize() + OuterMaskCommitmentSize() + InnerMaskCommitmentSize() + ScalarSize;

        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical bytes of the outer mask's filler sum <c>σ_F</c>.</summary>
    public ReadOnlySpan<byte> GetOuterMaskFillerSumBytes()
    {
        int offset = WitnessCommitmentSize() + OuterMaskCommitmentSize() + InnerMaskCommitmentSize() + (2 * ScalarSize);

        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical bytes of the inner mask's filler sum <c>σ_F</c>.</summary>
    public ReadOnlySpan<byte> GetInnerMaskFillerSumBytes()
    {
        int offset = WitnessCommitmentSize() + OuterMaskCommitmentSize() + InnerMaskCommitmentSize() + (3 * ScalarSize);

        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the compressed bytes of the outer sumcheck round at <paramref name="roundIndex"/>.</summary>
    public ReadOnlySpan<byte> GetOuterRoundCompressedBytes(int roundIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(roundIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(roundIndex, OuterRoundCount);
        int offset = MaskingSectionEnd() + (roundIndex * OuterRoundCompressedSize);

        return AsReadOnlySpan().Slice(offset, OuterRoundCompressedSize);
    }


    /// <summary>Returns the canonical bytes of <c>claim_Az</c>.</summary>
    public ReadOnlySpan<byte> GetClaimAzBytes()
    {
        int offset = MaskingSectionEnd() + (OuterRoundCount * OuterRoundCompressedSize);

        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical bytes of <c>claim_Bz</c>.</summary>
    public ReadOnlySpan<byte> GetClaimBzBytes()
    {
        int offset = MaskingSectionEnd() + (OuterRoundCount * OuterRoundCompressedSize) + ScalarSize;

        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical bytes of <c>claim_Cz</c>.</summary>
    public ReadOnlySpan<byte> GetClaimCzBytes()
    {
        int offset = MaskingSectionEnd() + (OuterRoundCount * OuterRoundCompressedSize) + (2 * ScalarSize);

        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical bytes of the relaxed error-MLE evaluation <c>E(r_x)</c>.</summary>
    public ReadOnlySpan<byte> GetErrorEvaluationBytes()
    {
        int offset = MaskingSectionEnd() + (OuterRoundCount * OuterRoundCompressedSize) + OuterClaimsSize;

        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the compressed bytes of the inner sumcheck round at <paramref name="roundIndex"/>.</summary>
    public ReadOnlySpan<byte> GetInnerRoundCompressedBytes(int roundIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(roundIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(roundIndex, InnerRoundCount);
        int offset = OuterSectionEnd() + (roundIndex * InnerRoundCompressedSize);

        return AsReadOnlySpan().Slice(offset, InnerRoundCompressedSize);
    }


    /// <summary>Returns the canonical bytes of the witness MLE evaluation <c>eval_W</c>.</summary>
    public ReadOnlySpan<byte> GetEvalWBytes()
    {
        int offset = OuterSectionEnd() + (InnerRoundCount * InnerRoundCompressedSize);

        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the embedded error-commitment opening proof bytes (at <c>r_x</c>).</summary>
    public ReadOnlySpan<byte> GetErrorOpeningProofBytes()
    {
        int offset = OpeningsSectionStart();
        int length = OpeningProofSizeBytes(ErrorIpaRoundCount, Curve);

        return AsReadOnlySpan().Slice(offset, length);
    }


    /// <summary>Returns the embedded outer masking opening proof bytes.</summary>
    public ReadOnlySpan<byte> GetOuterMaskOpeningProofBytes()
    {
        int offset = OpeningsSectionStart() + OpeningProofSizeBytes(ErrorIpaRoundCount, Curve);
        int length = OpeningProofSizeBytes(OuterMaskIpaRoundCount, Curve);

        return AsReadOnlySpan().Slice(offset, length);
    }


    /// <summary>Returns the embedded inner masking opening proof bytes.</summary>
    public ReadOnlySpan<byte> GetInnerMaskOpeningProofBytes()
    {
        int offset = OpeningsSectionStart()
            + OpeningProofSizeBytes(ErrorIpaRoundCount, Curve)
            + OpeningProofSizeBytes(OuterMaskIpaRoundCount, Curve);
        int length = OpeningProofSizeBytes(InnerMaskIpaRoundCount, Curve);

        return AsReadOnlySpan().Slice(offset, length);
    }


    /// <summary>Returns the embedded witness Hyrax opening proof bytes.</summary>
    public ReadOnlySpan<byte> GetWitnessOpeningProofBytes()
    {
        int offset = OpeningsSectionStart()
            + OpeningProofSizeBytes(ErrorIpaRoundCount, Curve)
            + OpeningProofSizeBytes(OuterMaskIpaRoundCount, Curve)
            + OpeningProofSizeBytes(InnerMaskIpaRoundCount, Curve);
        int length = OpeningProofSizeBytes(WitnessIpaRoundCount, Curve);

        return AsReadOnlySpan().Slice(offset, length);
    }


    /// <summary>
    /// Returns a zero-copy window over the scheme-independent sumcheck middle
    /// (outer rounds, the three claims, <c>E(r_x)</c>, inner rounds,
    /// <c>eval_W</c>), shared with <see cref="BaseFoldMaskedSpartanProof"/> and
    /// consumed by the masked verifier core. This proof must outlive the part.
    /// </summary>
    internal SpartanSumcheckProofPart GetSumcheckPart() =>
        new(this, MaskingSectionEnd(), OuterRoundCount, InnerRoundCount, Curve);


    /// <summary>Returns the total wire-format byte size for the supplied dimensions.</summary>
    public static int GetBufferSizeBytes(
        int witnessCommitmentRowCount,
        int outerMaskCommitmentRowCount,
        int innerMaskCommitmentRowCount,
        int outerRoundCount,
        int innerRoundCount,
        int witnessIpaRoundCount,
        int outerMaskIpaRoundCount,
        int innerMaskIpaRoundCount,
        int errorIpaRoundCount,
        CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(witnessCommitmentRowCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outerMaskCommitmentRowCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(innerMaskCommitmentRowCount);
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);

        return CommitmentSizeBytes(witnessCommitmentRowCount, curve)
            + CommitmentSizeBytes(outerMaskCommitmentRowCount, curve)
            + CommitmentSizeBytes(innerMaskCommitmentRowCount, curve)
            + (4 * ScalarSize) //σ_outer + σ_inner + the two filler sums
            + (outerRoundCount * OuterRoundCompressedSize)
            + OuterClaimsSize
            + ScalarSize //E(r_x)
            + (innerRoundCount * InnerRoundCompressedSize)
            + ScalarSize //eval_W
            + OpeningProofSizeBytes(errorIpaRoundCount, curve)
            + OpeningProofSizeBytes(outerMaskIpaRoundCount, curve)
            + OpeningProofSizeBytes(innerMaskIpaRoundCount, curve)
            + OpeningProofSizeBytes(witnessIpaRoundCount, curve);
    }


    //Section size helpers. These mirror the byte layout the Hyrax commitment
    //scheme produces, expressed in curve-generic terms so the proof type names
    //no scheme type. A future scheme with a differently-shaped proof brings its
    //own layout; this proof remains the Hyrax-shaped one.
    private static int CommitmentSizeBytes(int rowCount, CurveParameterSet curve)
    {
        return rowCount * WellKnownCurves.GetG1CompressedSizeBytes(curve);
    }


    private static int OpeningProofSizeBytes(int ipaRoundCount, CurveParameterSet curve)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        return g1Size + (ipaRoundCount * (2 * g1Size)) + (3 * ScalarSize);
    }


    //Inverse of OpeningProofSizeBytes: rounds = (len − g1 − 3·scalar) / (2·g1).
    private static int IpaRoundCountFromBytes(int lengthBytes, CurveParameterSet curve)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        return (lengthBytes - g1Size - (3 * ScalarSize)) / (2 * g1Size);
    }


    private int WitnessCommitmentSize() => WitnessCommitmentRowCount * G1Size;
    private int OuterMaskCommitmentSize() => OuterMaskCommitmentRowCount * G1Size;
    private int InnerMaskCommitmentSize() => InnerMaskCommitmentRowCount * G1Size;

    private int MaskingSectionEnd() =>
        WitnessCommitmentSize()
        + OuterMaskCommitmentSize()
        + InnerMaskCommitmentSize()
        + (4 * ScalarSize);

    //End of the outer section: masking section, outer rounds, the three
    //outer claims, and E(r_x). The inner rounds start here.
    private int OuterSectionEnd() =>
        MaskingSectionEnd()
        + (OuterRoundCount * OuterRoundCompressedSize)
        + OuterClaimsSize
        + ScalarSize;

    private int OpeningsSectionStart() =>
        OuterSectionEnd()
        + (InnerRoundCount * InnerRoundCompressedSize)
        + ScalarSize;


    private static void ValidateRoundShape(
        IReadOnlyList<SumcheckRound> rounds,
        int expectedDegree,
        string phase,
        CurveParameterSet curve)
    {
        for(int i = 0; i < rounds.Count; i++)
        {
            SumcheckRound round = rounds[i];
            if(round.Curve.Code != curve.Code)
            {
                throw new ArgumentException(
                    $"{phase} sumcheck round {i} has curve {round.Curve}; expected {curve}.");
            }
            if(round.Degree != expectedDegree)
            {
                throw new ArgumentException(
                    $"{phase} sumcheck round {i} has degree {round.Degree}; expected {expectedDegree}.");
            }
        }
    }


    private static Tag ComposeAlgebraicTag(CurveParameterSet curve)
    {
        return Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.ZkProof),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(SpartanProofVariant), (object)SpartanProofVariant.MaskedStatistical));
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, CurveParameterSet curve)
    {
        return tag.With(
            (typeof(AlgebraicRole), (object)AlgebraicRole.ZkProof),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(SpartanProofVariant), (object)SpartanProofVariant.MaskedStatistical));
    }
}