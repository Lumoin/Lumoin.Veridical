using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// A Spartan2 wire-format proof: every byte the verifier needs to
/// validate that an R1CS instance is satisfied by a hidden witness.
/// Packed into one pool-rented buffer in fixed-layout sections.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in order:
/// </para>
/// <list type="number">
///   <item><description>Witness commitment: <see cref="HyraxCommitment.GetBufferSizeBytes"/>(<see cref="WitnessCommitmentRowCount"/>) bytes — the prover's Hyrax commitment to the witness MLE.</description></item>
///   <item><description>Outer sumcheck rounds: <see cref="OuterRoundCount"/> degree-3 compressed polynomials, <c>3 × 32 = 96</c> bytes each.</description></item>
///   <item><description>Outer terminating evaluations <c>(claim_Az, claim_Bz, claim_Cz)</c>: <c>3 × 32 = 96</c> bytes.</description></item>
///   <item><description>Relaxed error-MLE evaluation <c>E(r_x)</c>: <c>32</c> bytes. For a raw-prepared instance this is the field zero; for a folded instance it carries the accumulated error term.</description></item>
///   <item><description>Inner sumcheck rounds: <see cref="InnerRoundCount"/> degree-2 compressed polynomials, <c>2 × 32 = 64</c> bytes each.</description></item>
///   <item><description>Witness evaluation <c>eval_W = z_W(r_y)</c>: <c>32</c> bytes.</description></item>
///   <item><description>Error-commitment Hyrax opening proof at <c>r_x</c>: <see cref="HyraxOpeningProof.GetBufferSizeBytes"/>(<see cref="ErrorIpaRoundCount"/>) bytes — proves <c>E(r_x)</c> against the instance's error commitment.</description></item>
///   <item><description>Witness Hyrax opening proof at <c>r_y</c>: <see cref="HyraxOpeningProof.GetBufferSizeBytes"/>(<see cref="IpaRoundCount"/>) bytes.</description></item>
/// </list>
/// <para>
/// The byte layout is part of the wire-format contract — the
/// Spartan2 codebase documentation (<c>SPARTAN2.md</c>) pins it
/// alongside the transcript schedule.
/// </para>
/// </remarks>
public sealed class SpartanProof: SensitiveMemory
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int OuterRoundCompressedSize = 3 * ScalarSize;
    private const int InnerRoundCompressedSize = 2 * ScalarSize;
    private const int OuterClaimsSize = 3 * ScalarSize;

    //The witness-commitment G1 rows are sized by the curve; computed
    //per-instance from Curve rather than pinned to a constant.
    private int G1Size => WellKnownCurves.GetG1CompressedSizeBytes(Curve);


    /// <summary>The number of rows in the witness Hyrax commitment.</summary>
    public int WitnessCommitmentRowCount { get; }

    /// <summary>The number of outer-sumcheck rounds.</summary>
    public int OuterRoundCount { get; }

    /// <summary>The number of inner-sumcheck rounds.</summary>
    public int InnerRoundCount { get; }

    /// <summary>The number of IPA rounds inside the embedded witness Hyrax opening proof.</summary>
    public int IpaRoundCount { get; }

    /// <summary>The number of IPA rounds inside the embedded error-commitment Hyrax opening proof.</summary>
    public int ErrorIpaRoundCount { get; }

    /// <summary>The curve identifying the scalar field and group operations.</summary>
    public CurveParameterSet Curve { get; }


    internal SpartanProof(
        IMemoryOwner<byte> owner,
        int witnessCommitmentRowCount,
        int outerRoundCount,
        int innerRoundCount,
        int ipaRoundCount,
        int errorIpaRoundCount,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, GetBufferSizeBytes(witnessCommitmentRowCount, outerRoundCount, innerRoundCount, ipaRoundCount, errorIpaRoundCount, curve), tag)
    {
        WitnessCommitmentRowCount = witnessCommitmentRowCount;
        OuterRoundCount = outerRoundCount;
        InnerRoundCount = innerRoundCount;
        IpaRoundCount = ipaRoundCount;
        ErrorIpaRoundCount = errorIpaRoundCount;
        Curve = curve;
    }


    /// <summary>
    /// Packs the per-section inputs into one wire-format proof buffer.
    /// All input bytes are copied; the caller retains ownership of the
    /// input objects and may dispose them after this call returns.
    /// </summary>
    /// <param name="witnessCommitment">The prover's Hyrax commitment to the witness MLE.</param>
    /// <param name="outerRounds">The outer sumcheck rounds; each must carry a degree-3 compressed round polynomial.</param>
    /// <param name="claimAz">The outer sumcheck's terminating <c>Az(r_x)</c>.</param>
    /// <param name="claimBz">The outer sumcheck's terminating <c>Bz(r_x)</c>.</param>
    /// <param name="claimCz">The outer sumcheck's terminating <c>Cz(r_x)</c>.</param>
    /// <param name="errorEvaluation">The relaxed error-MLE evaluation <c>E(r_x)</c> from the outer sumcheck.</param>
    /// <param name="innerRounds">The inner sumcheck rounds; each must carry a degree-2 compressed round polynomial.</param>
    /// <param name="evalW">The witness MLE evaluation at <c>r_y</c>.</param>
    /// <param name="errorOpeningProof">The opening proof for the instance's error commitment at <c>r_x</c>, attesting <c>E(r_x)</c>.</param>
    /// <param name="hyraxOpeningProof">The opening proof for the witness commitment at <c>r_y</c>.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A proof wrapping a pool-rented copy of every input's bytes.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When round degrees, lengths, or curves do not match the expected layout.</exception>
    public static SpartanProof Build(
        PolynomialCommitment witnessCommitment,
        IReadOnlyList<SumcheckRound> outerRounds,
        Scalar claimAz,
        Scalar claimBz,
        Scalar claimCz,
        Scalar errorEvaluation,
        IReadOnlyList<SumcheckRound> innerRounds,
        Scalar evalW,
        PolynomialOpening errorOpeningProof,
        PolynomialOpening hyraxOpeningProof,
        SensitiveMemoryPool<byte> pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(witnessCommitment);
        ArgumentNullException.ThrowIfNull(outerRounds);
        ArgumentNullException.ThrowIfNull(claimAz);
        ArgumentNullException.ThrowIfNull(claimBz);
        ArgumentNullException.ThrowIfNull(claimCz);
        ArgumentNullException.ThrowIfNull(errorEvaluation);
        ArgumentNullException.ThrowIfNull(innerRounds);
        ArgumentNullException.ThrowIfNull(evalW);
        ArgumentNullException.ThrowIfNull(errorOpeningProof);
        ArgumentNullException.ThrowIfNull(hyraxOpeningProof);
        ArgumentNullException.ThrowIfNull(pool);

        CurveParameterSet curve = witnessCommitment.Curve;
        int outerRoundCount = outerRounds.Count;
        int innerRoundCount = innerRounds.Count;

        //The broad commitment/opening types carry only bytes; recover the
        //Hyrax-shaped layout dimensions from the section byte lengths (the
        //inverse of the size formulas below), naming no scheme type.
        int witnessRowCount = WitnessRowCountFromBytes(witnessCommitment.AsReadOnlySpan().Length, curve);
        int ipaRoundCount = IpaRoundCountFromBytes(hyraxOpeningProof.AsReadOnlySpan().Length, curve);
        int errorIpaRoundCount = IpaRoundCountFromBytes(errorOpeningProof.AsReadOnlySpan().Length, curve);

        ValidateRoundShape(outerRounds, expectedDegree: 3, "outer", curve);
        ValidateRoundShape(innerRounds, expectedDegree: 2, "inner", curve);

        int bufferSize = GetBufferSizeBytes(witnessRowCount, outerRoundCount, innerRoundCount, ipaRoundCount, errorIpaRoundCount, curve);
        IMemoryOwner<byte> owner = pool.Rent(bufferSize);
        Span<byte> buffer = owner.Memory.Span[..bufferSize];

        int offset = 0;
        int commitmentSize = witnessCommitment.AsReadOnlySpan().Length;
        witnessCommitment.AsReadOnlySpan().CopyTo(buffer.Slice(offset, commitmentSize));
        offset += commitmentSize;

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

        ReadOnlySpan<byte> errorOpeningBytes = errorOpeningProof.AsReadOnlySpan();
        errorOpeningBytes.CopyTo(buffer.Slice(offset, errorOpeningBytes.Length));
        offset += errorOpeningBytes.Length;

        hyraxOpeningProof.AsReadOnlySpan().CopyTo(buffer.Slice(offset, hyraxOpeningProof.AsReadOnlySpan().Length));

        var dimensions = new SpartanProofDimensions(outerRoundCount, innerRoundCount, ipaRoundCount, errorIpaRoundCount);
        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(dimensions, curve)
            : MergeWithAlgebraicTag(tag, dimensions, curve);

        return new SpartanProof(owner, witnessRowCount, outerRoundCount, innerRoundCount, ipaRoundCount, errorIpaRoundCount, curve, effectiveTag);
    }


    /// <summary>
    /// Reconstructs a proof from its canonical wire bytes given the dimensions
    /// (recovered by the verifier from the instance shape and the commitment
    /// key). Copies the bytes into a fresh pool-rented buffer — the sibling of
    /// <see cref="BaseFoldSpartanProof.FromBytes"/> for the Hyrax-shaped proof,
    /// and the entry point for proofs that arrive over a wire or from storage.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bytes"/> does not have the exact expected length.</exception>
    public static SpartanProof FromBytes(
        ReadOnlySpan<byte> bytes,
        int witnessCommitmentRowCount,
        int outerRoundCount,
        int innerRoundCount,
        int ipaRoundCount,
        int errorIpaRoundCount,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(witnessCommitmentRowCount);
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(ipaRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(errorIpaRoundCount);

        int expected = GetBufferSizeBytes(witnessCommitmentRowCount, outerRoundCount, innerRoundCount, ipaRoundCount, errorIpaRoundCount, curve);
        if(bytes.Length != expected)
        {
            throw new ArgumentException(
                $"Spartan proof must be {expected} bytes for the supplied dimensions; received {bytes.Length}.",
                nameof(bytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expected);
        bytes.CopyTo(owner.Memory.Span[..expected]);

        var dimensions = new SpartanProofDimensions(outerRoundCount, innerRoundCount, ipaRoundCount, errorIpaRoundCount);

        return new SpartanProof(owner, witnessCommitmentRowCount, outerRoundCount, innerRoundCount, ipaRoundCount, errorIpaRoundCount, curve, ComposeAlgebraicTag(dimensions, curve));
    }


    /// <summary>Returns the embedded witness commitment bytes.</summary>
    public ReadOnlySpan<byte> GetWitnessCommitmentBytes()
    {
        int length = WitnessCommitmentSizeBytes(WitnessCommitmentRowCount, Curve);
        return AsReadOnlySpan()[..length];
    }


    /// <summary>Returns the compressed bytes of the outer sumcheck round at <paramref name="roundIndex"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="roundIndex"/> is outside <c>[0, OuterRoundCount)</c>.</exception>
    public ReadOnlySpan<byte> GetOuterRoundCompressedBytes(int roundIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(roundIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(roundIndex, OuterRoundCount);
        int offset = WitnessCommitmentSize() + (roundIndex * OuterRoundCompressedSize);
        return AsReadOnlySpan().Slice(offset, OuterRoundCompressedSize);
    }


    /// <summary>Returns the canonical bytes of <c>claim_Az</c>.</summary>
    public ReadOnlySpan<byte> GetClaimAzBytes()
    {
        int offset = WitnessCommitmentSize() + (OuterRoundCount * OuterRoundCompressedSize);
        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical bytes of <c>claim_Bz</c>.</summary>
    public ReadOnlySpan<byte> GetClaimBzBytes()
    {
        int offset = WitnessCommitmentSize() + (OuterRoundCount * OuterRoundCompressedSize) + ScalarSize;
        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical bytes of <c>claim_Cz</c>.</summary>
    public ReadOnlySpan<byte> GetClaimCzBytes()
    {
        int offset = WitnessCommitmentSize() + (OuterRoundCount * OuterRoundCompressedSize) + (2 * ScalarSize);
        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the canonical bytes of the relaxed error-MLE evaluation <c>E(r_x)</c>.</summary>
    public ReadOnlySpan<byte> GetErrorEvaluationBytes()
    {
        int offset = WitnessCommitmentSize() + (OuterRoundCount * OuterRoundCompressedSize) + OuterClaimsSize;
        return AsReadOnlySpan().Slice(offset, ScalarSize);
    }


    /// <summary>Returns the compressed bytes of the inner sumcheck round at <paramref name="roundIndex"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="roundIndex"/> is outside <c>[0, InnerRoundCount)</c>.</exception>
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


    /// <summary>Returns the embedded witness opening proof bytes (at <c>r_y</c>).</summary>
    public ReadOnlySpan<byte> GetHyraxOpeningProofBytes()
    {
        int offset = OpeningsSectionStart() + OpeningProofSizeBytes(ErrorIpaRoundCount, Curve);
        int length = OpeningProofSizeBytes(IpaRoundCount, Curve);
        return AsReadOnlySpan().Slice(offset, length);
    }


    /// <summary>
    /// Returns a zero-copy window over the scheme-independent middle block
    /// (outer rounds, the three claims, <c>E(r_x)</c>, inner rounds,
    /// <c>eval_W</c>), shared with <see cref="BaseFoldSpartanProof"/> and
    /// consumed by the sumcheck verifier drivers. The window reads from this
    /// proof's buffer, so this proof must outlive the returned part.
    /// </summary>
    internal SpartanSumcheckProofPart GetSumcheckPart() =>
        new(this, WitnessCommitmentSize(), OuterRoundCount, InnerRoundCount, Curve);


    /// <summary>Returns the total wire-format byte size for the supplied dimensions on the given curve.</summary>
    public static int GetBufferSizeBytes(int witnessCommitmentRowCount, int outerRoundCount, int innerRoundCount, int ipaRoundCount, int errorIpaRoundCount, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(witnessCommitmentRowCount);
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);

        return WitnessCommitmentSizeBytes(witnessCommitmentRowCount, curve)
            + (outerRoundCount * OuterRoundCompressedSize)
            + OuterClaimsSize
            + ScalarSize //E(r_x)
            + (innerRoundCount * InnerRoundCompressedSize)
            + ScalarSize //eval_W
            + OpeningProofSizeBytes(errorIpaRoundCount, curve)
            + OpeningProofSizeBytes(ipaRoundCount, curve);
    }


    //Section size helpers. These mirror the byte layout the Hyrax commitment
    //scheme produces (a commitment is one compressed-G1 point per row; an
    //opening proof is C_f + IpaRounds·(L,R) pairs + three trailing scalars),
    //expressed in curve-generic terms so the proof type names no scheme type.
    //If a future scheme assembles a differently-shaped proof it brings its own
    //layout; this proof remains the Hyrax-shaped one.
    private static int WitnessCommitmentSizeBytes(int rowCount, CurveParameterSet curve)
    {
        return rowCount * WellKnownCurves.GetG1CompressedSizeBytes(curve);
    }


    private static int OpeningProofSizeBytes(int ipaRoundCount, CurveParameterSet curve)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        return g1Size + (ipaRoundCount * (2 * g1Size)) + (3 * ScalarSize);
    }


    private static int WitnessRowCountFromBytes(int lengthBytes, CurveParameterSet curve)
    {
        return lengthBytes / WellKnownCurves.GetG1CompressedSizeBytes(curve);
    }


    //Inverse of OpeningProofSizeBytes: rounds = (len − g1 − 3·scalar) / (2·g1).
    private static int IpaRoundCountFromBytes(int lengthBytes, CurveParameterSet curve)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        return (lengthBytes - g1Size - (3 * ScalarSize)) / (2 * g1Size);
    }


    private int WitnessCommitmentSize() => WitnessCommitmentRowCount * G1Size;

    //End of the outer section: witness commitment, outer rounds, the
    //three outer claims, and E(r_x). The inner rounds start here.
    private int OuterSectionEnd() =>
        WitnessCommitmentSize()
        + (OuterRoundCount * OuterRoundCompressedSize)
        + OuterClaimsSize
        + ScalarSize;

    //Start of the two trailing Hyrax opening proofs (error opening at
    //r_x first, then the witness opening at r_y).
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


    private static Tag ComposeAlgebraicTag(SpartanProofDimensions dimensions, CurveParameterSet curve)
    {
        return Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.ZkProof),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(SpartanProofDimensions), (object)dimensions),
            (typeof(SpartanProofVariant), (object)SpartanProofVariant.Unmasked));
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, SpartanProofDimensions dimensions, CurveParameterSet curve)
    {
        return tag.With(
            (typeof(AlgebraicRole), (object)AlgebraicRole.ZkProof),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(SpartanProofDimensions), (object)dimensions),
            (typeof(SpartanProofVariant), (object)SpartanProofVariant.Unmasked));
    }
}