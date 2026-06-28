using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// A masked Spartan2 proof whose polynomial-commitment scheme is BaseFold: the
/// BaseFold-shaped sibling of <see cref="MaskedSpartanProof"/>. It carries the
/// same masking sums and scheme-independent sumcheck middle but BaseFold-shaped
/// commitment and opening sections — three 32-byte Merkle roots and four
/// serialized BaseFold evaluation proofs.
/// </summary>
/// <remarks>
/// <para>
/// <b>Hiding caveat.</b> The masked construction provides zero-knowledge only
/// when the commitments are hiding. BaseFold's commitment is a Merkle root over
/// the codeword — binding but <em>not</em> hiding — so a masked Spartan proof
/// over BaseFold is a sound argument of knowledge but does <em>not</em> achieve
/// the witness privacy the "masked" name implies; full ZK needs a hiding
/// BaseFold variant (a blinded codeword), which is out of scope. See BASEFOLD.md.
/// </para>
/// <para>
/// Buffer layout, in order: witness root, outer-mask root, inner-mask root,
/// outer-mask sum <c>σ</c>, inner-mask sum <c>σ</c>, the two mask filler sums
/// <c>σ_F</c>, the scheme-independent sumcheck middle
/// (<see cref="SpartanSumcheckProofPart"/>), then four BaseFold openings —
/// error (row variables), the outer mask's weighted opening (at its
/// policy-resolved coefficient variable count), the inner mask's likewise,
/// witness (column variables). Every section size is a pure function of the
/// round counts, query count, and digest size — the mask shapes resolve
/// deterministically from the round counts — so the layout carries no length
/// prefixes.
/// </para>
/// </remarks>
public sealed class BaseFoldMaskedSpartanProof: SensitiveMemory, IMaskedSpartanProofView
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>The number of outer-sumcheck rounds (row-variable count; also the error and outer-mask opening variable count).</summary>
    public int OuterRoundCount { get; }

    /// <summary>The number of inner-sumcheck rounds (column-variable count; also the inner-mask and witness opening variable count).</summary>
    public int InnerRoundCount { get; }

    /// <summary>The BaseFold IOPP query repetition count the openings were produced under.</summary>
    public int QueryCount { get; }

    /// <summary>The Merkle digest size in bytes.</summary>
    public int DigestSizeBytes { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    internal BaseFoldMaskedSpartanProof(
        IMemoryOwner<byte> owner,
        int outerRoundCount,
        int innerRoundCount,
        int queryCount,
        int digestSizeBytes,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, tag)
    {
        OuterRoundCount = outerRoundCount;
        InnerRoundCount = innerRoundCount;
        QueryCount = queryCount;
        DigestSizeBytes = digestSizeBytes;
        Curve = curve;
    }


    /// <summary>
    /// Packs the per-section inputs into one wire-format proof. All input bytes
    /// are copied; the caller retains ownership of the inputs.
    /// </summary>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a section length, round degree, or curve does not match the expected layout.</exception>
    public static BaseFoldMaskedSpartanProof Build(
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
        int queryCount,
        int digestSizeBytes,
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
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        CurveParameterSet curve = witnessCommitment.Curve;
        int outerRoundCount = outerRounds.Count;
        int innerRoundCount = innerRounds.Count;

        ValidateRoundShape(outerRounds, expectedDegree: 3, "outer", curve);
        ValidateRoundShape(innerRounds, expectedDegree: 2, "inner", curve);
        ValidateCommitmentLength(witnessCommitment, digestSizeBytes, nameof(witnessCommitment));
        ValidateCommitmentLength(outerMaskCommitment, digestSizeBytes, nameof(outerMaskCommitment));
        ValidateCommitmentLength(innerMaskCommitment, digestSizeBytes, nameof(innerMaskCommitment));

        int outerOpeningSize = OpeningSizeBytes(outerRoundCount, curve, queryCount, digestSizeBytes);
        int innerOpeningSize = OpeningSizeBytes(innerRoundCount, curve, queryCount, digestSizeBytes);
        int outerMaskOpeningSize = MaskOpeningSizeBytes(outerRoundCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree, curve, queryCount, digestSizeBytes);
        int innerMaskOpeningSize = MaskOpeningSizeBytes(innerRoundCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree, curve, queryCount, digestSizeBytes);
        ValidateOpeningLength(errorOpening, outerOpeningSize, nameof(errorOpening));
        ValidateOpeningLength(outerMaskOpening, outerMaskOpeningSize, nameof(outerMaskOpening));
        ValidateOpeningLength(innerMaskOpening, innerMaskOpeningSize, nameof(innerMaskOpening));
        ValidateOpeningLength(witnessOpening, innerOpeningSize, nameof(witnessOpening));

        int bufferSize = GetBufferSizeBytes(outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, curve);
        IMemoryOwner<byte> owner = pool.Rent(bufferSize);
        Span<byte> buffer = owner.Memory.Span[..bufferSize];

        int offset = 0;
        offset += Copy(buffer, offset, witnessCommitment.AsReadOnlySpan());
        offset += Copy(buffer, offset, outerMaskCommitment.AsReadOnlySpan());
        offset += Copy(buffer, offset, innerMaskCommitment.AsReadOnlySpan());
        offset += Copy(buffer, offset, outerMaskSum.AsReadOnlySpan());
        offset += Copy(buffer, offset, innerMaskSum.AsReadOnlySpan());
        offset += Copy(buffer, offset, outerMaskFillerSum.AsReadOnlySpan());
        offset += Copy(buffer, offset, innerMaskFillerSum.AsReadOnlySpan());

        int middleSize = SpartanSumcheckProofPart.GetSectionSizeBytes(outerRoundCount, innerRoundCount);
        SpartanSumcheckProofPart.Write(
            buffer.Slice(offset, middleSize),
            outerRounds, claimAz, claimBz, claimCz, errorEvaluation, innerRounds, evalW);
        offset += middleSize;

        offset += Copy(buffer, offset, errorOpening.AsReadOnlySpan());
        offset += Copy(buffer, offset, outerMaskOpening.AsReadOnlySpan());
        offset += Copy(buffer, offset, innerMaskOpening.AsReadOnlySpan());
        Copy(buffer, offset, witnessOpening.AsReadOnlySpan());

        Tag effectiveTag = tag is null ? ComposeTag(curve) : MergeAlgebraicTag(tag, curve);

        return new BaseFoldMaskedSpartanProof(owner, outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, curve, effectiveTag);
    }


    /// <summary>Reconstructs a proof from its canonical wire bytes given the dimensions.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bytes"/> does not have the exact expected length.</exception>
    public static BaseFoldMaskedSpartanProof FromBytes(
        ReadOnlySpan<byte> bytes,
        int outerRoundCount,
        int innerRoundCount,
        int queryCount,
        int digestSizeBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        int expected = GetBufferSizeBytes(outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, curve);
        if(bytes.Length != expected)
        {
            throw new ArgumentException(
                $"BaseFold masked Spartan proof must be {expected} bytes for the supplied dimensions; received {bytes.Length}.",
                nameof(bytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expected);
        bytes.CopyTo(owner.Memory.Span[..expected]);

        return new BaseFoldMaskedSpartanProof(owner, outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, curve, ComposeTag(curve));
    }


    /// <summary>Returns the embedded witness-commitment (Merkle root) bytes.</summary>
    public ReadOnlySpan<byte> GetWitnessCommitmentBytes() => AsReadOnlySpan().Slice(0, DigestSizeBytes);

    /// <summary>Returns the embedded outer-mask commitment (Merkle root) bytes.</summary>
    public ReadOnlySpan<byte> GetOuterMaskCommitmentBytes() => AsReadOnlySpan().Slice(DigestSizeBytes, DigestSizeBytes);

    /// <summary>Returns the embedded inner-mask commitment (Merkle root) bytes.</summary>
    public ReadOnlySpan<byte> GetInnerMaskCommitmentBytes() => AsReadOnlySpan().Slice(2 * DigestSizeBytes, DigestSizeBytes);

    /// <summary>Returns the canonical bytes of the outer masking-polynomial sum <c>z_outer</c>.</summary>
    public ReadOnlySpan<byte> GetOuterMaskSumBytes() => AsReadOnlySpan().Slice(3 * DigestSizeBytes, ScalarSize);

    /// <summary>Returns the canonical bytes of the inner masking-polynomial sum <c>z_inner</c>.</summary>
    public ReadOnlySpan<byte> GetInnerMaskSumBytes() => AsReadOnlySpan().Slice((3 * DigestSizeBytes) + ScalarSize, ScalarSize);

    /// <summary>Returns the canonical bytes of the outer mask's filler sum <c>σ_F</c>.</summary>
    public ReadOnlySpan<byte> GetOuterMaskFillerSumBytes() => AsReadOnlySpan().Slice((3 * DigestSizeBytes) + (2 * ScalarSize), ScalarSize);

    /// <summary>Returns the canonical bytes of the inner mask's filler sum <c>σ_F</c>.</summary>
    public ReadOnlySpan<byte> GetInnerMaskFillerSumBytes() => AsReadOnlySpan().Slice((3 * DigestSizeBytes) + (3 * ScalarSize), ScalarSize);


    /// <summary>Returns a zero-copy window over the scheme-independent sumcheck middle.</summary>
    internal SpartanSumcheckProofPart GetSumcheckPart() => new(this, MiddleStart(), OuterRoundCount, InnerRoundCount, Curve);


    /// <summary>Returns the embedded error-commitment BaseFold opening bytes (at <c>r_x</c>).</summary>
    public ReadOnlySpan<byte> GetErrorOpeningProofBytes() => AsReadOnlySpan().Slice(OpeningsStart(), OuterOpeningSize());

    /// <summary>Returns the embedded outer-mask BaseFold weighted-opening bytes.</summary>
    public ReadOnlySpan<byte> GetOuterMaskOpeningProofBytes() =>
        AsReadOnlySpan().Slice(OpeningsStart() + OuterOpeningSize(), OuterMaskOpeningSize());

    /// <summary>Returns the embedded inner-mask BaseFold weighted-opening bytes.</summary>
    public ReadOnlySpan<byte> GetInnerMaskOpeningProofBytes() =>
        AsReadOnlySpan().Slice(OpeningsStart() + OuterOpeningSize() + OuterMaskOpeningSize(), InnerMaskOpeningSize());

    /// <summary>Returns the embedded witness BaseFold opening bytes (at <c>r_y</c>).</summary>
    public ReadOnlySpan<byte> GetWitnessOpeningProofBytes() =>
        AsReadOnlySpan().Slice(OpeningsStart() + OuterOpeningSize() + OuterMaskOpeningSize() + InnerMaskOpeningSize(), InnerOpeningSize());


    /// <summary>Returns the total wire-format byte size for the supplied dimensions.</summary>
    public static int GetBufferSizeBytes(int outerRoundCount, int innerRoundCount, int queryCount, int digestSizeBytes, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        int outerOpening = OpeningSizeBytes(outerRoundCount, curve, queryCount, digestSizeBytes);
        int innerOpening = OpeningSizeBytes(innerRoundCount, curve, queryCount, digestSizeBytes);
        int outerMaskOpening = MaskOpeningSizeBytes(outerRoundCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree, curve, queryCount, digestSizeBytes);
        int innerMaskOpening = MaskOpeningSizeBytes(innerRoundCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree, curve, queryCount, digestSizeBytes);

        return (3 * digestSizeBytes)
            + (4 * ScalarSize) //σ_outer + σ_inner + the two filler sums
            + SpartanSumcheckProofPart.GetSectionSizeBytes(outerRoundCount, innerRoundCount)
            + outerOpening //error
            + outerMaskOpening
            + innerMaskOpening
            + innerOpening; //witness
    }


    private int MiddleStart() => (3 * DigestSizeBytes) + (4 * ScalarSize);

    private int OpeningsStart() => MiddleStart() + SpartanSumcheckProofPart.GetSectionSizeBytes(OuterRoundCount, InnerRoundCount);

    private int OuterOpeningSize() => OpeningSizeBytes(OuterRoundCount, Curve, QueryCount, DigestSizeBytes);

    private int InnerOpeningSize() => OpeningSizeBytes(InnerRoundCount, Curve, QueryCount, DigestSizeBytes);

    private int OuterMaskOpeningSize() => MaskOpeningSizeBytes(OuterRoundCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree, Curve, QueryCount, DigestSizeBytes);

    private int InnerMaskOpeningSize() => MaskOpeningSizeBytes(InnerRoundCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree, Curve, QueryCount, DigestSizeBytes);


    private static int OpeningSizeBytes(int variableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes) =>
        BaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(variableCount, curve, queryCount, digestSizeBytes);


    //A mask's weighted opening runs over its policy-resolved coefficient
    //variable count (the unlifted shape the plain provider resolves), not the
    //sumcheck's variable count.
    private static int MaskOpeningSizeBytes(int sumcheckVariableCount, int perVariableDegree, CurveParameterSet curve, int queryCount, int digestSizeBytes) =>
        BaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
            WellKnownStatisticalMaskParameters.CreatePedersenIpa(sumcheckVariableCount, perVariableDegree).CoefficientVariableCount,
            curve, queryCount, digestSizeBytes);


    private static int Copy(Span<byte> buffer, int offset, ReadOnlySpan<byte> source)
    {
        source.CopyTo(buffer.Slice(offset, source.Length));
        return source.Length;
    }


    private static void ValidateCommitmentLength(PolynomialCommitment commitment, int digestSizeBytes, string parameterName)
    {
        if(commitment.AsReadOnlySpan().Length != digestSizeBytes)
        {
            throw new ArgumentException(
                $"BaseFold commitment must be {digestSizeBytes} bytes (one Merkle root); received {commitment.AsReadOnlySpan().Length}.",
                parameterName);
        }
    }


    private static void ValidateOpeningLength(PolynomialOpening opening, int expected, string parameterName)
    {
        if(opening.AsReadOnlySpan().Length != expected)
        {
            throw new ArgumentException(
                $"BaseFold opening must be {expected} bytes; received {opening.AsReadOnlySpan().Length}.",
                parameterName);
        }
    }


    private static void ValidateRoundShape(IReadOnlyList<SumcheckRound> rounds, int expectedDegree, string phase, CurveParameterSet curve)
    {
        for(int i = 0; i < rounds.Count; i++)
        {
            SumcheckRound round = rounds[i];
            if(round.Curve.Code != curve.Code)
            {
                throw new ArgumentException($"{phase} sumcheck round {i} has curve {round.Curve}; expected {curve}.");
            }

            if(round.Degree != expectedDegree)
            {
                throw new ArgumentException($"{phase} sumcheck round {i} has degree {round.Degree}; expected {expectedDegree}.");
            }
        }
    }


    private static Tag ComposeTag(CurveParameterSet curve) => MergeAlgebraicTag(Tag.Empty, curve);


    private static Tag MergeAlgebraicTag(Tag tag, CurveParameterSet curve) =>
        tag.With(AlgebraicRole.ZkProof)
            .With(curve)
            .With(CommitmentScheme.BaseFold)
            .With(SpartanProofVariant.MaskedStatistical);
}
