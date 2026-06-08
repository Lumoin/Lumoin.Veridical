using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// A masked Spartan2 proof whose polynomial-commitment scheme is the genuinely
/// zero-knowledge BaseFold (<see cref="Commitments.ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge"/>):
/// the full-ZK sibling of <see cref="BaseFoldMaskedSpartanProof"/>. It carries
/// the identical commitment, masking-sum, and scheme-independent sumcheck
/// sections, but its witness opening is a full zero-knowledge BaseFold opening
/// (the dimension lift plus the CFS-2017 sumcheck mask) and its two mask
/// openings are <em>hiding weighted openings</em> of the salted-and-lifted mask
/// coefficient vectors (design v3 — the filler laundering replaces the old
/// recursive full-ZK opening, shrinking the proof).
/// </summary>
/// <remarks>
/// <para>
/// Unlike <see cref="BaseFoldMaskedSpartanProof"/> — which is a sound argument of
/// knowledge but not hiding — this proof is produced over a hiding, simulatable
/// provider, so masked-Spartan-over-BaseFold delivers the witness privacy
/// its name implies. The commitments are still single Merkle roots (the lift
/// changes the committed codeword, not the root's width), so only the opening
/// sections grow; the layout is otherwise identical to the non-ZK sibling.
/// </para>
/// <para>
/// Buffer layout, in order: witness root, outer-mask root, inner-mask root,
/// outer-mask sum <c>σ</c>, inner-mask sum <c>σ</c>, the two mask filler sums
/// <c>σ_F</c>, the scheme-independent sumcheck middle
/// (<see cref="SpartanSumcheckProofPart"/>), then four BaseFold openings —
/// error (plain, row variables), the outer mask's hiding weighted opening (at
/// its policy-resolved lifted variable count), the inner mask's likewise,
/// witness (full-ZK, column variables). Every section size is a pure function
/// of the round counts, the lift <see cref="ExtraVariableCount"/>, the query
/// count, and the digest size — the mask shapes resolve deterministically —
/// so the layout carries no length prefixes.
/// </para>
/// </remarks>
public sealed class ZkBaseFoldMaskedSpartanProof: SensitiveMemory, IMaskedSpartanProofView
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

    /// <summary>The dimension-lift <c>t</c> the full-ZK provider committed each polynomial by; it sizes every embedded opening.</summary>
    public int ExtraVariableCount { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    internal ZkBaseFoldMaskedSpartanProof(
        IMemoryOwner<byte> owner,
        int outerRoundCount,
        int innerRoundCount,
        int queryCount,
        int digestSizeBytes,
        int extraVariableCount,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, GetBufferSizeBytes(outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, extraVariableCount, curve), tag)
    {
        OuterRoundCount = outerRoundCount;
        InnerRoundCount = innerRoundCount;
        QueryCount = queryCount;
        DigestSizeBytes = digestSizeBytes;
        ExtraVariableCount = extraVariableCount;
        Curve = curve;
    }


    /// <summary>
    /// Packs the per-section inputs into one wire-format proof. All input bytes
    /// are copied; the caller retains ownership of the inputs.
    /// </summary>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a section length, round degree, or curve does not match the expected layout.</exception>
    public static ZkBaseFoldMaskedSpartanProof Build(
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
        int extraVariableCount,
        SensitiveMemoryPool<byte> pool,
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
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(extraVariableCount);

        CurveParameterSet curve = witnessCommitment.Curve;
        int outerRoundCount = outerRounds.Count;
        int innerRoundCount = innerRounds.Count;

        ValidateRoundShape(outerRounds, expectedDegree: 3, "outer", curve);
        ValidateRoundShape(innerRounds, expectedDegree: 2, "inner", curve);
        ValidateCommitmentLength(witnessCommitment, digestSizeBytes, nameof(witnessCommitment));
        ValidateCommitmentLength(outerMaskCommitment, digestSizeBytes, nameof(outerMaskCommitment));
        ValidateCommitmentLength(innerMaskCommitment, digestSizeBytes, nameof(innerMaskCommitment));

        //The error is the public zero vector — it carries no privacy, is committed
        //deterministically (plain), and is recomputed by the verifier, so its
        //opening is the plain (unlifted, unmasked) size. The witness is full-ZK
        //size; the two masks are hiding weighted openings at their
        //policy-resolved lifted shapes (design v3).
        int errorOpeningSize = PlainOpeningSizeBytes(outerRoundCount, curve, queryCount, digestSizeBytes);
        int outerMaskOpeningSize = MaskOpeningSizeBytes(outerRoundCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree, curve, queryCount, digestSizeBytes);
        int innerMaskOpeningSize = MaskOpeningSizeBytes(innerRoundCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree, curve, queryCount, digestSizeBytes);
        int innerOpeningSize = ZkOpeningSizeBytes(innerRoundCount, extraVariableCount, curve, queryCount, digestSizeBytes);
        ValidateOpeningLength(errorOpening, errorOpeningSize, nameof(errorOpening));
        ValidateOpeningLength(outerMaskOpening, outerMaskOpeningSize, nameof(outerMaskOpening));
        ValidateOpeningLength(innerMaskOpening, innerMaskOpeningSize, nameof(innerMaskOpening));
        ValidateOpeningLength(witnessOpening, innerOpeningSize, nameof(witnessOpening));

        int bufferSize = GetBufferSizeBytes(outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, extraVariableCount, curve);
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

        Tag effectiveTag = tag is null ? ComposeTag(curve) : tag.With(AlgebraicTagEntries(curve));

        return new ZkBaseFoldMaskedSpartanProof(owner, outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, extraVariableCount, curve, effectiveTag);
    }


    /// <summary>Reconstructs a proof from its canonical wire bytes given the dimensions.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bytes"/> does not have the exact expected length.</exception>
    public static ZkBaseFoldMaskedSpartanProof FromBytes(
        ReadOnlySpan<byte> bytes,
        int outerRoundCount,
        int innerRoundCount,
        int queryCount,
        int digestSizeBytes,
        int extraVariableCount,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(extraVariableCount);

        int expected = GetBufferSizeBytes(outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, extraVariableCount, curve);
        if(bytes.Length != expected)
        {
            throw new ArgumentException(
                $"ZK BaseFold masked Spartan proof must be {expected} bytes for the supplied dimensions; received {bytes.Length}.",
                nameof(bytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expected);
        bytes.CopyTo(owner.Memory.Span[..expected]);

        return new ZkBaseFoldMaskedSpartanProof(owner, outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, extraVariableCount, curve, ComposeTag(curve));
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


    /// <summary>Returns the embedded error-commitment BaseFold opening bytes (at <c>r_x</c>); plain (the public error is not hidden).</summary>
    public ReadOnlySpan<byte> GetErrorOpeningProofBytes() => AsReadOnlySpan().Slice(OpeningsStart(), ErrorOpeningSize());

    /// <summary>Returns the embedded outer-mask hiding weighted-opening bytes.</summary>
    public ReadOnlySpan<byte> GetOuterMaskOpeningProofBytes() =>
        AsReadOnlySpan().Slice(OpeningsStart() + ErrorOpeningSize(), OuterMaskOpeningSize());

    /// <summary>Returns the embedded inner-mask hiding weighted-opening bytes.</summary>
    public ReadOnlySpan<byte> GetInnerMaskOpeningProofBytes() =>
        AsReadOnlySpan().Slice(OpeningsStart() + ErrorOpeningSize() + OuterMaskOpeningSize(), InnerMaskOpeningSize());

    /// <summary>Returns the embedded witness full-ZK BaseFold opening bytes (at <c>r_y</c>).</summary>
    public ReadOnlySpan<byte> GetWitnessOpeningProofBytes() =>
        AsReadOnlySpan().Slice(OpeningsStart() + ErrorOpeningSize() + OuterMaskOpeningSize() + InnerMaskOpeningSize(), WitnessOpeningSize());


    /// <summary>Returns the total wire-format byte size for the supplied dimensions.</summary>
    public static int GetBufferSizeBytes(int outerRoundCount, int innerRoundCount, int queryCount, int digestSizeBytes, int extraVariableCount, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(extraVariableCount);

        int errorOpening = PlainOpeningSizeBytes(outerRoundCount, curve, queryCount, digestSizeBytes);
        int outerMaskOpening = MaskOpeningSizeBytes(outerRoundCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree, curve, queryCount, digestSizeBytes);
        int innerMaskOpening = MaskOpeningSizeBytes(innerRoundCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree, curve, queryCount, digestSizeBytes);
        int witnessOpening = ZkOpeningSizeBytes(innerRoundCount, extraVariableCount, curve, queryCount, digestSizeBytes);

        return (3 * digestSizeBytes)
            + (4 * ScalarSize) //σ_outer + σ_inner + the two filler sums
            + SpartanSumcheckProofPart.GetSectionSizeBytes(outerRoundCount, innerRoundCount)
            + errorOpening //error (plain)
            + outerMaskOpening //outer mask (hiding weighted)
            + innerMaskOpening //inner mask (hiding weighted)
            + witnessOpening; //witness (full-ZK)
    }


    private int MiddleStart() => (3 * DigestSizeBytes) + (4 * ScalarSize);

    private int OpeningsStart() => MiddleStart() + SpartanSumcheckProofPart.GetSectionSizeBytes(OuterRoundCount, InnerRoundCount);

    private int ErrorOpeningSize() => PlainOpeningSizeBytes(OuterRoundCount, Curve, QueryCount, DigestSizeBytes);

    private int OuterMaskOpeningSize() => MaskOpeningSizeBytes(OuterRoundCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree, Curve, QueryCount, DigestSizeBytes);

    private int InnerMaskOpeningSize() => MaskOpeningSizeBytes(InnerRoundCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree, Curve, QueryCount, DigestSizeBytes);

    private int WitnessOpeningSize() => ZkOpeningSizeBytes(InnerRoundCount, ExtraVariableCount, Curve, QueryCount, DigestSizeBytes);


    private static int PlainOpeningSizeBytes(int variableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes) =>
        BaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(variableCount, curve, queryCount, digestSizeBytes);


    private static int ZkOpeningSizeBytes(int variableCount, int extraVariableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes) =>
        ZkBaseFoldPolynomialCommitmentScheme.GetFullZeroKnowledgeEvaluationProofSizeBytes(variableCount, extraVariableCount, curve, queryCount, digestSizeBytes);


    //A mask's hiding weighted opening runs over its policy-resolved LIFTED
    //variable count (the salted-and-lifted vector commit of the full-ZK
    //provider), in Hiding mode — not the recursive full-ZK opening shape.
    private static int MaskOpeningSizeBytes(int sumcheckVariableCount, int perVariableDegree, CurveParameterSet curve, int queryCount, int digestSizeBytes)
    {
        StatisticalMaskParameters shape = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(sumcheckVariableCount, curve, queryCount, perVariableDegree);

        return ZkBaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(shape.LiftedVariableCount, curve, queryCount, digestSizeBytes);
    }


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
                $"Full-ZK BaseFold opening must be {expected} bytes; received {opening.AsReadOnlySpan().Length}.",
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


    private static Tag ComposeTag(CurveParameterSet curve) => Tag.Create(AlgebraicTagEntries(curve));


    private static (Type, object)[] AlgebraicTagEntries(CurveParameterSet curve) =>
    [
        (typeof(AlgebraicRole), AlgebraicRole.ZkProof),
        (typeof(CurveParameterSet), curve),
        (typeof(CommitmentScheme), CommitmentScheme.BaseFold),
        (typeof(SpartanProofVariant), SpartanProofVariant.MaskedStatistical)
    ];
}
