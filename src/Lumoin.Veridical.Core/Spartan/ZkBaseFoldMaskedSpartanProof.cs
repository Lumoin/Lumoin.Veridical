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
/// coefficient vectors — the filler laundering replaces a recursive full-ZK
/// opening, shrinking the proof.
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
    /// <summary>The in-memory canonical scalar width in bytes.</summary>
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


    /// <summary>Wraps an already-populated wire-format buffer with its dimensions, taking ownership of <paramref name="owner"/>.</summary>
    /// <param name="owner">The rented buffer holding the wire-format proof bytes.</param>
    /// <param name="outerRoundCount">The outer-sumcheck round count.</param>
    /// <param name="innerRoundCount">The inner-sumcheck round count.</param>
    /// <param name="queryCount">The BaseFold IOPP query repetition count the openings were produced under.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <param name="extraVariableCount">The dimension-lift <c>t</c> the full-ZK provider committed each polynomial by.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="tag">The algebraic tag identifying this memory's role and curve.</param>
    internal ZkBaseFoldMaskedSpartanProof(
        IMemoryOwner<byte> owner,
        int outerRoundCount,
        int innerRoundCount,
        int queryCount,
        int digestSizeBytes,
        int extraVariableCount,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, tag)
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
        //policy-resolved lifted shapes.
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

        Tag effectiveTag = tag is null ? ComposeTag(curve) : MergeAlgebraicTag(tag, curve);

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
        BaseMemoryPool pool)
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


    /// <summary>Computes the byte offset of the scheme-independent sumcheck middle, right after the three roots and the four scalar sums.</summary>
    /// <returns>The sumcheck middle's start offset.</returns>
    private int MiddleStart() => (3 * DigestSizeBytes) + (4 * ScalarSize);

    /// <summary>Computes the byte offset of the first BaseFold opening, right after the sumcheck middle.</summary>
    /// <returns>The openings section's start offset.</returns>
    private int OpeningsStart() => MiddleStart() + SpartanSumcheckProofPart.GetSectionSizeBytes(OuterRoundCount, InnerRoundCount);

    /// <summary>Computes this proof's error opening's byte length (plain, at the outer round count).</summary>
    /// <returns>The error opening's byte length.</returns>
    private int ErrorOpeningSize() => PlainOpeningSizeBytes(OuterRoundCount, Curve, QueryCount, DigestSizeBytes);

    /// <summary>Computes this proof's outer-mask opening's byte length (hiding weighted, at its policy-resolved lifted shape).</summary>
    /// <returns>The outer-mask opening's byte length.</returns>
    private int OuterMaskOpeningSize() => MaskOpeningSizeBytes(OuterRoundCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree, Curve, QueryCount, DigestSizeBytes);

    /// <summary>Computes this proof's inner-mask opening's byte length (hiding weighted, at its policy-resolved lifted shape).</summary>
    /// <returns>The inner-mask opening's byte length.</returns>
    private int InnerMaskOpeningSize() => MaskOpeningSizeBytes(InnerRoundCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree, Curve, QueryCount, DigestSizeBytes);

    /// <summary>Computes this proof's witness opening's byte length (full zero-knowledge, at the inner round count lifted by <see cref="ExtraVariableCount"/>).</summary>
    /// <returns>The witness opening's byte length.</returns>
    private int WitnessOpeningSize() => ZkOpeningSizeBytes(InnerRoundCount, ExtraVariableCount, Curve, QueryCount, DigestSizeBytes);


    /// <summary>Computes a plain (non-hiding, non-lifted) BaseFold evaluation opening's byte length, the shape the public error opening uses.</summary>
    /// <param name="variableCount">The committed polynomial's variable count.</param>
    /// <param name="curve">The curve the code is over.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <returns>The plain opening's byte length.</returns>
    private static int PlainOpeningSizeBytes(int variableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes) =>
        BaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(variableCount, curve, queryCount, digestSizeBytes);


    /// <summary>Computes a full zero-knowledge (dimension-lifted plus CFS-2017-masked) BaseFold evaluation opening's byte length, the shape the witness opening uses.</summary>
    /// <param name="variableCount">The real witness's variable count.</param>
    /// <param name="extraVariableCount">The dimension lift <c>t</c> the provider was built with.</param>
    /// <param name="curve">The curve the code is over.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <returns>The full zero-knowledge opening's byte length.</returns>
    private static int ZkOpeningSizeBytes(int variableCount, int extraVariableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes) =>
        ZkBaseFoldPolynomialCommitmentScheme.GetFullZeroKnowledgeEvaluationProofSizeBytes(variableCount, extraVariableCount, curve, queryCount, digestSizeBytes);


    /// <summary>
    /// Computes a mask's hiding weighted-opening byte length. A mask's opening runs over its
    /// policy-resolved lifted variable count (the salted-and-lifted vector commit of the full-ZK
    /// provider), in hiding mode — not the recursive full-ZK opening shape.
    /// </summary>
    /// <param name="sumcheckVariableCount">The sumcheck round count the mask covers.</param>
    /// <param name="perVariableDegree">The mask's per-variable polynomial degree.</param>
    /// <param name="curve">The curve the code is over.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <returns>The mask's hiding weighted opening's byte length.</returns>
    private static int MaskOpeningSizeBytes(int sumcheckVariableCount, int perVariableDegree, CurveParameterSet curve, int queryCount, int digestSizeBytes)
    {
        StatisticalMaskParameters shape = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(sumcheckVariableCount, curve, queryCount, perVariableDegree);

        return ZkBaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(shape.LiftedVariableCount, curve, queryCount, digestSizeBytes);
    }


    /// <summary>Copies a section's bytes into the buffer at the given offset.</summary>
    /// <param name="buffer">The destination wire-format buffer.</param>
    /// <param name="offset">The byte offset to write at.</param>
    /// <param name="source">The section bytes to copy.</param>
    /// <returns>The number of bytes written, i.e. <c>source.Length</c>.</returns>
    private static int Copy(Span<byte> buffer, int offset, ReadOnlySpan<byte> source)
    {
        source.CopyTo(buffer.Slice(offset, source.Length));
        return source.Length;
    }


    /// <summary>Throws unless a commitment is exactly one Merkle root wide.</summary>
    /// <param name="commitment">The commitment to check.</param>
    /// <param name="digestSizeBytes">The expected Merkle digest size in bytes.</param>
    /// <param name="parameterName">The parameter name to report if the check fails.</param>
    /// <exception cref="ArgumentException">When the commitment's length does not equal <paramref name="digestSizeBytes"/>.</exception>
    private static void ValidateCommitmentLength(PolynomialCommitment commitment, int digestSizeBytes, string parameterName)
    {
        if(commitment.AsReadOnlySpan().Length != digestSizeBytes)
        {
            throw new ArgumentException(
                $"BaseFold commitment must be {digestSizeBytes} bytes (one Merkle root); received {commitment.AsReadOnlySpan().Length}.",
                parameterName);
        }
    }


    /// <summary>Throws unless an opening is exactly the expected byte length.</summary>
    /// <param name="opening">The opening to check.</param>
    /// <param name="expected">The expected byte length.</param>
    /// <param name="parameterName">The parameter name to report if the check fails.</param>
    /// <exception cref="ArgumentException">When the opening's length does not equal <paramref name="expected"/>.</exception>
    private static void ValidateOpeningLength(PolynomialOpening opening, int expected, string parameterName)
    {
        if(opening.AsReadOnlySpan().Length != expected)
        {
            throw new ArgumentException(
                $"Full-ZK BaseFold opening must be {expected} bytes; received {opening.AsReadOnlySpan().Length}.",
                parameterName);
        }
    }


    /// <summary>Throws unless every round in a sumcheck phase shares the given curve and per-round polynomial degree.</summary>
    /// <param name="rounds">The sumcheck rounds to check.</param>
    /// <param name="expectedDegree">The required per-round polynomial degree.</param>
    /// <param name="phase">The phase name ("outer" or "inner") used in the exception message.</param>
    /// <param name="curve">The curve every round must share.</param>
    /// <exception cref="ArgumentException">When a round's curve or degree does not match.</exception>
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


    /// <summary>Builds this proof type's default algebraic tag for the given curve, starting from an empty tag.</summary>
    /// <param name="curve">The curve to tag the memory with.</param>
    /// <returns>A tag identifying this proof's role, curve, scheme and variant.</returns>
    private static Tag ComposeTag(CurveParameterSet curve) => MergeAlgebraicTag(Tag.Empty, curve);


    /// <summary>Merges this proof type's role, scheme and variant onto a caller-supplied tag for the given curve.</summary>
    /// <param name="tag">The base tag to merge onto.</param>
    /// <param name="curve">The curve to tag the memory with.</param>
    /// <returns>The merged tag.</returns>
    private static Tag MergeAlgebraicTag(Tag tag, CurveParameterSet curve) =>
        tag.With(AlgebraicRole.ZkProof)
            .With(curve)
            .With(CommitmentScheme.BaseFold)
            .With(SpartanProofVariant.MaskedStatistical);
}
