using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// A Spartan2 proof whose polynomial-commitment scheme is Ligero: the
/// Ligero-shaped sibling of <see cref="BaseFoldSpartanProof"/>. It carries the
/// same scheme-independent sumcheck middle (via
/// <see cref="SpartanSumcheckProofPart"/>) but Ligero-shaped commitment and
/// opening sections — a digest-wide column-commitment root for the witness
/// commitment, and two serialized Ligero evaluation openings.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in order:
/// </para>
/// <list type="number">
///   <item><description>Witness commitment: the column-commitment root of the witness MLE (<see cref="DigestSizeBytes"/> bytes).</description></item>
///   <item><description>Sumcheck middle: outer rounds, the three outer claims, <c>E(r_x)</c>, inner rounds, <c>eval_W</c> — identical to <see cref="SpartanProof"/>'s middle.</description></item>
///   <item><description>Error-commitment opening at <c>r_x</c>: a serialized Ligero evaluation opening over the <em>row</em> variables (<see cref="OuterRoundCount"/>).</description></item>
///   <item><description>Witness opening at <c>r_y</c>: a serialized Ligero evaluation opening over the <em>column</em> variables (<see cref="InnerRoundCount"/>).</description></item>
/// </list>
/// <para>
/// Every section size is a pure function of the round counts, the query count
/// and the digest size — all known to both endpoints (the round counts from the
/// instance dimensions, the query count and digest size from the verifying key's
/// provider) — so the layout carries no length prefixes.
/// </para>
/// </remarks>
public sealed class LigeroSpartanProof: SensitiveMemory
{
    /// <summary>The number of outer-sumcheck rounds (equals the row-variable count and the error-opening variable count).</summary>
    public int OuterRoundCount { get; }

    /// <summary>The number of inner-sumcheck rounds (equals the column-variable count and the witness-opening variable count).</summary>
    public int InnerRoundCount { get; }

    /// <summary>The Ligero opened-column query count the openings were produced under.</summary>
    public int QueryCount { get; }

    /// <summary>The Merkle digest size in bytes (the witness-commitment length and the path-node width inside the openings).</summary>
    public int DigestSizeBytes { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    internal LigeroSpartanProof(
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
    /// Packs the per-section inputs into one wire-format Ligero Spartan proof.
    /// All input bytes are copied; the caller retains ownership of the inputs.
    /// </summary>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a section length, round degree, or curve does not match the expected layout.</exception>
    public static LigeroSpartanProof Build(
        PolynomialCommitment witnessCommitment,
        IReadOnlyList<SumcheckRound> outerRounds,
        Scalar claimAz,
        Scalar claimBz,
        Scalar claimCz,
        Scalar errorEvaluation,
        IReadOnlyList<SumcheckRound> innerRounds,
        Scalar evalW,
        PolynomialOpening errorOpeningProof,
        PolynomialOpening witnessOpeningProof,
        int queryCount,
        int digestSizeBytes,
        BaseMemoryPool pool,
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
        ArgumentNullException.ThrowIfNull(witnessOpeningProof);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        CurveParameterSet curve = witnessCommitment.Curve;
        int outerRoundCount = outerRounds.Count;
        int innerRoundCount = innerRounds.Count;

        ValidateRoundShape(outerRounds, expectedDegree: 3, "outer", curve);
        ValidateRoundShape(innerRounds, expectedDegree: 2, "inner", curve);

        if(witnessCommitment.AsReadOnlySpan().Length != digestSizeBytes)
        {
            throw new ArgumentException(
                $"Ligero witness commitment must be {digestSizeBytes} bytes (one column-commitment root); received {witnessCommitment.AsReadOnlySpan().Length}.",
                nameof(witnessCommitment));
        }

        int errorOpeningSize = OpeningSizeBytes(outerRoundCount, curve, queryCount, digestSizeBytes);
        int witnessOpeningSize = OpeningSizeBytes(innerRoundCount, curve, queryCount, digestSizeBytes);
        if(errorOpeningProof.AsReadOnlySpan().Length != errorOpeningSize)
        {
            throw new ArgumentException(
                $"Ligero error opening must be {errorOpeningSize} bytes for {outerRoundCount} row variable(s); received {errorOpeningProof.AsReadOnlySpan().Length}.",
                nameof(errorOpeningProof));
        }

        if(witnessOpeningProof.AsReadOnlySpan().Length != witnessOpeningSize)
        {
            throw new ArgumentException(
                $"Ligero witness opening must be {witnessOpeningSize} bytes for {innerRoundCount} column variable(s); received {witnessOpeningProof.AsReadOnlySpan().Length}.",
                nameof(witnessOpeningProof));
        }

        int bufferSize = GetBufferSizeBytes(outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, curve);
        IMemoryOwner<byte> owner = pool.Rent(bufferSize);
        Span<byte> buffer = owner.Memory.Span[..bufferSize];

        int offset = 0;
        witnessCommitment.AsReadOnlySpan().CopyTo(buffer.Slice(offset, digestSizeBytes));
        offset += digestSizeBytes;

        int middleSize = SpartanSumcheckProofPart.GetSectionSizeBytes(outerRoundCount, innerRoundCount);
        SpartanSumcheckProofPart.Write(
            buffer.Slice(offset, middleSize),
            outerRounds, claimAz, claimBz, claimCz, errorEvaluation, innerRounds, evalW);
        offset += middleSize;

        errorOpeningProof.AsReadOnlySpan().CopyTo(buffer.Slice(offset, errorOpeningSize));
        offset += errorOpeningSize;

        witnessOpeningProof.AsReadOnlySpan().CopyTo(buffer.Slice(offset, witnessOpeningSize));

        Tag effectiveTag = tag is null
            ? ComposeTag(curve)
            : MergeAlgebraicTag(tag, curve);

        return new LigeroSpartanProof(owner, outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, curve, effectiveTag);
    }


    /// <summary>
    /// Reconstructs a proof from its canonical wire bytes given the dimensions
    /// (recovered by the verifier from the instance shape and the provider).
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bytes"/> does not have the exact expected length.</exception>
    public static LigeroSpartanProof FromBytes(
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
                $"Ligero Spartan proof must be {expected} bytes for the supplied dimensions; received {bytes.Length}.",
                nameof(bytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expected);
        bytes.CopyTo(owner.Memory.Span[..expected]);

        return new LigeroSpartanProof(owner, outerRoundCount, innerRoundCount, queryCount, digestSizeBytes, curve, ComposeTag(curve));
    }


    /// <summary>Returns the embedded witness-commitment (column-commitment root) bytes.</summary>
    public ReadOnlySpan<byte> GetWitnessCommitmentBytes() => AsReadOnlySpan()[..DigestSizeBytes];


    /// <summary>Returns a zero-copy window over the scheme-independent sumcheck middle.</summary>
    internal SpartanSumcheckProofPart GetSumcheckPart() =>
        new(this, DigestSizeBytes, OuterRoundCount, InnerRoundCount, Curve);


    /// <summary>Returns the embedded error-commitment Ligero opening bytes (at <c>r_x</c>).</summary>
    public ReadOnlySpan<byte> GetErrorOpeningProofBytes()
    {
        int offset = DigestSizeBytes + SpartanSumcheckProofPart.GetSectionSizeBytes(OuterRoundCount, InnerRoundCount);
        int length = OpeningSizeBytes(OuterRoundCount, Curve, QueryCount, DigestSizeBytes);
        return AsReadOnlySpan().Slice(offset, length);
    }


    /// <summary>Returns the embedded witness Ligero opening bytes (at <c>r_y</c>).</summary>
    public ReadOnlySpan<byte> GetWitnessOpeningProofBytes()
    {
        int offset = DigestSizeBytes
            + SpartanSumcheckProofPart.GetSectionSizeBytes(OuterRoundCount, InnerRoundCount)
            + OpeningSizeBytes(OuterRoundCount, Curve, QueryCount, DigestSizeBytes);
        int length = OpeningSizeBytes(InnerRoundCount, Curve, QueryCount, DigestSizeBytes);
        return AsReadOnlySpan().Slice(offset, length);
    }


    /// <summary>Returns the total wire-format byte size for the supplied dimensions.</summary>
    public static int GetBufferSizeBytes(int outerRoundCount, int innerRoundCount, int queryCount, int digestSizeBytes, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);

        return digestSizeBytes
            + SpartanSumcheckProofPart.GetSectionSizeBytes(outerRoundCount, innerRoundCount)
            + OpeningSizeBytes(outerRoundCount, curve, queryCount, digestSizeBytes)
            + OpeningSizeBytes(innerRoundCount, curve, queryCount, digestSizeBytes);
    }


    //The serialized Ligero opening for a polynomial in variableCount variables.
    private static int OpeningSizeBytes(int variableCount, CurveParameterSet curve, int queryCount, int digestSizeBytes)
    {
        return LigeroPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(variableCount, curve, queryCount, digestSizeBytes);
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
            .With(CommitmentScheme.Ligero)
            .With(SpartanProofVariant.Unmasked);
}
