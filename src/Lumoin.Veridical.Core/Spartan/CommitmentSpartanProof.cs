using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// A Spartan2 proof over any polynomial-commitment scheme whose witness
/// commitment and evaluation openings are opaque byte sections of a length the
/// scheme can state ahead of time. It carries the same scheme-independent
/// sumcheck middle every Spartan proof carries (via
/// <see cref="SpartanSumcheckProofPart"/>), surrounded by three sections whose
/// lengths are the only thing that varies between schemes.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in order:
/// </para>
/// <list type="number">
///   <item><description>Witness commitment (<see cref="WitnessCommitmentSizeBytes"/> bytes).</description></item>
///   <item><description>Sumcheck middle: outer rounds, the three outer claims, <c>E(r_x)</c>, inner rounds, <c>eval_W</c>.</description></item>
///   <item><description>Error-commitment opening at <c>r_x</c>, over the row variables (<see cref="ErrorOpeningSizeBytes"/> bytes).</description></item>
///   <item><description>Witness opening at <c>r_y</c>, over the column variables (<see cref="WitnessOpeningSizeBytes"/> bytes).</description></item>
/// </list>
/// <para>
/// The type holds three lengths rather than a scheme's parameters. A per-scheme
/// proof type has to name the figures its own scheme sizes openings by — a query
/// repetition count, an inverse rate, a digest size — which means a scheme sized
/// by anything else cannot be expressed at all, and means a caller can pair a
/// proof with figures that disagree with the provider that produced it. Three
/// lengths cannot disagree with anything: <see cref="Build"/> reads each one from
/// the section it is given, and a verifier recovers all three from the provider it
/// is about to verify against —
/// <see cref="PolynomialCommitmentProvider.CommitmentSizeBytes"/> for the
/// commitment and <see cref="PolynomialCommitmentProvider.EvaluationProofSizeBytes"/>
/// for the two openings — so it supplies no figure of its own and needs to know
/// which scheme it holds only well enough to have built that provider.
/// </para>
/// <para>
/// The layout carries no length prefixes: both endpoints know the round counts
/// from the instance dimensions and the section lengths from the provider, so the
/// wire bytes are pure payload.
/// </para>
/// </remarks>
public sealed class CommitmentSpartanProof: SensitiveMemory
{
    /// <summary>The commitment scheme the sections were produced under.</summary>
    public CommitmentScheme Scheme { get; }

    /// <summary>The number of outer-sumcheck rounds (equals the row-variable count and the error-opening variable count).</summary>
    public int OuterRoundCount { get; }

    /// <summary>The number of inner-sumcheck rounds (equals the column-variable count and the witness-opening variable count).</summary>
    public int InnerRoundCount { get; }

    /// <summary>The witness-commitment section's length in bytes.</summary>
    public int WitnessCommitmentSizeBytes { get; }

    /// <summary>The error-opening section's length in bytes.</summary>
    public int ErrorOpeningSizeBytes { get; }

    /// <summary>The witness-opening section's length in bytes.</summary>
    public int WitnessOpeningSizeBytes { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>Wraps an already-filled wire-format buffer under the given scheme, section dimensions, curve, and provenance tag.</summary>
    internal CommitmentSpartanProof(
        IMemoryOwner<byte> owner,
        CommitmentScheme scheme,
        int outerRoundCount,
        int innerRoundCount,
        int witnessCommitmentSizeBytes,
        int errorOpeningSizeBytes,
        int witnessOpeningSizeBytes,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, tag)
    {
        Scheme = scheme;
        OuterRoundCount = outerRoundCount;
        InnerRoundCount = innerRoundCount;
        WitnessCommitmentSizeBytes = witnessCommitmentSizeBytes;
        ErrorOpeningSizeBytes = errorOpeningSizeBytes;
        WitnessOpeningSizeBytes = witnessOpeningSizeBytes;
        Curve = curve;
    }


    /// <summary>
    /// Packs the per-section inputs into one wire-format proof. All input bytes
    /// are copied; the caller retains ownership of the inputs. Every section
    /// length is taken from the section supplied, so no scheme figures are
    /// needed and none can be supplied inconsistently.
    /// </summary>
    /// <param name="witnessCommitment">The commitment to the witness MLE.</param>
    /// <param name="outerRounds">The outer sumcheck rounds (degree-3).</param>
    /// <param name="claimAz">The outer terminating <c>Az(r_x)</c>.</param>
    /// <param name="claimBz">The outer terminating <c>Bz(r_x)</c>.</param>
    /// <param name="claimCz">The outer terminating <c>Cz(r_x)</c>.</param>
    /// <param name="errorEvaluation">The relaxed error-MLE evaluation <c>E(r_x)</c>.</param>
    /// <param name="innerRounds">The inner sumcheck rounds (degree-2).</param>
    /// <param name="evalW">The witness MLE evaluation at <c>r_y</c>.</param>
    /// <param name="errorOpeningProof">The opening for the error commitment at <c>r_x</c>.</param>
    /// <param name="witnessOpeningProof">The opening for the witness commitment at <c>r_y</c>.</param>
    /// <param name="scheme">The commitment scheme the sections were produced under.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries.</param>
    /// <returns>A proof wrapping a pool-rented copy of every input's bytes.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a round degree or curve does not match the expected layout.</exception>
    public static CommitmentSpartanProof Build(
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
        CommitmentScheme scheme,
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

        CurveParameterSet curve = witnessCommitment.Curve;
        int outerRoundCount = outerRounds.Count;
        int innerRoundCount = innerRounds.Count;

        ValidateRoundShape(outerRounds, expectedDegree: 3, "outer", curve);
        ValidateRoundShape(innerRounds, expectedDegree: 2, "inner", curve);

        int witnessCommitmentSize = witnessCommitment.AsReadOnlySpan().Length;
        int errorOpeningSize = errorOpeningProof.AsReadOnlySpan().Length;
        int witnessOpeningSize = witnessOpeningProof.AsReadOnlySpan().Length;

        int bufferSize = GetBufferSizeBytes(outerRoundCount, innerRoundCount, witnessCommitmentSize, errorOpeningSize, witnessOpeningSize);
        IMemoryOwner<byte> owner = pool.Rent(bufferSize);
        Span<byte> buffer = owner.Memory.Span[..bufferSize];

        int offset = 0;
        witnessCommitment.AsReadOnlySpan().CopyTo(buffer.Slice(offset, witnessCommitmentSize));
        offset += witnessCommitmentSize;

        int middleSize = SpartanSumcheckProofPart.GetSectionSizeBytes(outerRoundCount, innerRoundCount);
        SpartanSumcheckProofPart.Write(
            buffer.Slice(offset, middleSize),
            outerRounds, claimAz, claimBz, claimCz, errorEvaluation, innerRounds, evalW);
        offset += middleSize;

        errorOpeningProof.AsReadOnlySpan().CopyTo(buffer.Slice(offset, errorOpeningSize));
        offset += errorOpeningSize;

        witnessOpeningProof.AsReadOnlySpan().CopyTo(buffer.Slice(offset, witnessOpeningSize));

        Tag effectiveTag = tag is null
            ? ComposeTag(curve, scheme)
            : MergeAlgebraicTag(tag, curve, scheme);

        return new CommitmentSpartanProof(
            owner, scheme, outerRoundCount, innerRoundCount,
            witnessCommitmentSize, errorOpeningSize, witnessOpeningSize, curve, effectiveTag);
    }


    /// <summary>
    /// Reconstructs a proof from its canonical wire bytes given the dimensions
    /// and section lengths, which a verifier recovers from the instance shape
    /// and the provider it is about to verify against.
    /// </summary>
    /// <param name="bytes">The canonical wire bytes.</param>
    /// <param name="scheme">The commitment scheme the sections were produced under.</param>
    /// <param name="outerRoundCount">The outer-sumcheck round count.</param>
    /// <param name="innerRoundCount">The inner-sumcheck round count.</param>
    /// <param name="witnessCommitmentSizeBytes">The witness-commitment section's length, from <see cref="PolynomialCommitmentProvider.CommitmentSizeBytes"/> at the column-variable count.</param>
    /// <param name="errorOpeningSizeBytes">The error-opening section's length, from <see cref="PolynomialCommitmentProvider.EvaluationProofSizeBytes"/> at the row-variable count.</param>
    /// <param name="witnessOpeningSizeBytes">The witness-opening section's length, from <see cref="PolynomialCommitmentProvider.EvaluationProofSizeBytes"/> at the column-variable count.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A proof wrapping a pool-rented copy of <paramref name="bytes"/>.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bytes"/> does not have the exact expected length.</exception>
    public static CommitmentSpartanProof FromBytes(
        ReadOnlySpan<byte> bytes,
        CommitmentScheme scheme,
        int outerRoundCount,
        int innerRoundCount,
        int witnessCommitmentSizeBytes,
        int errorOpeningSizeBytes,
        int witnessOpeningSizeBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int expected = GetBufferSizeBytes(outerRoundCount, innerRoundCount, witnessCommitmentSizeBytes, errorOpeningSizeBytes, witnessOpeningSizeBytes);
        if(bytes.Length != expected)
        {
            throw new ArgumentException(
                $"A {scheme} Spartan proof must be {expected} bytes for the supplied dimensions; received {bytes.Length}.",
                nameof(bytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expected);
        bytes.CopyTo(owner.Memory.Span[..expected]);

        return new CommitmentSpartanProof(
            owner, scheme, outerRoundCount, innerRoundCount,
            witnessCommitmentSizeBytes, errorOpeningSizeBytes, witnessOpeningSizeBytes, curve, ComposeTag(curve, scheme));
    }


    /// <summary>Returns the embedded witness-commitment bytes.</summary>
    /// <returns>The witness-commitment section.</returns>
    public ReadOnlySpan<byte> GetWitnessCommitmentBytes() => AsReadOnlySpan()[..WitnessCommitmentSizeBytes];


    /// <summary>Returns a zero-copy window over the scheme-independent sumcheck middle.</summary>
    /// <returns>The middle window.</returns>
    internal SpartanSumcheckProofPart GetSumcheckPart() =>
        new(this, WitnessCommitmentSizeBytes, OuterRoundCount, InnerRoundCount, Curve);


    /// <summary>Returns the embedded error-commitment opening bytes (at <c>r_x</c>).</summary>
    /// <returns>The error-opening section.</returns>
    public ReadOnlySpan<byte> GetErrorOpeningProofBytes()
    {
        int offset = WitnessCommitmentSizeBytes + SpartanSumcheckProofPart.GetSectionSizeBytes(OuterRoundCount, InnerRoundCount);

        return AsReadOnlySpan().Slice(offset, ErrorOpeningSizeBytes);
    }


    /// <summary>Returns the embedded witness opening bytes (at <c>r_y</c>).</summary>
    /// <returns>The witness-opening section.</returns>
    public ReadOnlySpan<byte> GetWitnessOpeningProofBytes()
    {
        int offset = WitnessCommitmentSizeBytes
            + SpartanSumcheckProofPart.GetSectionSizeBytes(OuterRoundCount, InnerRoundCount)
            + ErrorOpeningSizeBytes;

        return AsReadOnlySpan().Slice(offset, WitnessOpeningSizeBytes);
    }


    /// <summary>Returns the total wire-format byte size for the supplied dimensions and section lengths.</summary>
    /// <param name="outerRoundCount">The outer-sumcheck round count.</param>
    /// <param name="innerRoundCount">The inner-sumcheck round count.</param>
    /// <param name="witnessCommitmentSizeBytes">The witness-commitment section's length.</param>
    /// <param name="errorOpeningSizeBytes">The error-opening section's length.</param>
    /// <param name="witnessOpeningSizeBytes">The witness-opening section's length.</param>
    /// <returns>The total buffer length in bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a count or length is negative, or a section length is zero.</exception>
    public static int GetBufferSizeBytes(
        int outerRoundCount,
        int innerRoundCount,
        int witnessCommitmentSizeBytes,
        int errorOpeningSizeBytes,
        int witnessOpeningSizeBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(witnessCommitmentSizeBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(errorOpeningSizeBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(witnessOpeningSizeBytes);

        return witnessCommitmentSizeBytes
            + SpartanSumcheckProofPart.GetSectionSizeBytes(outerRoundCount, innerRoundCount)
            + errorOpeningSizeBytes
            + witnessOpeningSizeBytes;
    }


    /// <summary>Throws if any round in <paramref name="rounds"/> does not match <paramref name="curve"/> or <paramref name="expectedDegree"/>.</summary>
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


    /// <summary>Builds the algebraic-identity tag for a freshly built unmasked Spartan proof of the given curve and scheme.</summary>
    private static Tag ComposeTag(CurveParameterSet curve, CommitmentScheme scheme) => MergeAlgebraicTag(Tag.Empty, curve, scheme);


    /// <summary>Merges the algebraic-identity entries for an unmasked Spartan proof of the given curve and scheme into a caller-supplied tag.</summary>
    private static Tag MergeAlgebraicTag(Tag tag, CurveParameterSet curve, CommitmentScheme scheme) =>
        tag.With(AlgebraicRole.ZkProof)
            .With(curve)
            .With(scheme)
            .With(SpartanProofVariant.Unmasked);
}
