using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// A zero-copy window over the scheme-independent middle of a Spartan proof
/// buffer: the outer sumcheck rounds, the three outer terminating claims, the
/// relaxed error evaluation <c>E(r_x)</c>, the inner sumcheck rounds, and the
/// witness evaluation <c>eval_W</c>. Every Spartan proof — whatever its
/// commitment scheme — carries this identical block; only the surrounding
/// commitment and opening sections are scheme-shaped.
/// </summary>
/// <remarks>
/// <para>
/// Layout, in order (offsets relative to the window start):
/// </para>
/// <code>
/// [outerRounds : 96·R] [claim_Az : 32] [claim_Bz : 32] [claim_Cz : 32]
/// [E(r_x) : 32] [innerRounds : 64·C] [eval_W : 32]
/// </code>
/// <para>
/// The part does not own a buffer. It holds a reference to the owning proof's
/// <see cref="SensitiveMemory"/> and the byte offset where the middle begins,
/// slicing on demand — so both <see cref="SpartanProof"/> and
/// <see cref="BaseFoldSpartanProof"/> expose the identical block from their own
/// buffers without a copy. <see cref="Write"/> packs the block for a proof's
/// assembly; the accessors read it back during verification, decoupling the
/// sumcheck verifier drivers from any concrete proof type.
/// </para>
/// </remarks>
internal sealed class SpartanSumcheckProofPart
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int OuterRoundCompressedSize = 3 * ScalarSize;
    private const int InnerRoundCompressedSize = 2 * ScalarSize;
    private const int OuterClaimsSize = 3 * ScalarSize;

    private readonly SensitiveMemory source;
    private readonly int offset;


    /// <summary>The number of outer-sumcheck rounds carried in the window.</summary>
    public int OuterRoundCount { get; }

    /// <summary>The number of inner-sumcheck rounds carried in the window.</summary>
    public int InnerRoundCount { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>
    /// Windows the middle block of <paramref name="source"/> starting at
    /// <paramref name="middleOffset"/>. The source proof must outlive this part.
    /// </summary>
    internal SpartanSumcheckProofPart(
        SensitiveMemory source,
        int middleOffset,
        int outerRoundCount,
        int innerRoundCount,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentOutOfRangeException.ThrowIfNegative(middleOffset);
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);

        this.source = source;
        offset = middleOffset;
        OuterRoundCount = outerRoundCount;
        InnerRoundCount = innerRoundCount;
        Curve = curve;
    }


    /// <summary>Returns the compressed bytes of the outer round at <paramref name="roundIndex"/> (96 bytes).</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="roundIndex"/> is outside <c>[0, OuterRoundCount)</c>.</exception>
    public ReadOnlySpan<byte> GetOuterRoundCompressedBytes(int roundIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(roundIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(roundIndex, OuterRoundCount);

        return source.AsReadOnlySpan().Slice(offset + (roundIndex * OuterRoundCompressedSize), OuterRoundCompressedSize);
    }


    /// <summary>Returns the compressed bytes of the inner round at <paramref name="roundIndex"/> (64 bytes).</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="roundIndex"/> is outside <c>[0, InnerRoundCount)</c>.</exception>
    public ReadOnlySpan<byte> GetInnerRoundCompressedBytes(int roundIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(roundIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(roundIndex, InnerRoundCount);

        return source.AsReadOnlySpan().Slice(InnerRoundsStart() + (roundIndex * InnerRoundCompressedSize), InnerRoundCompressedSize);
    }


    /// <summary>Returns the canonical bytes of <c>claim_Az</c>.</summary>
    public ReadOnlySpan<byte> GetClaimAzBytes() => source.AsReadOnlySpan().Slice(ClaimsStart(), ScalarSize);

    /// <summary>Returns the canonical bytes of <c>claim_Bz</c>.</summary>
    public ReadOnlySpan<byte> GetClaimBzBytes() => source.AsReadOnlySpan().Slice(ClaimsStart() + ScalarSize, ScalarSize);

    /// <summary>Returns the canonical bytes of <c>claim_Cz</c>.</summary>
    public ReadOnlySpan<byte> GetClaimCzBytes() => source.AsReadOnlySpan().Slice(ClaimsStart() + (2 * ScalarSize), ScalarSize);

    /// <summary>Returns the canonical bytes of the relaxed error-MLE evaluation <c>E(r_x)</c>.</summary>
    public ReadOnlySpan<byte> GetErrorEvaluationBytes() => source.AsReadOnlySpan().Slice(ClaimsStart() + OuterClaimsSize, ScalarSize);

    /// <summary>Returns the canonical bytes of the witness MLE evaluation <c>eval_W</c>.</summary>
    public ReadOnlySpan<byte> GetEvalWBytes() => source.AsReadOnlySpan().Slice(InnerRoundsStart() + (InnerRoundCount * InnerRoundCompressedSize), ScalarSize);


    private int ClaimsStart() => offset + (OuterRoundCount * OuterRoundCompressedSize);

    private int InnerRoundsStart() => ClaimsStart() + OuterClaimsSize + ScalarSize;


    /// <summary>The total byte size of the middle block for the supplied round counts.</summary>
    internal static int GetSectionSizeBytes(int outerRoundCount, int innerRoundCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);

        return (outerRoundCount * OuterRoundCompressedSize)
            + OuterClaimsSize
            + ScalarSize //E(r_x)
            + (innerRoundCount * InnerRoundCompressedSize)
            + ScalarSize; //eval_W
    }


    /// <summary>
    /// Packs the scheme-independent middle block into <paramref name="destination"/>
    /// (exactly <see cref="GetSectionSizeBytes"/>(<paramref name="outerRounds"/>.Count,
    /// <paramref name="innerRounds"/>.Count) bytes) in the canonical order. Both
    /// <see cref="SpartanProof"/> and <see cref="BaseFoldSpartanProof"/> route
    /// their middle through this so the block is byte-identical across schemes.
    /// </summary>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a round has the wrong degree for its phase or a length does not match.</exception>
    internal static void Write(
        Span<byte> destination,
        IReadOnlyList<SumcheckRound> outerRounds,
        Scalar claimAz,
        Scalar claimBz,
        Scalar claimCz,
        Scalar errorEvaluation,
        IReadOnlyList<SumcheckRound> innerRounds,
        Scalar evalW)
    {
        ArgumentNullException.ThrowIfNull(outerRounds);
        ArgumentNullException.ThrowIfNull(claimAz);
        ArgumentNullException.ThrowIfNull(claimBz);
        ArgumentNullException.ThrowIfNull(claimCz);
        ArgumentNullException.ThrowIfNull(errorEvaluation);
        ArgumentNullException.ThrowIfNull(innerRounds);
        ArgumentNullException.ThrowIfNull(evalW);

        int expected = GetSectionSizeBytes(outerRounds.Count, innerRounds.Count);
        if(destination.Length != expected)
        {
            throw new ArgumentException(
                $"Sumcheck-part destination must be {expected} bytes for {outerRounds.Count} outer and {innerRounds.Count} inner rounds; received {destination.Length}.",
                nameof(destination));
        }

        int cursor = 0;
        for(int i = 0; i < outerRounds.Count; i++)
        {
            outerRounds[i].GetCompressedPolynomialBytes().CopyTo(destination.Slice(cursor, OuterRoundCompressedSize));
            cursor += OuterRoundCompressedSize;
        }

        claimAz.AsReadOnlySpan().CopyTo(destination.Slice(cursor, ScalarSize));
        cursor += ScalarSize;
        claimBz.AsReadOnlySpan().CopyTo(destination.Slice(cursor, ScalarSize));
        cursor += ScalarSize;
        claimCz.AsReadOnlySpan().CopyTo(destination.Slice(cursor, ScalarSize));
        cursor += ScalarSize;
        errorEvaluation.AsReadOnlySpan().CopyTo(destination.Slice(cursor, ScalarSize));
        cursor += ScalarSize;

        for(int i = 0; i < innerRounds.Count; i++)
        {
            innerRounds[i].GetCompressedPolynomialBytes().CopyTo(destination.Slice(cursor, InnerRoundCompressedSize));
            cursor += InnerRoundCompressedSize;
        }

        evalW.AsReadOnlySpan().CopyTo(destination.Slice(cursor, ScalarSize));
    }
}
