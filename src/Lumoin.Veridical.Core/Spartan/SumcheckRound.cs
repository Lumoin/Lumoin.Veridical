using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// A single round of the sumcheck protocol: the prover's compressed
/// round polynomial and the verifier's challenge derived from it via
/// the Fiat-Shamir transcript. One <see cref="SumcheckRound"/> is
/// produced per protocol round, so a sumcheck of <c>numRounds</c>
/// variables collects <c>numRounds</c> instances.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in order:
/// </para>
/// <list type="number">
///   <item><description>Compressed round polynomial bytes: <c>Degree</c> field elements in storage order <c>(c_0, c_2, c_3, ..., c_d)</c>.</description></item>
///   <item><description>Verifier's challenge scalar: one canonical big-endian field element.</description></item>
/// </list>
/// <para>
/// Total: <c>(Degree + 1) × fieldElementSize</c> bytes for a
/// degree-<c>d</c> round polynomial. The linear term <c>c_1</c> is not
/// stored; it is reconstructed by callers via
/// <see cref="CompressedRoundPolynomialArithmeticExtensions.Decompress"/>
/// against the running sumcheck claim.
/// </para>
/// <para>
/// The type is broad in the rules-document sense — one
/// <see cref="SumcheckRound"/> can carry any curve's bytes, with the
/// curve identity in the <see cref="Tag"/>. Only BLS12-381 is wired
/// today; the <see cref="GetFieldElementSizeBytes"/> dispatch grows
/// when more curves are added.
/// </para>
/// <para>
/// SumcheckRound does not own the inner
/// <see cref="CompressedRoundPolynomial"/> or
/// <see cref="Scalar"/> instances the caller constructed —
/// it copies their bytes into one contiguous pool-rented buffer at
/// <see cref="Create"/> time. Callers may dispose their original inner
/// objects immediately afterwards.
/// </para>
/// </remarks>
public sealed class SumcheckRound: SensitiveMemory
{
    /// <summary>The zero-based round index.</summary>
    public int RoundIndex { get; }

    /// <summary>The algebraic degree of the round polynomial.</summary>
    public int Degree { get; }

    /// <summary>The byte size of one field element.</summary>
    public int FieldElementSizeBytes { get; }

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    internal SumcheckRound(
        IMemoryOwner<byte> owner,
        int roundIndex,
        int degree,
        int fieldElementSizeBytes,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, (degree + 1) * fieldElementSizeBytes, tag)
    {
        RoundIndex = roundIndex;
        Degree = degree;
        FieldElementSizeBytes = fieldElementSizeBytes;
        Curve = curve;
    }


    /// <summary>
    /// Bundles a compressed round polynomial and a verifier challenge
    /// into a single <see cref="SumcheckRound"/>. Bytes from both
    /// arguments are copied into a fresh pool-rented buffer; the inputs
    /// can be disposed immediately afterwards.
    /// </summary>
    /// <param name="roundIndex">The zero-based round index.</param>
    /// <param name="roundPolynomial">The prover's compressed round polynomial.</param>
    /// <param name="challenge">The verifier's challenge scalar squeezed from the transcript after absorbing <paramref name="roundPolynomial"/>.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A round wrapping a pool-rented copy of both inputs' bytes.</returns>
    /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="roundIndex"/> is negative.</exception>
    /// <exception cref="ArgumentException">When the polynomial and challenge curves disagree, or either is not over BLS12-381.</exception>
    public static SumcheckRound Create(
        int roundIndex,
        CompressedRoundPolynomial roundPolynomial,
        Scalar challenge,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(roundPolynomial);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(roundIndex);

        WellKnownCurves.ThrowIfCurveNotWired(roundPolynomial.Curve);

        CurveParameterSet curve = roundPolynomial.Curve;
        int elementSize = GetFieldElementSizeBytes(curve);
        if(challenge.AsReadOnlySpan().Length != elementSize)
        {
            throw new ArgumentException(
                $"Challenge length {challenge.AsReadOnlySpan().Length} does not match the {curve} scalar size {elementSize}.",
                nameof(challenge));
        }

        int degree = roundPolynomial.Degree;
        int compressedSize = degree * elementSize;
        int bufferSize = compressedSize + elementSize;

        IMemoryOwner<byte> owner = pool.Rent(bufferSize);
        Span<byte> buffer = owner.Memory.Span[..bufferSize];
        roundPolynomial.AsReadOnlySpan().CopyTo(buffer[..compressedSize]);
        challenge.AsReadOnlySpan().CopyTo(buffer.Slice(compressedSize, elementSize));

        var dimensions = new SumcheckRoundDimensions(roundIndex, degree);
        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(dimensions, curve)
            : MergeWithAlgebraicTag(tag, dimensions, curve);

        return new SumcheckRound(owner, roundIndex, degree, elementSize, curve, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the compressed round polynomial — <c>Degree × fieldElementSize</c> bytes.</summary>
    public ReadOnlySpan<byte> GetCompressedPolynomialBytes()
    {
        return AsReadOnlySpan()[..(Degree * FieldElementSizeBytes)];
    }


    /// <summary>Returns the canonical big-endian bytes of the verifier's challenge scalar.</summary>
    public ReadOnlySpan<byte> GetChallengeBytes()
    {
        return AsReadOnlySpan().Slice(Degree * FieldElementSizeBytes, FieldElementSizeBytes);
    }


    /// <summary>Returns the canonical scalar-field byte size for the supplied curve. Throws for unsupported curves.</summary>
    internal static int GetFieldElementSizeBytes(CurveParameterSet curve)
    {
        if(curve.Code == CurveParameterSet.Bls12Curve381.Code)
        {
            return WellKnownCurves.Bls12Curve381ScalarSizeBytes;
        }

        if(curve.Code == CurveParameterSet.Bn254.Code)
        {
            return WellKnownCurves.Bn254ScalarSizeBytes;
        }

        throw new ArgumentException(
            $"SumcheckRound supports Bls12Curve381 or Bn254; received {curve}.",
            nameof(curve));
    }


    private static Tag ComposeAlgebraicTag(SumcheckRoundDimensions dimensions, CurveParameterSet curve)
    {
        return Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.SumcheckRound),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(SumcheckRoundDimensions), (object)dimensions));
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, SumcheckRoundDimensions dimensions, CurveParameterSet curve)
    {
        return tag.With(
            (typeof(AlgebraicRole), (object)AlgebraicRole.SumcheckRound),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(SumcheckRoundDimensions), (object)dimensions));
    }
}