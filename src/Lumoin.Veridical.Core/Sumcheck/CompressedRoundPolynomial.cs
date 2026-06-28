using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Sumcheck;

/// <summary>
/// A sumcheck round polynomial in compressed form: the coefficient
/// vector of a univariate polynomial of degree <c>d ≥ 2</c> with the
/// linear-term slot elided. Storage is <c>d</c> field elements in the
/// order <c>(c_0, c_2, c_3, ..., c_d)</c>; the missing <c>c_1</c> is
/// reconstructed from the running sumcheck claim at decompress time.
/// </summary>
/// <remarks>
/// <para>
/// Compression saves one field element per sumcheck round (~32 bytes for
/// BLS12-381) and — more importantly — pins the absorbed bytes to the
/// canonical Spartan2 transcript shape. Verifiers and provers must
/// serialise the same compressed bytes onto the transcript to interop.
/// </para>
/// <para>
/// The reconstruction identity ties decompression to the running claim
/// <c>e</c> of the sumcheck round. The verifier already knows
/// <c>e = poly(0) + poly(1)</c> from the prior round; the decompress
/// helper computes
/// <c>c_1 = e − 2·c_0 − c_2 − c_3 − … − c_d</c>
/// and writes a regular <see cref="Polynomial"/> the rest of the round
/// machinery consumes.
/// </para>
/// <para>
/// The type is broad in the rules-document sense — one
/// <see cref="CompressedRoundPolynomial"/> represents the compressed
/// round polynomial over any curve's scalar field, with the field
/// identity in the <see cref="Tag"/>. BLS12-381 and BN254 are wired;
/// the <see cref="GetFieldElementSizeBytes"/> dispatch grows when more
/// curves are added.
/// </para>
/// <para>
/// Buffer layout, in storage order:
/// </para>
/// <code>
/// [c_0 : 32 bytes] [c_2 : 32 bytes] [c_3 : 32 bytes] ... [c_d : 32 bytes]
/// </code>
/// <para>
/// Total: <c>Degree × fieldElementSize</c> bytes. Slot <c>i</c> in
/// storage corresponds to coefficient index <c>0</c> when <c>i = 0</c>
/// and <c>i + 1</c> when <c>i ≥ 1</c> — slot indices skip the elided
/// linear term.
/// </para>
/// </remarks>
public sealed class CompressedRoundPolynomial: SensitiveMemory
{
    //Reasonable upper bound on the algebraic degree carried in a round
    //polynomial. Spartan v1 uses degree 3 (outer sumcheck) and degree 2
    //(inner sumcheck); higher-degree round polynomials appear in
    //extensions for higher-degree constraint systems. A generous cap at
    //2^10 bounds int-domain buffer-length arithmetic with margin.
    private const int MaximumDegree = (1 << 10) - 1;

    //A degree-1 polynomial only has c_0 and c_1; eliding c_1 leaves
    //nothing meaningful in the buffer, and the sumcheck rounds it would
    //carry would always be linear (no need for compression). Compression
    //is meaningful only for degree-2 and higher.
    private const int MinimumDegree = 2;


    /// <summary>The algebraic degree <c>d</c> of the represented polynomial; storage carries <c>d</c> field elements.</summary>
    public int Degree { get; }

    /// <summary>The number of field elements stored — equal to <see cref="Degree"/>, one fewer than an uncompressed polynomial of the same algebraic degree carries.</summary>
    public int StoredCoefficientCount => Degree;

    /// <summary>The byte size of one field element.</summary>
    public int FieldElementSizeBytes { get; }

    /// <summary>The curve identifying the field the coefficients live in.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>
    /// Constructs a compressed round polynomial over a buffer the caller
    /// has already populated. The instance takes ownership of
    /// <paramref name="owner"/>.
    /// </summary>
    internal CompressedRoundPolynomial(
        IMemoryOwner<byte> owner,
        int degree,
        int fieldElementSizeBytes,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, tag)
    {
        Degree = degree;
        FieldElementSizeBytes = fieldElementSizeBytes;
        Curve = curve;
    }


    /// <summary>
    /// Copies caller-supplied compressed bytes into a pool-rented buffer
    /// and returns a compressed round polynomial wrapping them.
    /// </summary>
    /// <param name="compressedBytes">Exactly <c>degree × fieldElementSizeBytes</c> bytes in storage order: <c>(c_0, c_2, c_3, ..., c_d)</c>, each a canonical big-endian field element.</param>
    /// <param name="degree">The algebraic degree <c>d ≥ 2</c>.</param>
    /// <param name="curve">The curve identifying the field.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="degree"/> is outside <c>[2, 2^10 - 1]</c>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="compressedBytes"/> has the wrong length.</exception>
    public static CompressedRoundPolynomial FromCompressedBytes(
        ReadOnlySpan<byte> compressedBytes,
        int degree,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ValidateDegree(degree);

        int fieldElementSize = GetFieldElementSizeBytes(curve);
        int expectedLength = degree * fieldElementSize;
        if(compressedBytes.Length != expectedLength)
        {
            throw new ArgumentException(
                $"Compressed round polynomial of degree {degree} over {curve} requires exactly {expectedLength} bytes ({degree} × {fieldElementSize}); received {compressedBytes.Length}.",
                nameof(compressedBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(expectedLength);
        compressedBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(degree, curve)
            : MergeWithAlgebraicTag(tag, degree, curve);

        return new CompressedRoundPolynomial(owner, degree, fieldElementSize, curve, effectiveTag);
    }


    /// <summary>
    /// Returns the canonical big-endian bytes of the constant term <c>c_0</c>.
    /// </summary>
    public ReadOnlySpan<byte> GetConstantTermBytes() => AsReadOnlySpan()[..FieldElementSizeBytes];


    /// <summary>
    /// Returns the canonical big-endian bytes of the coefficient at the
    /// supplied storage slot. Slot 0 is <c>c_0</c>; slots <c>1, 2, ..., Degree − 1</c>
    /// are <c>c_2, c_3, ..., c_d</c>. The linear term <c>c_1</c> is not
    /// stored and is not addressable through this accessor.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="storageSlotIndex"/> is outside <c>[0, Degree)</c>.</exception>
    public ReadOnlySpan<byte> GetStoredCoefficientBytes(int storageSlotIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(storageSlotIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(storageSlotIndex, Degree);

        return AsReadOnlySpan().Slice(storageSlotIndex * FieldElementSizeBytes, FieldElementSizeBytes);
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
            $"The compressed round polynomial layer supports Bls12Curve381 or Bn254; received '{curve}'.",
            nameof(curve));
    }


    private static void ValidateDegree(int degree)
    {
        if(degree < MinimumDegree)
        {
            throw new ArgumentOutOfRangeException(
                nameof(degree),
                degree,
                $"Compressed round polynomial degree must be at least {MinimumDegree}; the construction is only meaningful when a quadratic or higher term is present.");
        }

        ArgumentOutOfRangeException.ThrowIfGreaterThan(degree, MaximumDegree);
    }


    private static Tag ComposeAlgebraicTag(int degree, CurveParameterSet curve)
    {
        return Tag.Create(AlgebraicRole.CompressedRoundPolynomial)
            .With(curve)
            .With(new CompressedRoundPolynomialDegree(degree));
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, int degree, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.CompressedRoundPolynomial)
            .With(curve)
            .With(new CompressedRoundPolynomialDegree(degree));
    }
}