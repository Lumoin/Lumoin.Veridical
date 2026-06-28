using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A univariate polynomial in coefficient form:
/// <c>f(x) = c_0 + c_1·x + c_2·x^2 + ... + c_d·x^d</c>,
/// carried as <c>d+1</c> field-element coefficients in canonical
/// big-endian byte order, low-degree first.
/// </summary>
/// <remarks>
/// <para>
/// Like <see cref="MultilinearExtension"/> the type is broad: one
/// <see cref="Polynomial"/> represents univariate polynomials over any
/// curve's scalar field, with the field identity in the
/// <see cref="Tag"/>. Protocol logic that builds and evaluates
/// polynomials does not care which curve underlies the field.
/// </para>
/// <para>
/// Three entries always appear in the tag: an
/// <see cref="AlgebraicRole.PolynomialCoefficients"/> discriminator
/// (the role's name reflects the historical coefficient-form choice
/// and matches the univariate-polynomial concept the handout asked
/// for), the <see cref="CurveParameterSet"/>, and a
/// <see cref="PolynomialDegree"/> value carrying the storage degree
/// so consumers can read the size without unwrapping the leaf type.
/// </para>
/// <para>
/// <see cref="Degree"/> is the storage degree — the index of the
/// highest-degree coefficient slot. The actual algebraic degree may
/// be smaller when the leading coefficient is zero; the polynomial
/// inspection surface reports both the storage degree and predicates
/// that look at the coefficient pattern. Arithmetic delegates use
/// storage degree to size their inputs and outputs uniformly.
/// </para>
/// <para>
/// Buffer layout: <c>coefficients[k]</c> at byte offset
/// <c>k · fieldElementSize</c> for <c>k ∈ [0, degree]</c>. The
/// evaluate delegate's Horner walk traverses high-to-low.
/// </para>
/// </remarks>
public sealed class Polynomial: SensitiveMemory
{
    //Upper bound on storage degree: in a v1 prover the largest univariate
    //witness polynomial is the per-round sumcheck polynomial of degree at
    //most 3 (for a degree-3 constraint system), so a generous cap at 2^20
    //is well above any realistic use. The cap exists to bound int-domain
    //buffer-length arithmetic.
    private const int MaximumDegree = (1 << 20) - 1;


    /// <summary>The storage degree; <see cref="CoefficientCount"/> equals <c>Degree + 1</c>.</summary>
    public int Degree { get; }

    /// <summary>The number of coefficients stored (<c>Degree + 1</c>).</summary>
    public int CoefficientCount => Degree + 1;

    /// <summary>The byte size of one coefficient.</summary>
    public int FieldElementSizeBytes { get; }

    /// <summary>The curve identifying the field the coefficients live in.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>
    /// Constructs a polynomial over a buffer the caller has already
    /// populated. The instance takes ownership of <paramref name="owner"/>.
    /// </summary>
    /// <param name="owner">A pool-rented buffer whose first <c>(degree + 1) * fieldElementSizeBytes</c> bytes hold the canonical big-endian coefficients, low-degree first.</param>
    /// <param name="degree">The storage degree.</param>
    /// <param name="fieldElementSizeBytes">The byte size of one coefficient.</param>
    /// <param name="curve">The curve identifying the field.</param>
    /// <param name="tag">The runtime tag.</param>
    internal Polynomial(
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
    /// Copies caller-supplied coefficients into a pool-rented buffer and
    /// returns a polynomial wrapping them.
    /// </summary>
    /// <param name="coefficients">Exactly <c>(degree + 1) * fieldElementSizeBytes</c> bytes carrying the coefficients in canonical big-endian order, low-degree first.</param>
    /// <param name="degree">The storage degree.</param>
    /// <param name="curve">The curve identifying the field.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A polynomial wrapping a pool-rented copy of the supplied coefficients.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="degree"/> is outside <c>[0, 2^20 - 1]</c>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="coefficients"/> has the wrong length.</exception>
    public static Polynomial FromCoefficients(
        ReadOnlySpan<byte> coefficients,
        int degree,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ValidateDegree(degree);

        int fieldElementSize = GetFieldElementSizeBytes(curve);
        int expectedLength = (degree + 1) * fieldElementSize;
        if(coefficients.Length != expectedLength)
        {
            throw new ArgumentException(
                $"Polynomial of degree {degree} over {curve} requires exactly {expectedLength} bytes ({degree + 1} × {fieldElementSize}); received {coefficients.Length}.",
                nameof(coefficients));
        }

        IMemoryOwner<byte> owner = pool.Rent(expectedLength);
        coefficients.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(degree, curve)
            : MergeWithAlgebraicTag(tag, degree, curve);

        return new Polynomial(owner, degree, fieldElementSize, curve, effectiveTag);
    }


    /// <summary>
    /// Returns the zero polynomial of the requested storage degree.
    /// Every coefficient slot is the field zero.
    /// </summary>
    /// <param name="degree">The storage degree.</param>
    /// <param name="curve">The curve identifying the field.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <returns>A polynomial with all <c>degree + 1</c> coefficients set to zero.</returns>
    public static Polynomial Zero(
        int degree,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ValidateDegree(degree);

        int fieldElementSize = GetFieldElementSizeBytes(curve);
        int totalSize = (degree + 1) * fieldElementSize;

        IMemoryOwner<byte> owner = pool.Rent(totalSize);
        owner.Memory.Span[..totalSize].Clear();

        Tag tag = ComposeAlgebraicTag(degree, curve);

        return new Polynomial(owner, degree, fieldElementSize, curve, tag);
    }


    /// <summary>
    /// Returns a degree-0 polynomial whose single coefficient is
    /// <paramref name="constantValue"/>.
    /// </summary>
    /// <param name="constantValue">The constant coefficient bytes; length must equal the curve's scalar size.</param>
    /// <param name="curve">The curve identifying the field.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <exception cref="ArgumentException">When <paramref name="constantValue"/> has the wrong length.</exception>
    public static Polynomial Constant(
        ReadOnlySpan<byte> constantValue,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int fieldElementSize = GetFieldElementSizeBytes(curve);
        if(constantValue.Length != fieldElementSize)
        {
            throw new ArgumentException(
                $"Constant polynomial coefficient over {curve} requires exactly {fieldElementSize} bytes; received {constantValue.Length}.",
                nameof(constantValue));
        }

        IMemoryOwner<byte> owner = pool.Rent(fieldElementSize);
        constantValue.CopyTo(owner.Memory.Span);

        Tag tag = ComposeAlgebraicTag(0, curve);

        return new Polynomial(owner, 0, fieldElementSize, curve, tag);
    }


    /// <summary>
    /// Returns the canonical scalar-field byte size for the supplied
    /// curve. Throws for curves the polynomial layer does not yet wire.
    /// </summary>
    /// <exception cref="ArgumentException">When the curve is not supported by the polynomial layer.</exception>
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
            $"The polynomial layer supports Bls12Curve381 or Bn254; received '{curve}'.",
            nameof(curve));
    }


    private static void ValidateDegree(int degree)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(degree);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(degree, MaximumDegree);
    }


    private static Tag ComposeAlgebraicTag(int degree, CurveParameterSet curve)
    {
        return Tag.Create(AlgebraicRole.PolynomialCoefficients)
            .With(curve)
            .With(new PolynomialDegree(degree));
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, int degree, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.PolynomialCoefficients)
            .With(curve)
            .With(new PolynomialDegree(degree));
    }
}