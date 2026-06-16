using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Arithmetic in the quadratic extension <c>Fp256[i]/(i² + 1)</c> of the P-256 base field, a faithful
/// port of google/longfellow-zk's <c>lib/algebra/fp2.h</c> <c>Fp2&lt;Fp256Base&gt;</c> with the
/// nonresidue fixed to <c>−1</c> (the "complex" case <c>i² = −1</c>). This is the field the reference's
/// real-FFT Reed–Solomon encoder for the P-256 signature circuit lives over: the twiddle factors and the
/// FFT roots of unity are extension elements, while the data being transformed stays in the base field.
/// </summary>
/// <remarks>
/// <para>
/// An extension element <c>a = re + i·im</c> is carried as the pair of its two base-field coordinates,
/// each a 32-byte canonical big-endian scalar, laid out <c>re ‖ im</c> in a 64-byte span. The base-field
/// arithmetic is delegate-injected (the Fp256 add/subtract/multiply/invert backends) so the construction
/// stays consistent with the library's primitive-agnostic algebraic infrastructure.
/// </para>
/// <para>
/// The operations mirror the reference exactly. <em>Addition / subtraction</em> are coordinate-wise.
/// <em>Multiplication</em> uses the three-multiply Karatsuba form: with <c>p0 = re·y.re</c>,
/// <c>p1 = im·y.im</c>, the product's real part is <c>p0 − p1</c> (the nonresidue is <c>−1</c>) and its
/// imaginary part is <c>(re + im)·(y.re + y.im) − p0 − p1</c>. <em>Conjugation</em> negates the
/// imaginary part. <em>Inversion</em> divides the conjugate by the norm <c>re² + im²</c> (so
/// <c>x·conj(x) = 1</c> on the unit circle, which the reference's real-FFT validity check relies on).
/// </para>
/// </remarks>
internal sealed class Fp256QuadraticExtension
{
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The byte size of an extension element: two base-field coordinates, <c>re ‖ im</c>.</summary>
    public const int ElementSize = 2 * ScalarSize;

    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly ScalarInvertDelegate invert;
    private readonly CurveParameterSet curve;


    /// <summary>
    /// Constructs the extension over the supplied P-256 base-field arithmetic.
    /// </summary>
    /// <param name="add">Base-field addition.</param>
    /// <param name="subtract">Base-field subtraction.</param>
    /// <param name="multiply">Base-field multiplication.</param>
    /// <param name="invert">Base-field inversion.</param>
    /// <param name="curve">The curve the delegates route over (the reference passes none for the bare field).</param>
    /// <exception cref="ArgumentNullException">When a delegate is <see langword="null"/>.</exception>
    public Fp256QuadraticExtension(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);

        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.invert = invert;
        this.curve = curve;
    }


    /// <summary>The real (base-field) coordinate of <paramref name="element"/>.</summary>
    public static ReadOnlySpan<byte> Real(ReadOnlySpan<byte> element) => element[..ScalarSize];

    /// <summary>The imaginary (base-field) coordinate of <paramref name="element"/>.</summary>
    public static ReadOnlySpan<byte> Imaginary(ReadOnlySpan<byte> element) => element.Slice(ScalarSize, ScalarSize);


    /// <summary>Sets <paramref name="element"/> to the extension element <c>re + i·im</c>.</summary>
    public static void Set(Span<byte> element, ReadOnlySpan<byte> re, ReadOnlySpan<byte> im)
    {
        re.CopyTo(element[..ScalarSize]);
        im.CopyTo(element.Slice(ScalarSize, ScalarSize));
    }


    /// <summary><c>result = a + b</c> over the extension (coordinate-wise).</summary>
    public void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        add(Real(a), Real(b), result[..ScalarSize], curve);
        add(Imaginary(a), Imaginary(b), result.Slice(ScalarSize, ScalarSize), curve);
    }


    /// <summary><c>result = a − b</c> over the extension (coordinate-wise).</summary>
    public void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        subtract(Real(a), Real(b), result[..ScalarSize], curve);
        subtract(Imaginary(a), Imaginary(b), result.Slice(ScalarSize, ScalarSize), curve);
    }


    /// <summary>
    /// <c>result = a · b</c> over the extension, the reference's three-multiply Karatsuba form with the
    /// nonresidue fixed to <c>−1</c>.
    /// </summary>
    public void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<byte> p0 = stackalloc byte[ScalarSize];
        Span<byte> p1 = stackalloc byte[ScalarSize];
        Span<byte> a01 = stackalloc byte[ScalarSize];
        Span<byte> y01 = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];

        multiply(Real(a), Real(b), p0, curve);
        multiply(Imaginary(a), Imaginary(b), p1, curve);
        add(Real(a), Imaginary(a), a01, curve);
        add(Real(b), Imaginary(b), y01, curve);

        //im = (re+im)·(y.re+y.im) − p0 − p1; compute it before overwriting result.re in case of aliasing.
        multiply(a01, y01, sum, curve);
        subtract(sum, p0, sum, curve);
        subtract(sum, p1, sum, curve);

        //re = p0 − p1 (nonresidue −1).
        subtract(p0, p1, result[..ScalarSize], curve);
        sum.CopyTo(result.Slice(ScalarSize, ScalarSize));
    }


    /// <summary><c>result = conj(a)</c>: the imaginary coordinate negated (real coordinate unchanged).</summary>
    public void Conjugate(ReadOnlySpan<byte> a, Span<byte> result)
    {
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        Real(a).CopyTo(result[..ScalarSize]);
        subtract(zero, Imaginary(a), result.Slice(ScalarSize, ScalarSize), curve);
    }


    /// <summary>
    /// <c>result = a⁻¹</c>: the conjugate scaled by the inverse of the norm <c>re² + im²</c>, the
    /// reference's <c>invert</c> for the <c>−1</c> nonresidue.
    /// </summary>
    /// <exception cref="InvalidOperationException">When <paramref name="a"/> is zero.</exception>
    public void Invert(ReadOnlySpan<byte> a, Span<byte> result)
    {
        Span<byte> reSquared = stackalloc byte[ScalarSize];
        Span<byte> imSquared = stackalloc byte[ScalarSize];
        Span<byte> norm = stackalloc byte[ScalarSize];

        multiply(Real(a), Real(a), reSquared, curve);
        multiply(Imaginary(a), Imaginary(a), imSquared, curve);
        add(reSquared, imSquared, norm, curve);
        invert(norm, norm, curve);

        //result = conj(a) · norm⁻¹, where norm⁻¹ is a real scalar (scale both coordinates).
        Span<byte> conjugate = stackalloc byte[ElementSize];
        Conjugate(a, conjugate);
        multiply(Real(conjugate), norm, result[..ScalarSize], curve);
        multiply(Imaginary(conjugate), norm, result.Slice(ScalarSize, ScalarSize), curve);
    }


    /// <summary>
    /// <c>result = a²</c>, the squared extension element (one multiply through <see cref="Multiply"/>).
    /// </summary>
    public void Square(ReadOnlySpan<byte> a, Span<byte> result) => Multiply(a, a, result);
}
