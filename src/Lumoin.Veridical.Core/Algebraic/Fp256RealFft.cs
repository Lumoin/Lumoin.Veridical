using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The radix-4 real fast Fourier transform over the P-256 base field, a faithful port of
/// google/longfellow-zk's <c>lib/algebra/rfft.h</c> <c>RFFT&lt;Fp2&lt;Fp256Base&gt;&gt;</c>. It transforms
/// a power-of-two array of base-field ("real") elements to and from the FFTW-style "half-complex"
/// storage of the conjugate-symmetric spectrum. This is the transform the reference's Fp256 Reed–Solomon
/// convolution runs (<c>r2hc</c> forward, <c>hc2r</c> backward), so reproducing it element-for-element is
/// what makes the P-256 signature-circuit Ligero codewords match the reference's.
/// </summary>
/// <remarks>
/// <para>
/// The spectrum <c>F[j]</c> of a real input is conjugate symmetric (<c>F[n−j] = conj(F[j])</c>), so it is
/// stored in <c>n</c> base-field slots: <c>HC[j] = real(F[j])</c> for <c>2j ≤ n</c> and
/// <c>HC[j] = imag(F[n−j])</c> otherwise. The forward transform is R2HC (real → half-complex, the FFTW
/// "forward" sign), the backward is HC2R; HC2R(R2HC(x)) scales by <c>n</c>, which the convolution layer
/// pre-divides out.
/// </para>
/// <para>
/// The algorithm is decimation-in-time radix-4 Cooley–Tukey with a single radix-2 pass when the log is
/// odd, placed in the first (twiddle-free) butterfly level. The first butterfly of each level is the
/// twiddle-free real <c>r2hcI_4</c>; the middle butterflies are the complex <c>hc2hcf_4</c>; the last
/// (Nyquist) butterfly is the eighth-root <c>r2hcII_4</c>. The backward transform runs the same structure
/// in reverse with <c>hc2rI_4</c> / <c>hc2hcb_4</c> / <c>hc2rIII_4</c>. The twiddle factors are powers of
/// the appropriate root of unity in the quadratic extension (<see cref="Fp256QuadraticExtension"/>),
/// precomputed once per transform size; the butterflies touch only their base-field coordinates.
/// </para>
/// <para>
/// In-place over a caller span of <c>n · 32</c> base-field bytes. The twiddle table and the bit-reversal
/// scratch are pool-rented and cleared on return. The base-field arithmetic is delegate-injected so the
/// port stays consistent with the library's primitive-agnostic algebraic infrastructure.
/// </para>
/// <para>
/// The reference's <c>validate_root</c>, <c>validate_I</c>, and <c>validate_w8</c> debug assertions —
/// that the root lies on the unit circle, that ω^{n/4} = +i, and that the eighth-root's real and
/// imaginary parts are equal — are preconditions the radix-4 butterflies assume and are not re-checked
/// here; a caller must supply a root satisfying them (the mdoc configuration's root does).
/// </para>
/// </remarks>
internal sealed class Fp256RealFft: IDisposable
{
    /// <summary>The byte width of one base-field scalar.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The byte width of one quadratic-extension element (<c>re ‖ im</c>).</summary>
    private const int ExtensionSize = Fp256QuadraticExtension.ElementSize;

    /// <summary>The base-field addition delegate every butterfly computes over.</summary>
    private ScalarAddDelegate Add { get; }

    /// <summary>The base-field subtraction delegate every butterfly computes over.</summary>
    private ScalarSubtractDelegate Subtract { get; }

    /// <summary>The base-field multiplication delegate the twiddle and complex-multiply steps use.</summary>
    private ScalarMultiplyDelegate Multiply { get; }

    /// <summary>The base-field <c>of_scalar(u)</c> delegate, used to seed the twiddle table's extension one.</summary>
    private Action<uint, Span<byte>> OfScalar { get; }

    /// <summary>The quadratic-extension arithmetic built from this engine's base-field delegates, used to reroot and advance the twiddle table.</summary>
    private Fp256QuadraticExtension Extension { get; }

    /// <summary>The curve the base-field delegates route over.</summary>
    private CurveParameterSet Curve { get; }

    /// <summary>The pool the retained root, twiddle table and bit-reversal scratch rent from.</summary>
    private BaseMemoryPool Pool { get; }

    /// <summary>The owned root of unity, an extension element, retained until every transform and encoder callback has completed.</summary>
    private IMemoryOwner<byte>? omega;

    /// <summary>The root's multiplicative order, from which the transform reroots it to the size it needs.</summary>
    private ulong OmegaOrder { get; }


    /// <summary>
    /// Constructs the real-FFT engine for the supplied root of unity.
    /// </summary>
    /// <param name="omega">The root of unity in the quadratic extension (<c>re ‖ im</c>, 64 bytes), of order <paramref name="omegaOrder"/>, already in the working domain the delegates compute over.</param>
    /// <param name="omegaOrder">The multiplicative order of <paramref name="omega"/> (a power of two ≥ every transform size).</param>
    /// <param name="add">Base-field addition.</param>
    /// <param name="subtract">Base-field subtraction.</param>
    /// <param name="multiply">Base-field multiplication.</param>
    /// <param name="invert">Base-field inversion (the extension's norm divide).</param>
    /// <param name="ofScalar">The base-field <c>of_scalar(u)</c> in the working domain; the twiddle seed (the extension one) is <c>ofScalar(1)</c> in the real coordinate.</param>
    /// <param name="curve">The curve the delegates route over.</param>
    /// <param name="pool">Pool the retained root, twiddle table and scratch rent from; it must outlive this engine.</param>
    /// <exception cref="ArgumentNullException">When a delegate, the root or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="omega"/> is not 64 bytes.</exception>
    public Fp256RealFft(
        ReadOnlySpan<byte> omega,
        ulong omegaOrder,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        Action<uint, Span<byte>> ofScalar,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(pool);

        if(omega.Length != ExtensionSize)
        {
            throw new ArgumentException($"The root of unity is {ExtensionSize} bytes; received {omega.Length}.", nameof(omega));
        }

        this.Add = add;
        this.Subtract = subtract;
        this.Multiply = multiply;
        this.OfScalar = ofScalar;
        this.Curve = curve;
        this.Pool = pool;
        Extension = new Fp256QuadraticExtension(add, subtract, multiply, invert, curve);
        omegaOrder = omegaOrder == 0 ? throw new ArgumentOutOfRangeException(nameof(omegaOrder)) : omegaOrder;
        this.OmegaOrder = omegaOrder;
        IMemoryOwner<byte>? owner = pool.Rent(ExtensionSize);
        try
        {
            omega.CopyTo(owner.Memory.Span[..ExtensionSize]);
            this.omega = owner;
            owner = null;
        }
        finally
        {
            owner?.Dispose();
        }
    }


    /// <summary>
    /// The forward real-to-half-complex transform, in place over <paramref name="data"/> (the reference's
    /// <c>r2hc</c>). <paramref name="length"/> must be a power of two.
    /// </summary>
    /// <param name="data"><paramref name="length"/> base-field elements (<c>length · 32</c> bytes).</param>
    /// <param name="length">The transform size; a power of two.</param>
    public void ForwardRealToHalfComplex(Span<byte> data, int length)
    {
        ValidateLength(data, length);

        if(length == 2)
        {
            R2HcI2(data, 0, 1);

            return;
        }

        if(length < 4)
        {
            return;
        }

        using TwiddleTable roots = BuildTwiddles(length);
        BitReverse(data, length);

        int m = length;
        while(m > 4)
        {
            m /= 4;
        }

        if(m == 2)
        {
            for(int k = 0; k < length; k += 2)
            {
                R2HcI2(data, k, 1);
            }
        }
        else
        {
            for(int k = 0; k < length; k += 4)
            {
                R2HcI4(data, k, 1);
            }
        }

        for(; m < length; m = 4 * m)
        {
            int ws = length / (4 * m);
            for(int k = 0; k < length; k += 4 * m)
            {
                R2HcI4(data, k, m);

                int j;
                for(j = 1; j + j < m; ++j)
                {
                    Hc2HcF4(data, k + j, k + m - j, m, roots.At(j * ws), roots.At(2 * j * ws), roots.At(3 * j * ws));
                }

                R2HcII4(data, k + j, m, roots.At(j * ws));
            }
        }
    }


    /// <summary>
    /// The backward half-complex-to-real transform, in place over <paramref name="data"/> (the
    /// reference's <c>hc2r</c>). <paramref name="length"/> must be a power of two.
    /// </summary>
    /// <param name="data"><paramref name="length"/> base-field elements (<c>length · 32</c> bytes).</param>
    /// <param name="length">The transform size; a power of two.</param>
    public void BackwardHalfComplexToReal(Span<byte> data, int length)
    {
        ValidateLength(data, length);

        if(length == 2)
        {
            Hc2RI2(data, 0, 1);

            return;
        }

        if(length < 4)
        {
            return;
        }

        using TwiddleTable roots = BuildTwiddles(length);

        int m = length;
        while(m > 4)
        {
            m /= 4;
            int ws = length / (4 * m);
            for(int k = 0; k < length; k += 4 * m)
            {
                Hc2RI4(data, k, m);

                int j;
                for(j = 1; j + j < m; ++j)
                {
                    Hc2HcB4(data, k + j, k + m - j, m, roots.At(j * ws), roots.At(2 * j * ws), roots.At(3 * j * ws));
                }

                Hc2RIII4(data, k + j, m, roots.At(j * ws));
            }
        }

        if(m == 2)
        {
            for(int k = 0; k < length; k += 2)
            {
                Hc2RI2(data, k, 1);
            }
        }
        else
        {
            for(int k = 0; k < length; k += 4)
            {
                Hc2RI4(data, k, 1);
            }
        }

        BitReverse(data, length);
    }


    /// <summary>The forward radix-2 butterfly (the reference's <c>r2hcI_2</c>).</summary>
    private void R2HcI2(Span<byte> a, int basePos, int s)
    {
        Span<byte> t = stackalloc byte[ScalarSize];
        At(a, basePos + s).CopyTo(t);
        At(a, basePos).CopyTo(At(a, basePos + s));
        AddInPlace(At(a, basePos), t);
        SubtractInto(At(a, basePos + s), t, At(a, basePos + s));
    }


    /// <summary>The forward twiddle-free radix-4 butterfly, the first level of each pass (the reference's <c>r2hcI_4</c>).</summary>
    private void R2HcI4(Span<byte> a, int basePos, int s)
    {
        Span<byte> x0 = stackalloc byte[ScalarSize];
        Span<byte> x1 = stackalloc byte[ScalarSize];
        Span<byte> x2 = stackalloc byte[ScalarSize];
        Span<byte> x3 = stackalloc byte[ScalarSize];
        Span<byte> z0 = stackalloc byte[ScalarSize];
        Span<byte> z1 = stackalloc byte[ScalarSize];
        At(a, basePos).CopyTo(x0);
        At(a, basePos + s).CopyTo(x1);
        At(a, basePos + (2 * s)).CopyTo(x2);
        At(a, basePos + (3 * s)).CopyTo(x3);

        Add(x0, x1, z0, Curve);
        Add(x2, x3, z1, Curve);
        Add(z0, z1, At(a, basePos), Curve);
        Subtract(z0, z1, At(a, basePos + (2 * s)), Curve);
        Subtract(x0, x1, At(a, basePos + s), Curve);
        Subtract(x3, x2, At(a, basePos + (3 * s)), Curve);
    }


    /// <summary>The forward Nyquist (eighth-root) radix-4 butterfly, the last level of each pass (the reference's <c>r2hcII_4</c>).</summary>
    private void R2HcII4(Span<byte> a, int basePos, int s, ReadOnlySpan<byte> w8)
    {
        ReadOnlySpan<byte> w8Re = Fp256QuadraticExtension.Real(w8);
        ReadOnlySpan<byte> w8Im = Fp256QuadraticExtension.Imaginary(w8);

        Span<byte> x2 = stackalloc byte[ScalarSize];
        Span<byte> x3 = stackalloc byte[ScalarSize];
        Span<byte> z0 = stackalloc byte[ScalarSize];
        Span<byte> z1 = stackalloc byte[ScalarSize];
        At(a, basePos + (2 * s)).CopyTo(x2);
        At(a, basePos + (3 * s)).CopyTo(x3);
        Add(x2, x3, z0, Curve);
        Subtract(x2, x3, z1, Curve);
        Multiply(z0, w8Im, z0, Curve);
        Multiply(z1, w8Re, z1, Curve);

        Span<byte> x0 = stackalloc byte[ScalarSize];
        Span<byte> x1 = stackalloc byte[ScalarSize];
        At(a, basePos).CopyTo(x0);
        At(a, basePos + s).CopyTo(x1);
        Add(x0, z1, At(a, basePos), Curve);
        Subtract(x0, z1, At(a, basePos + s), Curve);
        Subtract(x1, z0, At(a, basePos + (2 * s)), Curve);
        Add(x1, z0, At(a, basePos + (3 * s)), Curve);
        NegateInPlace(At(a, basePos + (3 * s)));
    }


    /// <summary>The forward complex middle radix-4 butterfly applied at every non-edge level (the reference's <c>hc2hcf_4</c>).</summary>
    private void Hc2HcF4(Span<byte> a, int rBase, int iBase, int s, ReadOnlySpan<byte> tw1, ReadOnlySpan<byte> tw2, ReadOnlySpan<byte> tw3)
    {
        ComplexMultiplyConjugate(At(a, rBase + s), At(a, iBase + s), Fp256QuadraticExtension.Real(tw2), Fp256QuadraticExtension.Imaginary(tw2));

        Span<byte> y0r = stackalloc byte[ScalarSize];
        Span<byte> y0i = stackalloc byte[ScalarSize];
        Span<byte> y1r = stackalloc byte[ScalarSize];
        Span<byte> y1i = stackalloc byte[ScalarSize];
        Add(At(a, rBase), At(a, rBase + s), y0r, Curve);
        Add(At(a, iBase), At(a, iBase + s), y0i, Curve);
        Subtract(At(a, rBase), At(a, rBase + s), y1r, Curve);
        Subtract(At(a, iBase), At(a, iBase + s), y1i, Curve);

        ComplexMultiplyConjugate(At(a, rBase + (2 * s)), At(a, iBase + (2 * s)), Fp256QuadraticExtension.Real(tw1), Fp256QuadraticExtension.Imaginary(tw1));
        ComplexMultiplyConjugate(At(a, rBase + (3 * s)), At(a, iBase + (3 * s)), Fp256QuadraticExtension.Real(tw3), Fp256QuadraticExtension.Imaginary(tw3));

        Span<byte> y2r = stackalloc byte[ScalarSize];
        Span<byte> y3r = stackalloc byte[ScalarSize];
        Span<byte> y2i = stackalloc byte[ScalarSize];
        Span<byte> y3i = stackalloc byte[ScalarSize];
        Add(At(a, rBase + (3 * s)), At(a, rBase + (2 * s)), y2r, Curve);
        Subtract(At(a, rBase + (3 * s)), At(a, rBase + (2 * s)), y3r, Curve);
        Add(At(a, iBase + (2 * s)), At(a, iBase + (3 * s)), y2i, Curve);
        Subtract(At(a, iBase + (2 * s)), At(a, iBase + (3 * s)), y3i, Curve);

        Add(y0r, y2r, At(a, rBase), Curve);
        Subtract(y0r, y2r, At(a, iBase + s), Curve);
        Add(y1r, y3i, At(a, rBase + s), Curve);
        Subtract(y1r, y3i, At(a, iBase), Curve);
        Add(y2i, y0i, At(a, iBase + (3 * s)), Curve);
        Subtract(y2i, y0i, At(a, rBase + (2 * s)), Curve);
        Add(y3r, y1i, At(a, iBase + (2 * s)), Curve);
        Subtract(y3r, y1i, At(a, rBase + (3 * s)), Curve);
    }


    /// <summary>The backward radix-2 butterfly (the reference's <c>hc2rI_2</c>).</summary>
    private void Hc2RI2(Span<byte> a, int basePos, int s)
    {
        Span<byte> t = stackalloc byte[ScalarSize];
        At(a, basePos + s).CopyTo(t);
        At(a, basePos).CopyTo(At(a, basePos + s));
        AddInPlace(At(a, basePos), t);
        SubtractInto(At(a, basePos + s), t, At(a, basePos + s));
    }


    /// <summary>The backward twiddle-free radix-4 butterfly, the last level of each pass (the reference's <c>hc2rI_4</c>).</summary>
    private void Hc2RI4(Span<byte> a, int basePos, int s)
    {
        Span<byte> y0 = stackalloc byte[ScalarSize];
        Span<byte> y1 = stackalloc byte[ScalarSize];
        Span<byte> y2 = stackalloc byte[ScalarSize];
        Span<byte> y3 = stackalloc byte[ScalarSize];
        Add(At(a, basePos), At(a, basePos + (2 * s)), y0, Curve);
        Subtract(At(a, basePos), At(a, basePos + (2 * s)), y1, Curve);
        Add(At(a, basePos + s), At(a, basePos + s), y2, Curve);
        Add(At(a, basePos + (3 * s)), At(a, basePos + (3 * s)), y3, Curve);

        Add(y0, y2, At(a, basePos), Curve);
        Subtract(y0, y2, At(a, basePos + s), Curve);
        Subtract(y1, y3, At(a, basePos + (2 * s)), Curve);
        Add(y1, y3, At(a, basePos + (3 * s)), Curve);
    }


    /// <summary>The backward Nyquist (eighth-root) radix-4 butterfly, the first level of each pass (the reference's <c>hc2rIII_4</c>).</summary>
    private void Hc2RIII4(Span<byte> a, int basePos, int s, ReadOnlySpan<byte> w8)
    {
        ReadOnlySpan<byte> w8Re = Fp256QuadraticExtension.Real(w8);
        ReadOnlySpan<byte> w8Im = Fp256QuadraticExtension.Imaginary(w8);

        Span<byte> x0 = stackalloc byte[ScalarSize];
        Span<byte> x1 = stackalloc byte[ScalarSize];
        Span<byte> x2 = stackalloc byte[ScalarSize];
        Span<byte> x3 = stackalloc byte[ScalarSize];
        Add(At(a, basePos), At(a, basePos), x0, Curve);
        Add(At(a, basePos + s), At(a, basePos + s), x1, Curve);
        Add(At(a, basePos + (2 * s)), At(a, basePos + (2 * s)), x2, Curve);
        Add(At(a, basePos + (3 * s)), At(a, basePos + (3 * s)), x3, Curve);

        Add(x0, x1, At(a, basePos), Curve);
        Subtract(x2, x3, At(a, basePos + s), Curve);

        Span<byte> z0 = stackalloc byte[ScalarSize];
        Span<byte> z1 = stackalloc byte[ScalarSize];
        Subtract(x0, x1, z0, Curve);
        Multiply(z0, w8Re, z0, Curve);
        Add(x3, x2, z1, Curve);
        Multiply(z1, w8Im, z1, Curve);
        Subtract(z0, z1, At(a, basePos + (2 * s)), Curve);
        Add(z0, z1, At(a, basePos + (3 * s)), Curve);
        NegateInPlace(At(a, basePos + (3 * s)));
    }


    /// <summary>The backward complex middle radix-4 butterfly applied at every non-edge level (the reference's <c>hc2hcb_4</c>).</summary>
    private void Hc2HcB4(Span<byte> a, int rBase, int iBase, int s, ReadOnlySpan<byte> tw1, ReadOnlySpan<byte> tw2, ReadOnlySpan<byte> tw3)
    {
        Span<byte> z0 = stackalloc byte[ScalarSize];
        Span<byte> z1 = stackalloc byte[ScalarSize];
        Span<byte> z2 = stackalloc byte[ScalarSize];
        Span<byte> z3 = stackalloc byte[ScalarSize];
        Span<byte> z4 = stackalloc byte[ScalarSize];
        Span<byte> z5 = stackalloc byte[ScalarSize];
        Span<byte> z6 = stackalloc byte[ScalarSize];
        Span<byte> z7 = stackalloc byte[ScalarSize];
        Add(At(a, rBase), At(a, iBase + s), z0, Curve);
        Subtract(At(a, rBase), At(a, iBase + s), z1, Curve);
        Add(At(a, rBase + s), At(a, iBase), z2, Curve);
        Subtract(At(a, rBase + s), At(a, iBase), z3, Curve);
        Add(At(a, iBase + (3 * s)), At(a, rBase + (2 * s)), z4, Curve);
        Subtract(At(a, iBase + (3 * s)), At(a, rBase + (2 * s)), z5, Curve);
        Add(At(a, iBase + (2 * s)), At(a, rBase + (3 * s)), z6, Curve);
        Subtract(At(a, iBase + (2 * s)), At(a, rBase + (3 * s)), z7, Curve);

        Add(z0, z2, At(a, rBase), Curve);
        Add(z5, z7, At(a, iBase), Curve);
        Subtract(z0, z2, At(a, rBase + s), Curve);
        Subtract(z5, z7, At(a, iBase + s), Curve);
        ComplexMultiply(At(a, rBase + s), At(a, iBase + s), Fp256QuadraticExtension.Real(tw2), Fp256QuadraticExtension.Imaginary(tw2));

        Subtract(z1, z6, At(a, rBase + (2 * s)), Curve);
        Add(z4, z3, At(a, iBase + (2 * s)), Curve);
        ComplexMultiply(At(a, rBase + (2 * s)), At(a, iBase + (2 * s)), Fp256QuadraticExtension.Real(tw1), Fp256QuadraticExtension.Imaginary(tw1));

        Add(z1, z6, At(a, rBase + (3 * s)), Curve);
        Subtract(z4, z3, At(a, iBase + (3 * s)), Curve);
        ComplexMultiply(At(a, rBase + (3 * s)), At(a, iBase + (3 * s)), Fp256QuadraticExtension.Real(tw3), Fp256QuadraticExtension.Imaginary(tw3));
    }


    /// <summary>
    /// The complex pointwise multiply <c>x ·= b</c> over a base-field pair <c>(xr, xi)</c>, the
    /// reference's <c>cmul</c> (Karatsuba, three multiplies). Exposed for the convolution's spectral
    /// product step.
    /// </summary>
    public void ComplexMultiply(Span<byte> xr, Span<byte> xi, ReadOnlySpan<byte> br, ReadOnlySpan<byte> bi)
    {
        Span<byte> p0 = stackalloc byte[ScalarSize];
        Span<byte> p1 = stackalloc byte[ScalarSize];
        Span<byte> a01 = stackalloc byte[ScalarSize];
        Span<byte> b01 = stackalloc byte[ScalarSize];
        Multiply(xr, br, p0, Curve);
        Multiply(xi, bi, p1, Curve);
        Add(xr, xi, a01, Curve);
        Add(br, bi, b01, Curve);

        Subtract(p0, p1, xr, Curve);
        Multiply(a01, b01, a01, Curve);
        Subtract(a01, p0, a01, Curve);
        Subtract(a01, p1, xi, Curve);
    }


    /// <summary>The complex pointwise multiply <c>x *= conj(b)</c> over a base-field pair, the reference's <c>cmulj</c>.</summary>
    private void ComplexMultiplyConjugate(Span<byte> xr, Span<byte> xi, ReadOnlySpan<byte> br, ReadOnlySpan<byte> bi)
    {
        Span<byte> p0 = stackalloc byte[ScalarSize];
        Span<byte> p1 = stackalloc byte[ScalarSize];
        Span<byte> a01 = stackalloc byte[ScalarSize];
        Span<byte> b01 = stackalloc byte[ScalarSize];
        Multiply(xr, br, p0, Curve);
        Multiply(xi, bi, p1, Curve);
        Add(xr, xi, a01, Curve);
        Subtract(br, bi, b01, Curve);

        Add(p0, p1, xr, Curve);
        Multiply(a01, b01, a01, Curve);
        Subtract(a01, p0, a01, Curve);
        Add(a01, p1, xi, Curve);
    }


    /// <summary>Builds the order/2 extension powers of the root rerooted to the transform length.</summary>
    /// <param name="length">The positive transform length.</param>
    /// <returns>The owned twiddle table.</returns>
    private TwiddleTable BuildTwiddles(int length)
    {
        Span<byte> omegaN = stackalloc byte[ExtensionSize];
        Reroot((omega ?? throw new ObjectDisposedException(nameof(Fp256RealFft))).Memory.Span[..ExtensionSize], OmegaOrder, (ulong)length, omegaN);

        var table = new TwiddleTable(length / 2, Pool);
        try
        {
            Span<byte> w = stackalloc byte[ExtensionSize];
            //w = the extension one (re = of_scalar(1), im = 0) in the working domain.
            w.Clear();
            OfScalar(1, w[..ScalarSize]);
            for(int i = 0; 2 * i < length; ++i)
            {
                w.CopyTo(table.MutableAt(i));
                Extension.Multiply(w, omegaN, w);
            }

            return table;
        }
        catch
        {
            table.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Squares <paramref name="omegaN"/> repeatedly until its multiplicative order drops from
    /// <paramref name="n"/> to <paramref name="r"/>, writing the result (the reference's
    /// <c>Twiddle::reroot</c>).
    /// </summary>
    private void Reroot(ReadOnlySpan<byte> omegaN, ulong n, ulong r, Span<byte> result)
    {
        //A requested order above the root's own would leave the root unchanged
        //and every twiddle silently wrong; fail as a configuration error instead.
        if(r > n)
        {
            throw new ArgumentOutOfRangeException(nameof(r), $"The requested twiddle order {r} exceeds the root of unity's order {n}.");
        }

        omegaN.CopyTo(result);
        while(r < n)
        {
            Extension.Multiply(result, result, result);
            r += r;
        }
    }


    /// <summary>
    /// Permutes the data span into bit-reversed order in place, the preprocessing step every
    /// decimation-in-time transform requires (the reference's <c>bitrev</c>).
    /// </summary>
    private void BitReverse(Span<byte> data, int length)
    {
        Span<byte> swap = stackalloc byte[ScalarSize];
        int reverseIndex = 0;
        for(int i = 0; i < length - 1; ++i)
        {
            if(i < reverseIndex)
            {
                At(data, i).CopyTo(swap);
                At(data, reverseIndex).CopyTo(At(data, i));
                swap.CopyTo(At(data, reverseIndex));
            }

            BitReverseIncrement(ref reverseIndex, length);
        }
    }


    /// <summary>Advances a bit-reversed counter by one, flipping from the most-significant bit downward.</summary>
    private static void BitReverseIncrement(ref int j, int bit)
    {
        do
        {
            bit >>= 1;
            j ^= bit;
        }
        while((j & bit) == 0);
    }


    /// <summary>Adds <paramref name="addend"/> into <paramref name="destination"/> in place.</summary>
    private void AddInPlace(Span<byte> destination, ReadOnlySpan<byte> addend) => Add(destination, addend, destination, Curve);


    /// <summary>Subtracts <paramref name="b"/> from <paramref name="a"/> into <paramref name="result"/>.</summary>
    private void SubtractInto(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) => Subtract(a, b, result, Curve);


    /// <summary>Negates a base-field element in place by subtracting it from zero.</summary>
    private void NegateInPlace(Span<byte> value)
    {
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        Subtract(zero, value, value, Curve);
    }


    /// <summary>Slices out the base-field element at the given element index within the data span.</summary>
    private static Span<byte> At(Span<byte> data, int index) => data.Slice(index * ScalarSize, ScalarSize);


    /// <summary>Validates that the transform length is a power of two and that the data span is sized exactly for it.</summary>
    private static void ValidateLength(Span<byte> data, int length)
    {
        if(length < 1 || (length & (length - 1)) != 0)
        {
            throw new ArgumentException($"The transform length must be a power of two; received {length}.", nameof(length));
        }

        if(data.Length != length * ScalarSize)
        {
            throw new ArgumentException($"The data span must be {length * ScalarSize} bytes; received {data.Length}.", nameof(data));
        }
    }


    /// <summary>A pool-backed table of order/2 extension twiddle factors, cleared and released on disposal.</summary>
    private sealed class TwiddleTable: IDisposable
    {
        /// <summary>The number of extension-element slots the table holds.</summary>
        private int Count { get; }

        /// <summary>The pool-rented backing memory, or <see langword="null"/> once disposed.</summary>
        private IMemoryOwner<byte>? owner;


        /// <summary>Rents zero-cleared storage for the given number of extension-element slots from the pool.</summary>
        public TwiddleTable(int count, BaseMemoryPool pool)
        {
            this.Count = count;
            owner = pool.Rent(Math.Max(count, 1) * ExtensionSize);
            owner.Memory.Span[..(count * ExtensionSize)].Clear();
        }


        /// <summary>Returns the extension element at the given slot index, read-only.</summary>
        public ReadOnlySpan<byte> At(int index) =>
            (owner ?? throw new ObjectDisposedException(nameof(TwiddleTable))).Memory.Span.Slice(index * ExtensionSize, ExtensionSize);


        /// <summary>Returns the extension element at the given slot index, writable.</summary>
        public Span<byte> MutableAt(int index) =>
            (owner ?? throw new ObjectDisposedException(nameof(TwiddleTable))).Memory.Span.Slice(index * ExtensionSize, ExtensionSize);


        /// <summary>Clears and releases the rented storage.</summary>
        public void Dispose()
        {
            IMemoryOwner<byte>? local = owner;
            if(local is not null)
            {
                owner = null;
                local.Memory.Span[..(Count * ExtensionSize)].Clear();
                local.Dispose();
            }
        }
    }

    /// <summary>Clears and releases the root after all transforms and encoder callbacks have completed.</summary>
    public void Dispose()
    {
        IMemoryOwner<byte>? owner = omega;
        if(owner is not null)
        {
            omega = null;
            owner.Memory.Span[..ExtensionSize].Clear();
            owner.Dispose();
        }
    }
}
