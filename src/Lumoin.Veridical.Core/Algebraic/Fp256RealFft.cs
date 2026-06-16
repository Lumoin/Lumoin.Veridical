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
internal sealed class Fp256RealFft
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int ExtensionSize = Fp256QuadraticExtension.ElementSize;

    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly Action<uint, Span<byte>> ofScalar;
    private readonly Fp256QuadraticExtension extension;
    private readonly CurveParameterSet curve;
    private readonly BaseMemoryPool pool;

    //The root of unity omega (an extension element) and its multiplicative order; the transform reroots
    //it down to the size it needs.
    private readonly byte[] omega;
    private readonly ulong omegaOrder;


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
    /// <param name="pool">Pool the twiddle table and scratch rent from.</param>
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

        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.ofScalar = ofScalar;
        this.curve = curve;
        this.pool = pool;
        extension = new Fp256QuadraticExtension(add, subtract, multiply, invert, curve);
        this.omega = omega.ToArray();
        omegaOrder = omegaOrder == 0 ? throw new ArgumentOutOfRangeException(nameof(omegaOrder)) : omegaOrder;
        this.omegaOrder = omegaOrder;
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


    //--- The forward butterflies (rfft.h r2hcI_2, r2hcI_4, r2hcII_4, hc2hcf_4) ---

    private void R2HcI2(Span<byte> a, int basePos, int s)
    {
        Span<byte> t = stackalloc byte[ScalarSize];
        At(a, basePos + s).CopyTo(t);
        At(a, basePos).CopyTo(At(a, basePos + s));
        AddInPlace(At(a, basePos), t);
        SubtractInto(At(a, basePos + s), t, At(a, basePos + s));
    }


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

        add(x0, x1, z0, curve);
        add(x2, x3, z1, curve);
        add(z0, z1, At(a, basePos), curve);
        subtract(z0, z1, At(a, basePos + (2 * s)), curve);
        subtract(x0, x1, At(a, basePos + s), curve);
        subtract(x3, x2, At(a, basePos + (3 * s)), curve);
    }


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
        add(x2, x3, z0, curve);
        subtract(x2, x3, z1, curve);
        multiply(z0, w8Im, z0, curve);
        multiply(z1, w8Re, z1, curve);

        Span<byte> x0 = stackalloc byte[ScalarSize];
        Span<byte> x1 = stackalloc byte[ScalarSize];
        At(a, basePos).CopyTo(x0);
        At(a, basePos + s).CopyTo(x1);
        add(x0, z1, At(a, basePos), curve);
        subtract(x0, z1, At(a, basePos + s), curve);
        subtract(x1, z0, At(a, basePos + (2 * s)), curve);
        add(x1, z0, At(a, basePos + (3 * s)), curve);
        NegateInPlace(At(a, basePos + (3 * s)));
    }


    private void Hc2HcF4(Span<byte> a, int rBase, int iBase, int s, ReadOnlySpan<byte> tw1, ReadOnlySpan<byte> tw2, ReadOnlySpan<byte> tw3)
    {
        ComplexMultiplyConjugate(At(a, rBase + s), At(a, iBase + s), Fp256QuadraticExtension.Real(tw2), Fp256QuadraticExtension.Imaginary(tw2));

        Span<byte> y0r = stackalloc byte[ScalarSize];
        Span<byte> y0i = stackalloc byte[ScalarSize];
        Span<byte> y1r = stackalloc byte[ScalarSize];
        Span<byte> y1i = stackalloc byte[ScalarSize];
        add(At(a, rBase), At(a, rBase + s), y0r, curve);
        add(At(a, iBase), At(a, iBase + s), y0i, curve);
        subtract(At(a, rBase), At(a, rBase + s), y1r, curve);
        subtract(At(a, iBase), At(a, iBase + s), y1i, curve);

        ComplexMultiplyConjugate(At(a, rBase + (2 * s)), At(a, iBase + (2 * s)), Fp256QuadraticExtension.Real(tw1), Fp256QuadraticExtension.Imaginary(tw1));
        ComplexMultiplyConjugate(At(a, rBase + (3 * s)), At(a, iBase + (3 * s)), Fp256QuadraticExtension.Real(tw3), Fp256QuadraticExtension.Imaginary(tw3));

        Span<byte> y2r = stackalloc byte[ScalarSize];
        Span<byte> y3r = stackalloc byte[ScalarSize];
        Span<byte> y2i = stackalloc byte[ScalarSize];
        Span<byte> y3i = stackalloc byte[ScalarSize];
        add(At(a, rBase + (3 * s)), At(a, rBase + (2 * s)), y2r, curve);
        subtract(At(a, rBase + (3 * s)), At(a, rBase + (2 * s)), y3r, curve);
        add(At(a, iBase + (2 * s)), At(a, iBase + (3 * s)), y2i, curve);
        subtract(At(a, iBase + (2 * s)), At(a, iBase + (3 * s)), y3i, curve);

        add(y0r, y2r, At(a, rBase), curve);
        subtract(y0r, y2r, At(a, iBase + s), curve);
        add(y1r, y3i, At(a, rBase + s), curve);
        subtract(y1r, y3i, At(a, iBase), curve);
        add(y2i, y0i, At(a, iBase + (3 * s)), curve);
        subtract(y2i, y0i, At(a, rBase + (2 * s)), curve);
        add(y3r, y1i, At(a, iBase + (2 * s)), curve);
        subtract(y3r, y1i, At(a, rBase + (3 * s)), curve);
    }


    //--- The backward butterflies (rfft.h hc2rI_2, hc2rI_4, hc2rIII_4, hc2hcb_4) ---

    private void Hc2RI2(Span<byte> a, int basePos, int s)
    {
        Span<byte> t = stackalloc byte[ScalarSize];
        At(a, basePos + s).CopyTo(t);
        At(a, basePos).CopyTo(At(a, basePos + s));
        AddInPlace(At(a, basePos), t);
        SubtractInto(At(a, basePos + s), t, At(a, basePos + s));
    }


    private void Hc2RI4(Span<byte> a, int basePos, int s)
    {
        Span<byte> y0 = stackalloc byte[ScalarSize];
        Span<byte> y1 = stackalloc byte[ScalarSize];
        Span<byte> y2 = stackalloc byte[ScalarSize];
        Span<byte> y3 = stackalloc byte[ScalarSize];
        add(At(a, basePos), At(a, basePos + (2 * s)), y0, curve);
        subtract(At(a, basePos), At(a, basePos + (2 * s)), y1, curve);
        add(At(a, basePos + s), At(a, basePos + s), y2, curve);
        add(At(a, basePos + (3 * s)), At(a, basePos + (3 * s)), y3, curve);

        add(y0, y2, At(a, basePos), curve);
        subtract(y0, y2, At(a, basePos + s), curve);
        subtract(y1, y3, At(a, basePos + (2 * s)), curve);
        add(y1, y3, At(a, basePos + (3 * s)), curve);
    }


    private void Hc2RIII4(Span<byte> a, int basePos, int s, ReadOnlySpan<byte> w8)
    {
        ReadOnlySpan<byte> w8Re = Fp256QuadraticExtension.Real(w8);
        ReadOnlySpan<byte> w8Im = Fp256QuadraticExtension.Imaginary(w8);

        Span<byte> x0 = stackalloc byte[ScalarSize];
        Span<byte> x1 = stackalloc byte[ScalarSize];
        Span<byte> x2 = stackalloc byte[ScalarSize];
        Span<byte> x3 = stackalloc byte[ScalarSize];
        add(At(a, basePos), At(a, basePos), x0, curve);
        add(At(a, basePos + s), At(a, basePos + s), x1, curve);
        add(At(a, basePos + (2 * s)), At(a, basePos + (2 * s)), x2, curve);
        add(At(a, basePos + (3 * s)), At(a, basePos + (3 * s)), x3, curve);

        add(x0, x1, At(a, basePos), curve);
        subtract(x2, x3, At(a, basePos + s), curve);

        Span<byte> z0 = stackalloc byte[ScalarSize];
        Span<byte> z1 = stackalloc byte[ScalarSize];
        subtract(x0, x1, z0, curve);
        multiply(z0, w8Re, z0, curve);
        add(x3, x2, z1, curve);
        multiply(z1, w8Im, z1, curve);
        subtract(z0, z1, At(a, basePos + (2 * s)), curve);
        add(z0, z1, At(a, basePos + (3 * s)), curve);
        NegateInPlace(At(a, basePos + (3 * s)));
    }


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
        add(At(a, rBase), At(a, iBase + s), z0, curve);
        subtract(At(a, rBase), At(a, iBase + s), z1, curve);
        add(At(a, rBase + s), At(a, iBase), z2, curve);
        subtract(At(a, rBase + s), At(a, iBase), z3, curve);
        add(At(a, iBase + (3 * s)), At(a, rBase + (2 * s)), z4, curve);
        subtract(At(a, iBase + (3 * s)), At(a, rBase + (2 * s)), z5, curve);
        add(At(a, iBase + (2 * s)), At(a, rBase + (3 * s)), z6, curve);
        subtract(At(a, iBase + (2 * s)), At(a, rBase + (3 * s)), z7, curve);

        add(z0, z2, At(a, rBase), curve);
        add(z5, z7, At(a, iBase), curve);
        subtract(z0, z2, At(a, rBase + s), curve);
        subtract(z5, z7, At(a, iBase + s), curve);
        ComplexMultiply(At(a, rBase + s), At(a, iBase + s), Fp256QuadraticExtension.Real(tw2), Fp256QuadraticExtension.Imaginary(tw2));

        subtract(z1, z6, At(a, rBase + (2 * s)), curve);
        add(z4, z3, At(a, iBase + (2 * s)), curve);
        ComplexMultiply(At(a, rBase + (2 * s)), At(a, iBase + (2 * s)), Fp256QuadraticExtension.Real(tw1), Fp256QuadraticExtension.Imaginary(tw1));

        add(z1, z6, At(a, rBase + (3 * s)), curve);
        subtract(z4, z3, At(a, iBase + (3 * s)), curve);
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
        multiply(xr, br, p0, curve);
        multiply(xi, bi, p1, curve);
        add(xr, xi, a01, curve);
        add(br, bi, b01, curve);

        subtract(p0, p1, xr, curve);
        multiply(a01, b01, a01, curve);
        subtract(a01, p0, a01, curve);
        subtract(a01, p1, xi, curve);
    }


    //The complex pointwise multiply x *= conj(b), the reference's cmulj.
    private void ComplexMultiplyConjugate(Span<byte> xr, Span<byte> xi, ReadOnlySpan<byte> br, ReadOnlySpan<byte> bi)
    {
        Span<byte> p0 = stackalloc byte[ScalarSize];
        Span<byte> p1 = stackalloc byte[ScalarSize];
        Span<byte> a01 = stackalloc byte[ScalarSize];
        Span<byte> b01 = stackalloc byte[ScalarSize];
        multiply(xr, br, p0, curve);
        multiply(xi, bi, p1, curve);
        add(xr, xi, a01, curve);
        subtract(br, bi, b01, curve);

        add(p0, p1, xr, curve);
        multiply(a01, b01, a01, curve);
        subtract(a01, p0, a01, curve);
        add(a01, p1, xi, curve);
    }


    //--- The twiddle precompute and reroot (twiddle.h Twiddle / reroot) ---

    //Builds the order/2 powers of the (length)-th root of unity, each an extension element. The root is
    //the engine's omega rerooted from omegaOrder down to length.
    private TwiddleTable BuildTwiddles(int length)
    {
        Span<byte> omegaN = stackalloc byte[ExtensionSize];
        Reroot(omega, omegaOrder, (ulong)length, omegaN);

        var table = new TwiddleTable(length / 2, pool);
        try
        {
            Span<byte> w = stackalloc byte[ExtensionSize];
            //w = the extension one (re = of_scalar(1), im = 0) in the working domain.
            w.Clear();
            ofScalar(1, w[..ScalarSize]);
            for(int i = 0; 2 * i < length; ++i)
            {
                w.CopyTo(table.MutableAt(i));
                extension.Multiply(w, omegaN, w);
            }

            return table;
        }
        catch
        {
            table.Dispose();
            throw;
        }
    }


    //reroot(omega_n, n, r): square omega_n until its order drops to r (the reference's Twiddle::reroot).
    private void Reroot(ReadOnlySpan<byte> omegaN, ulong n, ulong r, Span<byte> result)
    {
        omegaN.CopyTo(result);
        while(r < n)
        {
            extension.Multiply(result, result, result);
            r += r;
        }
    }


    //--- bit reversal (permutations.h bitrev) ---

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


    private static void BitReverseIncrement(ref int j, int bit)
    {
        do
        {
            bit >>= 1;
            j ^= bit;
        }
        while((j & bit) == 0);
    }


    private void AddInPlace(Span<byte> destination, ReadOnlySpan<byte> addend) => add(destination, addend, destination, curve);


    private void SubtractInto(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result) => subtract(a, b, result, curve);


    private void NegateInPlace(Span<byte> value)
    {
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        subtract(zero, value, value, curve);
    }


    private static Span<byte> At(Span<byte> data, int index) => data.Slice(index * ScalarSize, ScalarSize);


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


    //A pool-backed table of order/2 extension twiddle factors, cleared and released on disposal.
    private sealed class TwiddleTable: IDisposable
    {
        private readonly int count;
        private IMemoryOwner<byte>? owner;


        public TwiddleTable(int count, BaseMemoryPool pool)
        {
            this.count = count;
            owner = pool.Rent(Math.Max(count, 1) * ExtensionSize);
            owner.Memory.Span[..(count * ExtensionSize)].Clear();
        }


        public ReadOnlySpan<byte> At(int index) =>
            (owner ?? throw new ObjectDisposedException(nameof(TwiddleTable))).Memory.Span.Slice(index * ExtensionSize, ExtensionSize);


        public Span<byte> MutableAt(int index) =>
            (owner ?? throw new ObjectDisposedException(nameof(TwiddleTable))).Memory.Span.Slice(index * ExtensionSize, ExtensionSize);


        public void Dispose()
        {
            IMemoryOwner<byte>? local = owner;
            if(local is not null)
            {
                owner = null;
                local.Memory.Span[..(count * ExtensionSize)].Clear();
                local.Dispose();
            }
        }
    }
}
