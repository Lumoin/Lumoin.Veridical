using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The FFT-based convolution over the P-256 base field, a faithful port of google/longfellow-zk's
/// <c>lib/algebra/convolution.h</c> <c>FFTExtConvolution&lt;Fp256Base, Fp2&lt;Fp256Base&gt;&gt;</c>. Given a
/// fixed second operand <c>y</c> (length <c>m</c>), it computes the first <c>m</c> entries of the linear
/// convolution <c>z[k] = Σ_i x[i]·y[k−i]</c> for a query operand <c>x</c> (length <c>n</c>), using the
/// real FFT (<see cref="Fp256RealFft"/>) in <c>O(n log n)</c>. This is the convolution the reference's
/// Fp256 Reed–Solomon interpolator runs (<see cref="Fp256ReedSolomon"/>), so reproducing it
/// element-for-element is what makes the P-256 signature-circuit Ligero codewords match the reference's.
/// </summary>
/// <remarks>
/// <para>
/// Construction pads <c>y</c> with zeros to the next power of two at least <c>m</c>, forward-transforms
/// it to half-complex storage, and pre-scales by <c>1/padding</c> to cancel the <c>HC2R(R2HC(·))</c>
/// scaling. Each <see cref="Convolve"/> pads <c>x</c> likewise, forward-transforms it, multiplies the two
/// spectra pointwise in half-complex form (the DC and Nyquist bins are real; the interior bins are the
/// complex products of the conjugate-symmetric pairs <c>(i, padding−i)</c>), backward-transforms, and
/// copies out the first <c>m</c> entries.
/// </para>
/// <para>
/// The transform and the field arithmetic are delegate-injected through the <see cref="Fp256RealFft"/>
/// the caller supplies; the working spectra are pool-rented and cleared on return. The pre-scaled spectrum
/// of <c>y</c> is retained for the lifetime of the convolver and released on disposal.
/// </para>
/// </remarks>
internal sealed class Fp256FftConvolution: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly Fp256RealFft fft;
    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly Action<uint, Span<byte>> ofScalar;
    private readonly CurveParameterSet curve;
    private readonly BaseMemoryPool pool;
    private readonly int inputLength;
    private readonly int outputLength;
    private readonly int padding;

    //The pre-scaled forward transform of the padded y operand, retained across Convolve calls.
    private IMemoryOwner<byte>? yTransform;


    /// <summary>
    /// Builds a convolver for the fixed operand <paramref name="y"/>.
    /// </summary>
    /// <param name="inputLength">The query-operand length <c>n</c> (≥ 1).</param>
    /// <param name="outputLength">The output length <c>m</c> (≥ <paramref name="inputLength"/>); also <c>y</c>'s length.</param>
    /// <param name="y">The fixed operand, <paramref name="outputLength"/> base-field elements (<c>m · 32</c> bytes).</param>
    /// <param name="fft">The real-FFT engine over the same field and root of unity.</param>
    /// <param name="add">Base-field addition.</param>
    /// <param name="subtract">Base-field subtraction.</param>
    /// <param name="multiply">Base-field multiplication.</param>
    /// <param name="invert">Base-field inversion (the <c>1/padding</c> pre-scale).</param>
    /// <param name="ofScalar">The base-field <c>of_scalar(u)</c> in the working domain; the <c>1/padding</c> pre-scale starts from <c>ofScalar(padding)</c>.</param>
    /// <param name="curve">The curve the delegates route over.</param>
    /// <param name="pool">Pool the spectra rent from.</param>
    /// <exception cref="ArgumentNullException">When a delegate, the FFT or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a length is out of range or <paramref name="y"/> is the wrong size.</exception>
    public Fp256FftConvolution(
        int inputLength,
        int outputLength,
        ReadOnlySpan<byte> y,
        Fp256RealFft fft,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        Action<uint, Span<byte>> ofScalar,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(inputLength, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(outputLength, inputLength);

        if(y.Length != outputLength * ScalarSize)
        {
            throw new ArgumentException($"The y operand must be {outputLength * ScalarSize} bytes; received {y.Length}.", nameof(y));
        }

        this.fft = fft;
        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.ofScalar = ofScalar;
        this.curve = curve;
        this.pool = pool;
        this.inputLength = inputLength;
        this.outputLength = outputLength;
        padding = ChoosePadding(outputLength);

        IMemoryOwner<byte> transform = pool.Rent(padding * ScalarSize);
        try
        {
            Span<byte> span = transform.Memory.Span[..(padding * ScalarSize)];
            span.Clear();
            y.CopyTo(span[..(outputLength * ScalarSize)]);
            fft.ForwardRealToHalfComplex(span, padding);

            //Pre-scale by 1/padding (a working-domain base-field scalar) to cancel the HC2R(R2HC(·)) scaling.
            Span<byte> inversePadding = stackalloc byte[ScalarSize];
            ofScalar((uint)padding, inversePadding);
            invert(inversePadding, inversePadding, curve);
            for(int i = 0; i < padding; i++)
            {
                multiply(span.Slice(i * ScalarSize, ScalarSize), inversePadding, span.Slice(i * ScalarSize, ScalarSize), curve);
            }

            yTransform = transform;
        }
        catch
        {
            transform.Memory.Span[..(padding * ScalarSize)].Clear();
            transform.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Computes the first <c>m</c> entries of <c>x ∗ y</c> into <paramref name="result"/>, the reference's
    /// <c>convolution</c>.
    /// </summary>
    /// <param name="x">The query operand, <c>n</c> base-field elements (<c>n · 32</c> bytes).</param>
    /// <param name="result">Receives <c>m</c> base-field elements (<c>m · 32</c> bytes).</param>
    /// <exception cref="ArgumentException">When a span length does not match the configured dimensions.</exception>
    public void Convolve(ReadOnlySpan<byte> x, Span<byte> result)
    {
        IMemoryOwner<byte> yOwner = yTransform ?? throw new ObjectDisposedException(nameof(Fp256FftConvolution));

        if(x.Length != inputLength * ScalarSize)
        {
            throw new ArgumentException($"The x operand must be {inputLength * ScalarSize} bytes; received {x.Length}.", nameof(x));
        }

        if(result.Length != outputLength * ScalarSize)
        {
            throw new ArgumentException($"The result must be {outputLength * ScalarSize} bytes; received {result.Length}.", nameof(result));
        }

        ReadOnlySpan<byte> yFft = yOwner.Memory.Span[..(padding * ScalarSize)];

        using IMemoryOwner<byte> xOwner = pool.Rent(padding * ScalarSize);
        Span<byte> xFft = xOwner.Memory.Span[..(padding * ScalarSize)];
        try
        {
            xFft.Clear();
            x.CopyTo(xFft[..(inputLength * ScalarSize)]);
            fft.ForwardRealToHalfComplex(xFft, padding);

            //Pointwise multiplication in half-complex storage: the DC bin (0) and the Nyquist bin
            //(padding/2) are real; the interior bins pair (i, padding-i) as (real, imag).
            multiply(At(xFft, 0), At(yFft, 0), At(xFft, 0), curve);
            int i;
            for(i = 1; i + i < padding; ++i)
            {
                fft.ComplexMultiply(At(xFft, i), At(xFft, padding - i), At(yFft, i), At(yFft, padding - i));
            }

            multiply(At(xFft, i), At(yFft, i), At(xFft, i), curve);

            fft.BackwardHalfComplexToReal(xFft, padding);
            xFft[..(outputLength * ScalarSize)].CopyTo(result);
        }
        finally
        {
            xFft.Clear();
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = yTransform;
        if(local is not null)
        {
            yTransform = null;
            local.Memory.Span[..(padding * ScalarSize)].Clear();
            local.Dispose();
        }
    }


    //The smallest power of two at least n (choose_padding).
    internal static int ChoosePadding(int n)
    {
        int p = 1;
        while(p < n)
        {
            p *= 2;
        }

        return p;
    }


    private static Span<byte> At(Span<byte> data, int index) => data.Slice(index * ScalarSize, ScalarSize);

    private static ReadOnlySpan<byte> At(ReadOnlySpan<byte> data, int index) => data.Slice(index * ScalarSize, ScalarSize);
}
