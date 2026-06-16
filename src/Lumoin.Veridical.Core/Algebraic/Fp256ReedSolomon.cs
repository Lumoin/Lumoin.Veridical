using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The point-evaluation Reed–Solomon interpolator over the P-256 base field, a faithful port of
/// google/longfellow-zk's <c>lib/algebra/reed_solomon.h</c>
/// <c>ReedSolomon&lt;Fp256Base, FFTExtConvolutionFactory&gt;</c> — the encoder
/// <c>lib/circuits/mdoc/mdoc_zk.cc</c> instantiates for the P-256 signature circuit's Ligero (the
/// <c>RSFactory_b</c> over the <c>FFTExtConvolution</c>). Given the values of a polynomial of degree
/// below <c>n</c> at the points <c>0, 1, …, n−1</c>, it extends them to the values at <c>n, n+1, …,
/// m−1</c> in place (the first <c>n</c> entries are unchanged). It is the prime-field analogue of the
/// binary <see cref="Lch14ReedSolomon"/>, and it is the encoder the Fp256 Ligero verifier's
/// low-degree / dot / quadratic checks run, so reproducing it bit-for-bit is part of the P-256 wire
/// format.
/// </summary>
/// <remarks>
/// <para>
/// The interpolation identity (Lagrange recast for equally spaced points) is
/// <c>p(k) = (−1)^d (k−d) C(k,d) Σ_{j≤d} (1/(k−j)) (−1)^j C(d,j) p(j)</c> with <c>d = n−1</c>, which the
/// reference evaluates as a convolution: the inner sum over <c>j</c> against the kernel <c>1/(k−j)</c> is
/// the convolution of <c>x[j] = (−1)^j C(d,j) p(j)</c> with the arithmetic inverses <c>1/i</c>, scaled by
/// the leading constant <c>(−1)^d (k−d) C(k,d)</c>. The arithmetic inverses, the binomial weights
/// <c>binom_i_</c> and the leading constants are precomputed once at construction (Montgomery batch
/// inversion through <see cref="BatchInverseArithmetic"/>); the convolution is the FFT convolution
/// (<see cref="Fp256FftConvolution"/>) whose fixed operand is the inverses array.
/// </para>
/// <para>
/// In-place over a caller span of <c>m · 32</c> base-field bytes (the first <c>n</c> hold the inputs).
/// The precomputed tables and the convolution scratch are pool-rented; the convolver is retained for the
/// lifetime of the interpolator and released on disposal. The base-field arithmetic is delegate-injected
/// so the port stays consistent with the library's primitive-agnostic algebraic infrastructure.
/// </para>
/// </remarks>
[System.Diagnostics.DebuggerDisplay("Fp256 RS (N={dimension}, M={blockLength})")]
internal sealed class Fp256ReedSolomon: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly ScalarBatchMultiplyDelegate? batchMultiply;
    private readonly Action<uint, Span<byte>> ofScalar;
    private readonly CurveParameterSet curve;
    private readonly BaseMemoryPool pool;

    private readonly int dimension;
    private readonly int degreeBound;
    private readonly int blockLength;

    //leading_constant_[i] for i in [0, m - degree_bound); binom_i_[i] for i in [0, n).
    private IMemoryOwner<byte>? leadingConstants;
    private IMemoryOwner<byte>? binomial;
    private Fp256FftConvolution? convolution;


    /// <summary>
    /// Builds the interpolator for the given dimensions over the supplied root of unity and field
    /// arithmetic.
    /// </summary>
    /// <param name="dimension">The number of input points <c>n</c> (≥ 1).</param>
    /// <param name="blockLength">The number of output points <c>m</c> (≥ <paramref name="dimension"/>).</param>
    /// <param name="fft">The real-FFT engine over the same field and root of unity (drives the convolution).</param>
    /// <param name="add">Base-field addition.</param>
    /// <param name="subtract">Base-field subtraction.</param>
    /// <param name="multiply">Base-field multiplication.</param>
    /// <param name="invert">Base-field inversion.</param>
    /// <param name="ofScalar">The base-field <c>of_scalar(u)</c> in the working domain; the leading-constant, binomial and batch-inverse seeds are <c>ofScalar(1)</c> and the small integers <c>ofScalar(k)</c>.</param>
    /// <param name="curve">The curve the delegates route over.</param>
    /// <param name="pool">Pool the tables and scratch rent from.</param>
    /// <param name="batchMultiply">The optional batched element-wise multiply the two <see cref="Interpolate"/> scalar-times-vector loops route through; the Montgomery-domain Fp256 path supplies it, the canonical/reference path leaves it <see langword="null"/> for the scalar fallback. It must implement the SAME field op as <paramref name="multiply"/> (the per-element product is byte-identical), so the working domain (Montgomery residue / canonical) matches.</param>
    /// <exception cref="ArgumentNullException">When a delegate, the FFT or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a dimension is out of range.</exception>
    public Fp256ReedSolomon(
        int dimension,
        int blockLength,
        Fp256RealFft fft,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        Action<uint, Span<byte>> ofScalar,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarBatchMultiplyDelegate? batchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(dimension, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(blockLength, dimension);

        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.batchMultiply = batchMultiply;
        this.ofScalar = ofScalar;
        this.curve = curve;
        this.pool = pool;
        this.dimension = dimension;
        degreeBound = dimension - 1;
        this.blockLength = blockLength;

        int leadingCount = blockLength - degreeBound;
        IMemoryOwner<byte> leadingOwner = pool.Rent(Math.Max(leadingCount, 1) * ScalarSize);
        IMemoryOwner<byte>? binomialOwner = null;
        Fp256FftConvolution? convolver = null;
        try
        {
            //inverses[i] = 1/i (inverses[0] = 0), i in [0, m).
            using IMemoryOwner<byte> inversesOwner = pool.Rent(blockLength * ScalarSize);
            Span<byte> inverses = inversesOwner.Memory.Span[..(blockLength * ScalarSize)];
            BatchInverseArithmetic(blockLength, inverses, add, subtract, multiply, invert, ofScalar, curve);

            //The convolution's fixed operand is the inverses array (factory.make(n, m, inverses)).
            convolver = new Fp256FftConvolution(dimension, blockLength, inverses, fft, add, subtract, multiply, invert, ofScalar, curve, pool);

            //Leading constants. leading_constant_[0] = 1; for i in [1, m - degree_bound):
            //leading_constant_[i] = leading_constant_[i-1] · (degree_bound + i) · inverses[i].
            Span<byte> leading = leadingOwner.Memory.Span[..(leadingCount * ScalarSize)];
            leading.Clear();
            ofScalar(1, LeadingAt(leading, 0));
            Span<byte> scalarValue = stackalloc byte[ScalarSize];
            for(int i = 1; i + degreeBound < blockLength; ++i)
            {
                ofScalar((uint)(degreeBound + i), scalarValue);
                multiply(LeadingAt(leading, i - 1), scalarValue, LeadingAt(leading, i), curve);
                multiply(LeadingAt(leading, i), InverseAt(inverses, i), LeadingAt(leading, i), curve);
            }

            //Finish: leading_constant_[k - degree_bound] *= (k - degree_bound); negate when degree_bound
            //is odd. k runs degree_bound .. m-1, so index runs 0 .. m-1-degree_bound.
            for(int k = degreeBound; k < blockLength; ++k)
            {
                int index = k - degreeBound;
                ofScalar((uint)(k - degreeBound), scalarValue);
                multiply(LeadingAt(leading, index), scalarValue, LeadingAt(leading, index), curve);
                if((degreeBound & 1) == 1)
                {
                    NegateInPlace(LeadingAt(leading, index));
                }
            }

            //Binomial weights. binom_i_[0] = 1; for i in [1, n):
            //binom_i_[i] = binom_i_[i-1] · (n - i) · inverses[i]; then negate odd indices.
            binomialOwner = pool.Rent(dimension * ScalarSize);
            Span<byte> binom = binomialOwner.Memory.Span[..(dimension * ScalarSize)];
            binom.Clear();
            ofScalar(1, BinomialAt(binom, 0));
            for(int i = 1; i < dimension; ++i)
            {
                ofScalar((uint)(dimension - i), scalarValue);
                multiply(BinomialAt(binom, i - 1), scalarValue, BinomialAt(binom, i), curve);
                multiply(BinomialAt(binom, i), InverseAt(inverses, i), BinomialAt(binom, i), curve);
            }

            for(int i = 1; i < dimension; i += 2)
            {
                NegateInPlace(BinomialAt(binom, i));
            }

            inverses.Clear();
            leadingConstants = leadingOwner;
            binomial = binomialOwner;
            convolution = convolver;
        }
        catch
        {
            convolver?.Dispose();
            if(binomialOwner is not null)
            {
                binomialOwner.Memory.Span[..(dimension * ScalarSize)].Clear();
                binomialOwner.Dispose();
            }

            leadingOwner.Memory.Span[..(Math.Max(leadingCount, 1) * ScalarSize)].Clear();
            leadingOwner.Dispose();
            throw;
        }
    }


    /// <summary>The RS dimension (input evaluation count <c>n</c>).</summary>
    public int Dimension => dimension;

    /// <summary>The RS block length (output evaluation count <c>m</c>).</summary>
    public int BlockLength => blockLength;


    /// <summary>
    /// Extends the <c>n</c> input evaluations in the prefix of <paramref name="evaluations"/> to all
    /// <c>m</c> evaluations, in place — the reference's <c>interpolate</c>. On entry <c>y[0..n)</c> holds
    /// the values at <c>0, …, n−1</c>; on return <c>y[0..m)</c> holds the values at <c>0, …, m−1</c>, the
    /// first <c>n</c> unchanged.
    /// </summary>
    /// <param name="evaluations"><c>m</c> base-field scalars (<c>m · 32</c> bytes); the first <c>n</c> are the inputs.</param>
    /// <exception cref="ArgumentException">When the span is the wrong length.</exception>
    public void Interpolate(Span<byte> evaluations)
    {
        Fp256FftConvolution convolver = convolution ?? throw new ObjectDisposedException(nameof(Fp256ReedSolomon));
        ReadOnlySpan<byte> binom = (binomial ?? throw new ObjectDisposedException(nameof(Fp256ReedSolomon))).Memory.Span[..(dimension * ScalarSize)];
        ReadOnlySpan<byte> leading = (leadingConstants ?? throw new ObjectDisposedException(nameof(Fp256ReedSolomon))).Memory.Span[..((blockLength - degreeBound) * ScalarSize)];

        if(evaluations.Length != blockLength * ScalarSize)
        {
            throw new ArgumentException($"The evaluation buffer must be {blockLength * ScalarSize} bytes; received {evaluations.Length}.", nameof(evaluations));
        }

        //x[i] = binom_i_[i] · y[i], i in [0, n).
        using IMemoryOwner<byte> xOwner = pool.Rent(dimension * ScalarSize);
        using IMemoryOwner<byte> convolvedOwner = pool.Rent(blockLength * ScalarSize);
        Span<byte> x = xOwner.Memory.Span[..(dimension * ScalarSize)];
        Span<byte> convolved = convolvedOwner.Memory.Span[..(blockLength * ScalarSize)];
        try
        {
            //x[i] = binom_i_[i]·y[i] is a contiguous element-wise product; the Montgomery Fp256 path routes it
            //through the lane-parallel batch multiply (byte-identical per element to the scalar multiply), the
            //canonical/reference path falls back to the scalar loop.
            if(batchMultiply is not null)
            {
                batchMultiply(binom, evaluations[..(dimension * ScalarSize)], x, dimension, curve);
            }
            else
            {
                for(int i = 0; i < dimension; i++)
                {
                    multiply(BinomialAt(binom, i), evaluations.Slice(i * ScalarSize, ScalarSize), x.Slice(i * ScalarSize, ScalarSize), curve);
                }
            }

            convolver.Convolve(x, convolved);

            //y[i] = leading_constant_[i - degree_bound]·T[i], i in [n, m): the same contiguous element-wise
            //product over the tail block (leading-constant, convolved and output slices are all contiguous).
            int tail = blockLength - dimension;
            if(batchMultiply is not null)
            {
                batchMultiply(
                    leading.Slice((dimension - degreeBound) * ScalarSize, tail * ScalarSize),
                    convolved.Slice(dimension * ScalarSize, tail * ScalarSize),
                    evaluations.Slice(dimension * ScalarSize, tail * ScalarSize),
                    tail,
                    curve);
            }
            else
            {
                for(int i = dimension; i < blockLength; i++)
                {
                    multiply(LeadingAt(leading, i - degreeBound), convolved.Slice(i * ScalarSize, ScalarSize), evaluations.Slice(i * ScalarSize, ScalarSize), curve);
                }
            }
        }
        finally
        {
            x.Clear();
            convolved.Clear();
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        Fp256FftConvolution? localConvolution = convolution;
        if(localConvolution is not null)
        {
            convolution = null;
            localConvolution.Dispose();
        }

        IMemoryOwner<byte>? localBinomial = binomial;
        if(localBinomial is not null)
        {
            binomial = null;
            localBinomial.Memory.Span[..(dimension * ScalarSize)].Clear();
            localBinomial.Dispose();
        }

        IMemoryOwner<byte>? localLeading = leadingConstants;
        if(localLeading is not null)
        {
            leadingConstants = null;
            localLeading.Memory.Span[..((blockLength - degreeBound) * ScalarSize)].Clear();
            localLeading.Dispose();
        }
    }


    //a[i] = 1/i, with a[0] = 0 (utility.h batch_inverse_arithmetic). Builds the prefix products of
    //1, 2, …, then a single inversion, then unwinds.
    internal static void BatchInverseArithmetic(
        int count,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        Action<uint, Span<byte>> ofScalar,
        CurveParameterSet curve)
    {
        destination[..ScalarSize].Clear();

        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> bi = stackalloc byte[ScalarSize];
        Span<byte> one = stackalloc byte[ScalarSize];
        ofScalar(1, product);
        bi.Clear();
        ofScalar(1, one);

        for(int i = 1; i < count; i++)
        {
            add(bi, one, bi, curve);
            product.CopyTo(destination.Slice(i * ScalarSize, ScalarSize));
            multiply(product, bi, product, curve);
        }

        invert(product, product, curve);

        for(int i = count; i-- > 0;)
        {
            multiply(destination.Slice(i * ScalarSize, ScalarSize), product, destination.Slice(i * ScalarSize, ScalarSize), curve);
            multiply(product, bi, product, curve);
            subtract(bi, one, bi, curve);
        }
    }


    private void NegateInPlace(Span<byte> value)
    {
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        subtract(zero, value, value, curve);
    }


    private static Span<byte> LeadingAt(Span<byte> table, int index) => table.Slice(index * ScalarSize, ScalarSize);

    private static ReadOnlySpan<byte> LeadingAt(ReadOnlySpan<byte> table, int index) => table.Slice(index * ScalarSize, ScalarSize);

    private static Span<byte> BinomialAt(Span<byte> table, int index) => table.Slice(index * ScalarSize, ScalarSize);

    private static ReadOnlySpan<byte> BinomialAt(ReadOnlySpan<byte> table, int index) => table.Slice(index * ScalarSize, ScalarSize);

    private static ReadOnlySpan<byte> InverseAt(ReadOnlySpan<byte> inverses, int index) => inverses.Slice(index * ScalarSize, ScalarSize);
}
