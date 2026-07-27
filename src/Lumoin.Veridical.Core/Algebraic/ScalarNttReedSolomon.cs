using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The NTT-convolution Reed–Solomon interpolator over the wired scalar fields:
/// extends the evaluations of a degree-<c>&lt; dimension</c> polynomial at the
/// consecutive-integer nodes <c>{0, …, dimension − 1}</c> to all of
/// <c>{0, …, blockLength − 1}</c>, in place and systematically, in
/// <c>O(L log L)</c> field multiplications per row for
/// <c>L = NextPow2(blockLength)</c>.
/// </summary>
/// <remarks>
/// <para>
/// The map is the second barycentric form with the per-point denominator folded
/// into a precomputed leading-constant table: each extension value is
/// <c>leading[k − degreeBound] · S(k)</c> where
/// <c>S(k) = Σ_i (binomial[i] · y[i]) · 1/(k − i)</c> is one linear convolution
/// of the weighted message with the reciprocal kernel
/// <c>(0, 1, 1/2, …, 1/(blockLength − 1))</c>. The convolution runs cyclically
/// at length <c>L</c>: wrapped products can only land at positions below
/// <c>dimension − 1</c>, which lie in the systematic prefix that is copied and
/// never computed, so every computed extension value is alias-free. The weight
/// recurrences are the same ones the <see cref="Fp256ReedSolomon"/> engine
/// builds its tables with, and the whole map equals the barycentric reference
/// path value-for-value — field arithmetic is exact, so the codeword bytes are
/// identical.
/// </para>
/// <para>
/// Construction precomputes the per-shape state once — forward and inverse
/// twiddle tables, the kernel spectrum pre-scaled by <c>1/L</c> (cancelling the
/// unnormalized inverse transform), the binomial weights and the leading
/// constants — so <see cref="Interpolate"/> performs no inversions at all. The
/// tables are pool-rented, cleared and released on disposal; per-call scratch is
/// pool-rented and cleared before return.
/// </para>
/// </remarks>
internal sealed class ScalarNttReedSolomon: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly ScalarAddDelegate add;
    private readonly ScalarSubtractDelegate subtract;
    private readonly ScalarMultiplyDelegate multiply;
    private readonly ScalarBatchMultiplyDelegate? batchMultiply;
    private readonly CurveParameterSet curve;
    private readonly BaseMemoryPool pool;

    private readonly int dimension;
    private readonly int degreeBound;
    private readonly int blockLength;
    private readonly int paddedLength;

    //Per-shape tables: ω^j and ω^(−j) for j in [0, L/2); the forward transform
    //of the reciprocal kernel pre-scaled by 1/L; leading_constant[i] for
    //i in [0, blockLength − degreeBound); binomial[i] for i in [0, dimension).
    private IMemoryOwner<byte>? forwardTwiddles;
    private IMemoryOwner<byte>? inverseTwiddles;
    private IMemoryOwner<byte>? kernelSpectrum;
    private IMemoryOwner<byte>? leadingConstants;
    private IMemoryOwner<byte>? binomial;

    /// <summary>
    /// Builds the per-shape engine: derives and order-checks the domain root,
    /// precomputes the twiddle tables, the pre-scaled kernel spectrum and both
    /// weight tables, so every later <see cref="Interpolate"/> is
    /// inversion-free.
    /// </summary>
    /// <param name="dimension">The message length (the RS dimension); at least 1.</param>
    /// <param name="blockLength">The codeword length (the RS block length); at least <paramref name="dimension"/>.</param>
    /// <param name="add">Scalar addition.</param>
    /// <param name="subtract">Scalar subtraction.</param>
    /// <param name="multiply">Scalar multiplication.</param>
    /// <param name="invert">Scalar inversion (table setup only).</param>
    /// <param name="ofScalar">Writes a small integer as a working-domain element.</param>
    /// <param name="curve">The wired curve the delegates route over.</param>
    /// <param name="pool">Pool the tables and per-call scratch rent from.</param>
    /// <param name="batchMultiply">Optional batched multiplication for the element-wise weight products.</param>
    /// <exception cref="ArgumentNullException">When a delegate or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a length is out of range or the padded domain exceeds the field's 2-adic subgroup or byte addressability.</exception>
    /// <exception cref="ArgumentException">When the curve is not wired.</exception>
    /// <exception cref="InvalidOperationException">When the derived root fails its order check.</exception>
    public ScalarNttReedSolomon(
        int dimension,
        int blockLength,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        Action<uint, Span<byte>> ofScalar,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarBatchMultiplyDelegate? batchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(ofScalar);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(dimension, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(blockLength, dimension);
        WellKnownCurves.ThrowIfCurveNotWired(curve);

        //The tables and the per-call workspace are byte spans of paddedLength
        //elements, so the PADDED domain — not just the codeword — must stay
        //byte-addressable; the guard also keeps every later size product inside
        //the positive int range.
        uint paddedUnsigned = BitOperations.RoundUpToPowerOf2((uint)blockLength);
        int lengthLog2 = BitOperations.Log2(paddedUnsigned);
        if(paddedUnsigned > int.MaxValue / ScalarSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(blockLength),
                $"The codeword length {blockLength} pads to a 2^{lengthLog2}-element transform domain whose tables cannot be addressed as byte spans.");
        }

        if(lengthLog2 > ScalarNtt.TwoAdicity(curve))
        {
            throw new ArgumentOutOfRangeException(
                nameof(blockLength),
                $"The codeword length {blockLength} needs a 2^{lengthLog2} transform domain, beyond the 2^{ScalarNtt.TwoAdicity(curve)} subgroup of curve '{curve}'.");
        }

        int padded = (int)paddedUnsigned;

        this.add = add;
        this.subtract = subtract;
        this.multiply = multiply;
        this.batchMultiply = batchMultiply;
        this.curve = curve;
        this.pool = pool;
        this.dimension = dimension;
        degreeBound = dimension - 1;
        this.blockLength = blockLength;
        paddedLength = padded;

        int twiddleCount = paddedLength / 2;
        int leadingCount = blockLength - degreeBound;
        IMemoryOwner<byte>? forwardOwner = null;
        IMemoryOwner<byte>? inverseOwner = null;
        IMemoryOwner<byte>? kernelOwner = null;
        IMemoryOwner<byte>? leadingOwner = null;
        IMemoryOwner<byte>? binomialOwner = null;
        IMemoryOwner<byte>? inversesOwner = null;
        try
        {
            //The twiddle tables from the derived root and its inverse; the
            //derivation verifies the root's exact order before returning it.
            Span<byte> root = stackalloc byte[ScalarSize];
            Span<byte> inverseRoot = stackalloc byte[ScalarSize];
            ScalarNtt.DeriveRootOfUnity(lengthLog2, root, subtract, multiply, ofScalar, curve);
            invert(root, inverseRoot, curve);
            forwardOwner = pool.Rent(Math.Max(twiddleCount, 1) * ScalarSize);
            inverseOwner = pool.Rent(Math.Max(twiddleCount, 1) * ScalarSize);
            ScalarNtt.BuildTwiddles(root, paddedLength, forwardOwner.Memory.Span[..(twiddleCount * ScalarSize)], multiply, ofScalar, curve);
            ScalarNtt.BuildTwiddles(inverseRoot, paddedLength, inverseOwner.Memory.Span[..(twiddleCount * ScalarSize)], multiply, ofScalar, curve);

            //inverses[i] = 1/i (inverses[0] = 0), i in [0, blockLength) — the
            //reciprocal kernel and the source of both weight tables. The batch
            //inversion helper is field-generic over the injected delegates.
            inversesOwner = pool.Rent(blockLength * ScalarSize);
            Span<byte> inverses = inversesOwner.Memory.Span[..(blockLength * ScalarSize)];
            Fp256ReedSolomon.BatchInverseArithmetic(blockLength, inverses, add, subtract, multiply, invert, ofScalar, curve);

            //The kernel spectrum: the reciprocal kernel zero-padded to L,
            //forward-transformed once, pre-scaled by 1/L so the unnormalized
            //inverse transform of every later convolution comes out exact.
            kernelOwner = pool.Rent(paddedLength * ScalarSize);
            Span<byte> kernel = kernelOwner.Memory.Span[..(paddedLength * ScalarSize)];
            kernel.Clear();
            inverses.CopyTo(kernel[..(blockLength * ScalarSize)]);
            ScalarNtt.Forward(kernel, paddedLength, forwardOwner.Memory.Span[..(twiddleCount * ScalarSize)], add, subtract, multiply, curve);
            Span<byte> inversePadding = stackalloc byte[ScalarSize];
            ofScalar((uint)paddedLength, inversePadding);
            invert(inversePadding, inversePadding, curve);
            for(int i = 0; i < paddedLength; i++)
            {
                multiply(kernel.Slice(i * ScalarSize, ScalarSize), inversePadding, kernel.Slice(i * ScalarSize, ScalarSize), curve);
            }

            //Leading constants. leading_constant[0] = 1; for i in [1, blockLength − degreeBound):
            //leading_constant[i] = leading_constant[i−1] · (degreeBound + i) · inverses[i].
            leadingOwner = pool.Rent(Math.Max(leadingCount, 1) * ScalarSize);
            Span<byte> leading = leadingOwner.Memory.Span[..(leadingCount * ScalarSize)];
            leading.Clear();
            ofScalar(1, ElementAt(leading, 0));
            Span<byte> scalarValue = stackalloc byte[ScalarSize];
            for(int i = 1; i + degreeBound < blockLength; ++i)
            {
                ofScalar((uint)(degreeBound + i), scalarValue);
                multiply(ElementAt(leading, i - 1), scalarValue, ElementAt(leading, i), curve);
                multiply(ElementAt(leading, i), ElementAt(inverses, i), ElementAt(leading, i), curve);
            }

            //Finish: leading_constant[k − degreeBound] *= (k − degreeBound); negate when
            //degreeBound is odd. k runs degreeBound .. blockLength − 1.
            for(int k = degreeBound; k < blockLength; ++k)
            {
                int index = k - degreeBound;
                ofScalar((uint)(k - degreeBound), scalarValue);
                multiply(ElementAt(leading, index), scalarValue, ElementAt(leading, index), curve);
                if((degreeBound & 1) == 1)
                {
                    NegateInPlace(ElementAt(leading, index));
                }
            }

            //Binomial weights. binomial[0] = 1; for i in [1, dimension):
            //binomial[i] = binomial[i−1] · (dimension − i) · inverses[i]; then negate odd indices.
            binomialOwner = pool.Rent(dimension * ScalarSize);
            Span<byte> binom = binomialOwner.Memory.Span[..(dimension * ScalarSize)];
            binom.Clear();
            ofScalar(1, ElementAt(binom, 0));
            for(int i = 1; i < dimension; ++i)
            {
                ofScalar((uint)(dimension - i), scalarValue);
                multiply(ElementAt(binom, i - 1), scalarValue, ElementAt(binom, i), curve);
                multiply(ElementAt(binom, i), ElementAt(inverses, i), ElementAt(binom, i), curve);
            }

            for(int i = 1; i < dimension; i += 2)
            {
                NegateInPlace(ElementAt(binom, i));
            }

            ReleaseTable(inversesOwner, blockLength);
            inversesOwner = null;
            forwardTwiddles = forwardOwner;
            inverseTwiddles = inverseOwner;
            kernelSpectrum = kernelOwner;
            leadingConstants = leadingOwner;
            binomial = binomialOwner;
        }
        catch
        {
            ReleaseTable(inversesOwner, blockLength);
            ReleaseTable(binomialOwner, dimension);
            ReleaseTable(leadingOwner, Math.Max(leadingCount, 1));
            ReleaseTable(kernelOwner, paddedLength);
            ReleaseTable(inverseOwner, Math.Max(twiddleCount, 1));
            ReleaseTable(forwardOwner, Math.Max(twiddleCount, 1));
            throw;
        }
    }

    public int Dimension => dimension;

    public int BlockLength => blockLength;

    /// <summary>
    /// Extends the codeword in place: on entry the first <c>dimension</c>
    /// elements hold the message evaluations; on return every element holds the
    /// evaluation at its node, the prefix untouched.
    /// </summary>
    /// <param name="evaluations">The codeword buffer, <c>blockLength · 32</c> bytes.</param>
    /// <exception cref="ArgumentException">When the buffer length does not match.</exception>
    /// <exception cref="ObjectDisposedException">When the engine is disposed.</exception>
    public void Interpolate(Span<byte> evaluations)
    {
        ReadOnlySpan<byte> twiddles = (forwardTwiddles ?? throw new ObjectDisposedException(nameof(ScalarNttReedSolomon))).Memory.Span[..((paddedLength / 2) * ScalarSize)];
        ReadOnlySpan<byte> inverse = (inverseTwiddles ?? throw new ObjectDisposedException(nameof(ScalarNttReedSolomon))).Memory.Span[..((paddedLength / 2) * ScalarSize)];
        ReadOnlySpan<byte> kernel = (kernelSpectrum ?? throw new ObjectDisposedException(nameof(ScalarNttReedSolomon))).Memory.Span[..(paddedLength * ScalarSize)];
        ReadOnlySpan<byte> binom = (binomial ?? throw new ObjectDisposedException(nameof(ScalarNttReedSolomon))).Memory.Span[..(dimension * ScalarSize)];
        ReadOnlySpan<byte> leading = (leadingConstants ?? throw new ObjectDisposedException(nameof(ScalarNttReedSolomon))).Memory.Span[..((blockLength - degreeBound) * ScalarSize)];

        if(evaluations.Length != blockLength * ScalarSize)
        {
            throw new ArgumentException($"The evaluation buffer must be {blockLength * ScalarSize} bytes; received {evaluations.Length}.", nameof(evaluations));
        }

        int tail = blockLength - dimension;
        if(tail == 0)
        {
            //The codeword is the message: nothing to extend.
            return;
        }

        using IMemoryOwner<byte> workOwner = pool.Rent(paddedLength * ScalarSize);
        Span<byte> work = workOwner.Memory.Span[..(paddedLength * ScalarSize)];
        try
        {
            //work[i] = binomial[i] · y[i] for i in [0, dimension), zero elsewhere.
            work.Clear();
            if(batchMultiply is not null)
            {
                batchMultiply(binom, evaluations[..(dimension * ScalarSize)], work[..(dimension * ScalarSize)], dimension, curve);
            }
            else
            {
                for(int i = 0; i < dimension; i++)
                {
                    multiply(ElementAt(binom, i), evaluations.Slice(i * ScalarSize, ScalarSize), work.Slice(i * ScalarSize, ScalarSize), curve);
                }
            }

            //The cyclic convolution with the cached kernel spectrum. Both spectra
            //share the forward transform's bit-reversed order, so the pointwise
            //product needs no reordering. The product stays on the per-element
            //delegate: it writes each result over its own left operand, and only
            //the single-element contract establishes aliasing; batching this
            //stage is a later performance seam with non-aliased scratch.
            ScalarNtt.Forward(work, paddedLength, twiddles, add, subtract, multiply, curve);
            for(int i = 0; i < paddedLength; i++)
            {
                multiply(work.Slice(i * ScalarSize, ScalarSize), kernel.Slice(i * ScalarSize, ScalarSize), work.Slice(i * ScalarSize, ScalarSize), curve);
            }

            ScalarNtt.Inverse(work, paddedLength, inverse, add, subtract, multiply, curve);

            //y[k] = leading_constant[k − degreeBound] · S(k) for k in [dimension, blockLength):
            //the leading-constant, convolution and output slices are all contiguous.
            if(batchMultiply is not null)
            {
                batchMultiply(
                    leading.Slice((dimension - degreeBound) * ScalarSize, tail * ScalarSize),
                    work.Slice(dimension * ScalarSize, tail * ScalarSize),
                    evaluations.Slice(dimension * ScalarSize, tail * ScalarSize),
                    tail,
                    curve);
            }
            else
            {
                for(int k = dimension; k < blockLength; k++)
                {
                    multiply(ElementAt(leading, k - degreeBound), work.Slice(k * ScalarSize, ScalarSize), evaluations.Slice(k * ScalarSize, ScalarSize), curve);
                }
            }
        }
        finally
        {
            work.Clear();
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        int twiddleCount = Math.Max(paddedLength / 2, 1);
        IMemoryOwner<byte>? localForward = forwardTwiddles;
        forwardTwiddles = null;
        ReleaseTable(localForward, twiddleCount);
        IMemoryOwner<byte>? localInverse = inverseTwiddles;
        inverseTwiddles = null;
        ReleaseTable(localInverse, twiddleCount);
        IMemoryOwner<byte>? localKernel = kernelSpectrum;
        kernelSpectrum = null;
        ReleaseTable(localKernel, paddedLength);
        IMemoryOwner<byte>? localLeading = leadingConstants;
        leadingConstants = null;
        ReleaseTable(localLeading, Math.Max(blockLength - degreeBound, 1));
        IMemoryOwner<byte>? localBinomial = binomial;
        binomial = null;
        ReleaseTable(localBinomial, dimension);
    }


    private static void ReleaseTable(IMemoryOwner<byte>? owner, int elementCount)
    {
        if(owner is not null)
        {
            owner.Memory.Span[..(elementCount * ScalarSize)].Clear();
            owner.Dispose();
        }
    }


    private void NegateInPlace(Span<byte> value)
    {
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        subtract(zero, value, value, curve);
    }


    private static Span<byte> ElementAt(Span<byte> table, int index) => table.Slice(index * ScalarSize, ScalarSize);

    private static ReadOnlySpan<byte> ElementAt(ReadOnlySpan<byte> table, int index) => table.Slice(index * ScalarSize, ScalarSize);
}
