using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The auxiliary-prime NTT convolver for the FIPS 204 base field, a faithful port of
/// google/longfellow-zk's <c>lib/algebra/crt_convolution.h</c> <c>CRTConvolution&lt;CRT&lt;1, Fp24&gt;, Fp24&gt;</c>
/// — the convolution engine behind the ML-DSA statements' Reed–Solomon row extension. The base field
/// <c>F_q</c> (<c>q = 8380417</c>) has no smooth-order root of unity, so the convolution is computed
/// exactly in an auxiliary NTT-friendly prime field and reduced back: with 24-bit operands the true
/// integer convolution coefficients fit a single 64-bit auxiliary prime (the reference's
/// one-prime CRT basis), so no reconstruction step is needed.
/// </summary>
/// <remarks>
/// <para>
/// The fixed operand (the Reed–Solomon inverses kernel) is lifted, scaled by <c>1/padding</c> and
/// forward-transformed once at construction; each <see cref="Convolve"/> is one forward NTT of the
/// variable operand, a pointwise product and one backward NTT, exactly the reference's shape. The
/// transform length is the codeword length rounded up to a power of two, and every output coefficient
/// is the exact integer <c>Σ x[i]·y[k−i]</c> reduced modulo <c>q</c>. Wrap-around terms of the cyclic
/// convolution touch only indices below the input length, which the Reed–Solomon caller never reads —
/// the same argument the reference's padding choice rests on.
/// </para>
/// <para>
/// The scratch and kernel buffers are pool-rented and retained for the convolver's lifetime; rows of
/// one shape are extended sequentially, never concurrently, so a single scratch buffer suffices.
/// </para>
/// </remarks>
[System.Diagnostics.DebuggerDisplay("Fp24 CRT convolution (N={inputLength}, M={outputLength}, padding={padding})")]
internal sealed class Fp24CrtConvolution: IDisposable
{
    /// <summary>The FIPS 204 prime <c>q = 2^23 − 2^13 + 1</c> the convolution outputs reduce into.</summary>
    private const uint FieldModulus = 8380417;

    /// <summary>The first prime of the reference's fixed CRT basis (<c>crt.cc</c> <c>kPrimes17[0]</c>). One prime suffices: the true convolution coefficients are bounded by <see cref="MaximumInputLength"/> · (q−1)², below this prime.</summary>
    private const ulong AuxiliaryPrime = 18446744072195407873UL;

    /// <summary>The auxiliary prime's root of unity of order <c>2^22</c> (<c>crt.cc</c> <c>kOmega17[0]</c>).</summary>
    private const ulong AuxiliaryOmega = 436037131817UL;

    /// <summary>The base-two logarithm of <see cref="AuxiliaryOmega"/>'s multiplicative order (<c>crt.h</c> <c>kOmegaOrder = 1 &lt;&lt; 22</c>); the padded transform length may not exceed it.</summary>
    private const int AuxiliaryOmegaLogOrder = 22;

    /// <summary>The largest input length whose exact convolution coefficients provably fit the auxiliary prime: <c>(q−1)² &lt; 2^46</c>, so <c>2^17</c> terms stay below <c>2^63</c> with a factor-two margin.</summary>
    private const int MaximumInputLength = 1 << 17;

    /// <summary>The variable operand's length <c>n</c>.</summary>
    private readonly int inputLength;

    /// <summary>The number of convolution outputs <c>m</c>.</summary>
    private readonly int outputLength;

    /// <summary>The padded transform length: the smallest power of two at or above <see cref="outputLength"/> (the reference's <c>choose_padding</c>).</summary>
    private readonly int padding;

    /// <summary>The forward-transformed kernel, pre-scaled by <c>1/padding</c> so the backward transform's implicit factor of the transform length cancels (the reference pre-scales <c>y</c> by <c>1/N</c> in the constructor); <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? kernelTransform;

    /// <summary>The per-call working buffer for the variable operand; retained because rows are extended sequentially on one thread; <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? scratch;

    /// <summary>The twiddle table for the forward transform: powers of the padded root's inverse (the reference's FFTPACK negative-exponent forward convention); <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? forwardTwiddles;

    /// <summary>The twiddle table for the backward transform: powers of the padded root; <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? backwardTwiddles;


    /// <summary>
    /// Builds the convolver for the given shape and fixed kernel.
    /// </summary>
    /// <param name="inputLength">The variable operand's length <c>n</c> (≥ 1).</param>
    /// <param name="outputLength">The number of convolution outputs <c>m</c> (≥ <paramref name="inputLength"/>).</param>
    /// <param name="kernel">The fixed operand (<c>m</c> base-field residues below <c>q</c>).</param>
    /// <param name="pool">Pool the kernel transform, twiddles and scratch rent from.</param>
    /// <exception cref="ArgumentNullException">When the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a dimension is out of range for the auxiliary basis.</exception>
    /// <exception cref="ArgumentException">When the kernel length does not match.</exception>
    public Fp24CrtConvolution(int inputLength, int outputLength, ReadOnlySpan<uint> kernel, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(inputLength, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(outputLength, inputLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(inputLength, MaximumInputLength);
        if(kernel.Length != outputLength)
        {
            throw new ArgumentException($"The kernel must hold {outputLength} residues; received {kernel.Length}.", nameof(kernel));
        }

        this.inputLength = inputLength;
        this.outputLength = outputLength;

        //The reference's choose_padding: the smallest power of two at or above the output length.
        int chosenPadding = 1;
        while(chosenPadding < outputLength)
        {
            chosenPadding <<= 1;
        }

        if(chosenPadding > 1 << AuxiliaryOmegaLogOrder)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength), $"The padded transform length {chosenPadding} exceeds the auxiliary root-of-unity order 2^{AuxiliaryOmegaLogOrder}.");
        }

        padding = chosenPadding;

        IMemoryOwner<byte>? kernelOwner = null;
        IMemoryOwner<byte>? scratchOwner = null;
        IMemoryOwner<byte>? forwardOwner = null;
        IMemoryOwner<byte>? backwardOwner = null;
        try
        {
            //The padded-length root: omega has order 2^22, so omega^(2^22 / padding) has order padding.
            ulong paddedRoot = PowMod(AuxiliaryOmega, (ulong)((1 << AuxiliaryOmegaLogOrder) / padding));
            ulong paddedRootInverse = PowMod(paddedRoot, AuxiliaryPrime - 2);

            forwardOwner = pool.Rent(Math.Max(padding / 2, 1) * sizeof(ulong));
            backwardOwner = pool.Rent(Math.Max(padding / 2, 1) * sizeof(ulong));
            FillTwiddles(TwiddleSpan(forwardOwner, padding), paddedRootInverse);
            FillTwiddles(TwiddleSpan(backwardOwner, padding), paddedRoot);

            kernelOwner = pool.Rent(padding * sizeof(ulong));
            Span<ulong> kernelValues = ValueSpan(kernelOwner, padding);
            kernelValues.Clear();

            //Pre-scale by 1/padding so backward(forward(x) ∘ forward(y/P)) is the plain convolution
            //(a forward-backward pair multiplies by the transform length).
            ulong paddingInverse = PowMod((ulong)padding % AuxiliaryPrime, AuxiliaryPrime - 2);
            for(int i = 0; i < outputLength; i++)
            {
                kernelValues[i] = MulMod(kernel[i], paddingInverse);
            }

            NumberTheoreticTransform(kernelValues, TwiddleSpan(forwardOwner, padding));

            scratchOwner = pool.Rent(padding * sizeof(ulong));
            ValueSpan(scratchOwner, padding).Clear();

            kernelTransform = kernelOwner;
            scratch = scratchOwner;
            forwardTwiddles = forwardOwner;
            backwardTwiddles = backwardOwner;
        }
        catch
        {
            kernelOwner?.Dispose();
            scratchOwner?.Dispose();
            forwardOwner?.Dispose();
            backwardOwner?.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Computes the first <c>m</c> coefficients of the convolution of <paramref name="values"/> with the
    /// fixed kernel — <c>destination[k] = Σ_{i&lt;n} values[i]·kernel[k−i] mod q</c>, the reference's
    /// <c>convolution(x, z)</c>.
    /// </summary>
    /// <param name="values">The variable operand (<c>n</c> base-field residues below <c>q</c>).</param>
    /// <param name="destination">Receives the <c>m</c> convolution outputs as base-field residues.</param>
    /// <exception cref="ObjectDisposedException">When the convolver has been disposed.</exception>
    /// <exception cref="ArgumentException">When a span length does not match the shape.</exception>
    public void Convolve(ReadOnlySpan<uint> values, Span<uint> destination)
    {
        IMemoryOwner<byte> kernelOwner = kernelTransform ?? throw new ObjectDisposedException(nameof(Fp24CrtConvolution));
        IMemoryOwner<byte> scratchOwner = scratch ?? throw new ObjectDisposedException(nameof(Fp24CrtConvolution));
        if(values.Length != inputLength)
        {
            throw new ArgumentException($"The input must hold {inputLength} residues; received {values.Length}.", nameof(values));
        }

        if(destination.Length != outputLength)
        {
            throw new ArgumentException($"The destination must hold {outputLength} residues; received {destination.Length}.", nameof(destination));
        }

        Span<ulong> work = ValueSpan(scratchOwner, padding);
        work.Clear();
        for(int i = 0; i < inputLength; i++)
        {
            work[i] = values[i];
        }

        NumberTheoreticTransform(work, TwiddleSpan(forwardTwiddles!, padding));

        ReadOnlySpan<ulong> kernelValues = ValueSpan(kernelOwner, padding);
        for(int i = 0; i < padding; i++)
        {
            work[i] = MulMod(work[i], kernelValues[i]);
        }

        NumberTheoreticTransform(work, TwiddleSpan(backwardTwiddles!, padding));

        //Every retained output is the exact integer convolution coefficient (below the auxiliary prime
        //by the construction bound), reduced into the base field.
        for(int k = 0; k < outputLength; k++)
        {
            destination[k] = (uint)(work[k] % FieldModulus);
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        DisposeOwner(ref kernelTransform, padding);
        DisposeOwner(ref scratch, padding);
        DisposeOwner(ref forwardTwiddles, Math.Max(padding / 2, 1));
        DisposeOwner(ref backwardTwiddles, Math.Max(padding / 2, 1));
    }


    /// <summary>
    /// The iterative radix-2 transform with the given twiddle table: bit-reversal permutation then
    /// Cooley–Tukey butterflies. The direction is carried entirely by the table (powers of the padded
    /// root for backward, of its inverse for forward), so one routine serves both.
    /// </summary>
    /// <param name="values">The <c>padding</c> auxiliary-field values transformed in place.</param>
    /// <param name="twiddles">The direction's twiddle table (<c>padding/2</c> root powers).</param>
    private static void NumberTheoreticTransform(Span<ulong> values, ReadOnlySpan<ulong> twiddles)
    {
        int length = values.Length;
        for(int i = 1, reversed = 0; i < length; i++)
        {
            int bit = length >> 1;
            while((reversed & bit) != 0)
            {
                reversed ^= bit;
                bit >>= 1;
            }

            reversed |= bit;
            if(i < reversed)
            {
                (values[i], values[reversed]) = (values[reversed], values[i]);
            }
        }

        for(int half = 1; half < length; half <<= 1)
        {
            int step = length / (2 * half);
            for(int start = 0; start < length; start += 2 * half)
            {
                for(int j = 0; j < half; j++)
                {
                    ulong twiddled = MulMod(values[start + half + j], twiddles[j * step]);
                    ulong kept = values[start + j];
                    values[start + j] = AddMod(kept, twiddled);
                    values[start + half + j] = SubMod(kept, twiddled);
                }
            }
        }
    }


    /// <summary>Fills the table with <c>root^i</c> for <c>i</c> in <c>[0, padding/2)</c> — the only powers the butterflies index.</summary>
    /// <param name="twiddles">The table to fill.</param>
    /// <param name="root">The transform direction's padded-length root.</param>
    private static void FillTwiddles(Span<ulong> twiddles, ulong root)
    {
        ulong power = 1;
        for(int i = 0; i < twiddles.Length; i++)
        {
            twiddles[i] = power;
            power = MulMod(power, root);
        }
    }


    /// <summary>Addition modulo <see cref="AuxiliaryPrime"/>; the prime exceeds <c>2^63</c>, so the sum's 64-bit wrap is detected and folded in the same branch as an in-range reduction.</summary>
    /// <param name="a">The first residue.</param>
    /// <param name="b">The second residue.</param>
    /// <returns>The sum residue.</returns>
    private static ulong AddMod(ulong a, ulong b)
    {
        ulong sum = a + b;
        if(sum < a || sum >= AuxiliaryPrime)
        {
            sum -= AuxiliaryPrime;
        }

        return sum;
    }


    /// <summary>Subtraction modulo <see cref="AuxiliaryPrime"/>.</summary>
    /// <param name="a">The minuend residue.</param>
    /// <param name="b">The subtrahend residue.</param>
    /// <returns>The difference residue.</returns>
    private static ulong SubMod(ulong a, ulong b)
    {
        ulong difference = a >= b ? a - b : a + (AuxiliaryPrime - b);

        return difference;
    }


    /// <summary>Multiplication modulo <see cref="AuxiliaryPrime"/> through a 128-bit intermediate.</summary>
    /// <param name="a">The first residue.</param>
    /// <param name="b">The second residue.</param>
    /// <returns>The product residue.</returns>
    private static ulong MulMod(ulong a, ulong b)
    {
        ulong product = (ulong)((UInt128)a * b % AuxiliaryPrime);

        return product;
    }


    /// <summary>Square-and-multiply exponentiation modulo <see cref="AuxiliaryPrime"/>; the exponents here are public transform parameters, never secrets.</summary>
    /// <param name="value">The basis residue.</param>
    /// <param name="exponent">The public exponent.</param>
    /// <returns>The power residue.</returns>
    private static ulong PowMod(ulong value, ulong exponent)
    {
        ulong result = 1;
        ulong basis = value % AuxiliaryPrime;
        while(exponent != 0)
        {
            if((exponent & 1) != 0)
            {
                result = MulMod(result, basis);
            }

            basis = MulMod(basis, basis);
            exponent >>= 1;
        }

        return result;
    }


    /// <summary>Views a pooled rent as its leading <paramref name="count"/> 64-bit auxiliary-field values.</summary>
    /// <param name="owner">The pooled rent.</param>
    /// <param name="count">The number of values.</param>
    /// <returns>The value span.</returns>
    private static Span<ulong> ValueSpan(IMemoryOwner<byte> owner, int count) => MemoryMarshal.Cast<byte, ulong>(owner.Memory.Span)[..count];


    /// <summary>Views a pooled rent as a direction's twiddle table for the given padded length.</summary>
    /// <param name="owner">The pooled rent.</param>
    /// <param name="paddedLength">The padded transform length.</param>
    /// <returns>The twiddle span (<c>paddedLength/2</c> entries, at least one).</returns>
    private static Span<ulong> TwiddleSpan(IMemoryOwner<byte> owner, int paddedLength) => MemoryMarshal.Cast<byte, ulong>(owner.Memory.Span)[..Math.Max(paddedLength / 2, 1)];


    /// <summary>Clears and releases one pooled rent, idempotently.</summary>
    /// <param name="owner">The rent reference; set to <see langword="null"/>.</param>
    /// <param name="count">The number of 64-bit values to clear.</param>
    private static void DisposeOwner(ref IMemoryOwner<byte>? owner, int count)
    {
        IMemoryOwner<byte>? local = owner;
        if(local is not null)
        {
            owner = null;
            MemoryMarshal.Cast<byte, ulong>(local.Memory.Span)[..count].Clear();
            local.Dispose();
        }
    }
}
