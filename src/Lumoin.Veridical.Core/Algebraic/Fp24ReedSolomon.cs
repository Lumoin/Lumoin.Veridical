using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The point-evaluation Reed–Solomon interpolator over the FIPS 204 base field
/// <c>F_q</c> (<c>q = 8380417</c>), a faithful port of google/longfellow-zk's
/// <c>lib/algebra/reed_solomon.h</c> <c>ReedSolomon&lt;Fp24, CrtConvolutionFactory&lt;CRT&lt;1, Fp24&gt;, Fp24&gt;&gt;</c>.
/// Given the values of a polynomial of degree below <c>n</c> at the points <c>0, 1, …, n−1</c>, it
/// extends them to the values at <c>n, …, m−1</c> in place. The sextic ML-DSA circuit field encodes
/// component-wise through this scalar engine (<see cref="Fp24SexticReedSolomon"/>), exactly as the
/// reference's <c>ReedSolomonExtension6</c> does.
/// </summary>
/// <remarks>
/// The interpolation identity (Lagrange recast for equally spaced points) is
/// <c>p(k) = (−1)^d (k−d) C(k,d) Σ_{j≤d} (1/(k−j)) (−1)^j C(d,j) p(j)</c> with <c>d = n−1</c>: the inner
/// sum is the convolution of <c>x[j] = (−1)^j C(d,j) p(j)</c> against the arithmetic-inverse kernel,
/// computed by <see cref="Fp24CrtConvolution"/> in the auxiliary prime domain. The inverse, binomial and
/// leading-constant tables are precomputed at construction. Values are plain residues below <c>q</c> in
/// 32-bit lanes; the arithmetic is self-contained single-word modular arithmetic — the field is fixed by
/// FIPS 204, so no delegate seam applies below the row-encoder factory that wraps this engine.
/// </remarks>
[System.Diagnostics.DebuggerDisplay("Fp24 RS (N={dimension}, M={blockLength})")]
internal sealed class Fp24ReedSolomon: IDisposable
{
    /// <summary>The FIPS 204 prime <c>q = 2^23 − 2^13 + 1</c>.</summary>
    private const uint FieldModulus = 8380417;

    /// <summary>The RS dimension <c>n</c> (input evaluation count).</summary>
    private readonly int dimension;

    /// <summary>The degree bound <c>d = n − 1</c> the reference states the identity in terms of.</summary>
    private readonly int degreeBound;

    /// <summary>The RS block length <c>m</c> (output evaluation count).</summary>
    private readonly int blockLength;

    /// <summary>The pool the interpolation scratch rents from.</summary>
    private readonly BaseMemoryPool pool;

    /// <summary>The leading constants <c>(−1)^d (k−d) C(k,d)</c>, indexed <c>k − d</c> over <c>[0, m − d)</c>; <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? leadingConstants;

    /// <summary>The binomial weights <c>(−1)^i C(d, i)</c> for <c>i</c> in <c>[0, n)</c>; <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? binomial;

    /// <summary>The auxiliary-prime convolver whose fixed kernel is the arithmetic-inverse table; <see langword="null"/> once disposed.</summary>
    private Fp24CrtConvolution? convolution;


    /// <summary>
    /// Builds the interpolator for the given dimensions.
    /// </summary>
    /// <param name="dimension">The number of input points <c>n</c> (≥ 1).</param>
    /// <param name="blockLength">The number of output points <c>m</c> (≥ <paramref name="dimension"/>).</param>
    /// <param name="pool">Pool the tables rent from.</param>
    /// <exception cref="ArgumentNullException">When the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a dimension is out of range, including the modulus bound: the evaluation points <c>0, …, m−1</c> must be distinct residues, so <c>m</c> may not reach <c>q</c>.</exception>
    public Fp24ReedSolomon(int dimension, int blockLength, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(dimension, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(blockLength, dimension);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual((uint)blockLength, FieldModulus);

        this.dimension = dimension;
        degreeBound = dimension - 1;
        this.blockLength = blockLength;
        this.pool = pool;

        int leadingCount = blockLength - degreeBound;
        IMemoryOwner<byte>? leadingOwner = null;
        IMemoryOwner<byte>? binomialOwner = null;
        Fp24CrtConvolution? convolver = null;
        try
        {
            //inverses[i] = 1/i (inverses[0] = 0), i in [0, m) — the reference's batch_inverse_arithmetic.
            using IMemoryOwner<byte> inversesOwner = pool.Rent(blockLength * sizeof(uint));
            Span<uint> inverses = ResidueSpan(inversesOwner, blockLength);
            BatchInverseArithmetic(inverses);

            //The convolution's fixed operand is the inverses array (factory.make(n, m, inverses)).
            convolver = new Fp24CrtConvolution(dimension, blockLength, inverses, pool);

            //Leading constants. leading[0] = 1; leading[i] = leading[i-1] · (degreeBound + i) · inverses[i];
            //then leading[k - degreeBound] *= (k - degreeBound) with a global negation when degreeBound is
            //odd. leading[0] ends at zero — the (k - d) factor vanishes at k = d, and only outputs at
            //k ≥ n are ever read.
            leadingOwner = pool.Rent(leadingCount * sizeof(uint));
            Span<uint> leading = ResidueSpan(leadingOwner, leadingCount);
            leading.Clear();
            leading[0] = 1;
            for(int i = 1; i + degreeBound < blockLength; i++)
            {
                leading[i] = MulMod(MulMod(leading[i - 1], (uint)(degreeBound + i) % FieldModulus), inverses[i]);
            }

            for(int k = degreeBound; k < blockLength; k++)
            {
                int index = k - degreeBound;
                leading[index] = MulMod(leading[index], (uint)index % FieldModulus);
                if((degreeBound & 1) == 1)
                {
                    leading[index] = NegMod(leading[index]);
                }
            }

            //Binomial weights. binomial[0] = 1; binomial[i] = binomial[i-1] · (n - i) · inverses[i];
            //odd indices negated — (−1)^i C(d, i).
            binomialOwner = pool.Rent(dimension * sizeof(uint));
            Span<uint> binomialValues = ResidueSpan(binomialOwner, dimension);
            binomialValues.Clear();
            binomialValues[0] = 1;
            for(int i = 1; i < dimension; i++)
            {
                binomialValues[i] = MulMod(MulMod(binomialValues[i - 1], (uint)(dimension - i) % FieldModulus), inverses[i]);
            }

            for(int i = 1; i < dimension; i += 2)
            {
                binomialValues[i] = NegMod(binomialValues[i]);
            }

            inverses.Clear();
            leadingConstants = leadingOwner;
            binomial = binomialOwner;
            convolution = convolver;
        }
        catch
        {
            convolver?.Dispose();
            binomialOwner?.Dispose();
            leadingOwner?.Dispose();
            throw;
        }
    }


    /// <summary>The RS dimension (input evaluation count <c>n</c>).</summary>
    public int Dimension => dimension;

    /// <summary>The RS block length (output evaluation count <c>m</c>).</summary>
    public int BlockLength => blockLength;


    /// <summary>
    /// Extends the <c>n</c> input evaluations in the prefix of <paramref name="values"/> to all <c>m</c>
    /// evaluations, in place — the reference's <c>interpolate</c>. On entry <c>values[0..n)</c> holds the
    /// polynomial's values at <c>0, …, n−1</c> as residues below <c>q</c>; on return <c>values[0..m)</c>
    /// holds the values at <c>0, …, m−1</c>, the first <c>n</c> unchanged.
    /// </summary>
    /// <param name="values"><c>m</c> base-field residues; the first <c>n</c> are the inputs.</param>
    /// <exception cref="ObjectDisposedException">When the interpolator has been disposed.</exception>
    /// <exception cref="ArgumentException">When the span is the wrong length.</exception>
    public void Interpolate(Span<uint> values)
    {
        Fp24CrtConvolution convolver = convolution ?? throw new ObjectDisposedException(nameof(Fp24ReedSolomon));
        ReadOnlySpan<uint> binomialValues = ResidueSpan(binomial ?? throw new ObjectDisposedException(nameof(Fp24ReedSolomon)), dimension);
        ReadOnlySpan<uint> leading = ResidueSpan(leadingConstants ?? throw new ObjectDisposedException(nameof(Fp24ReedSolomon)), blockLength - degreeBound);

        if(values.Length != blockLength)
        {
            throw new ArgumentException($"The evaluation buffer must hold {blockLength} residues; received {values.Length}.", nameof(values));
        }

        using IMemoryOwner<byte> workOwner = pool.Rent((dimension + blockLength) * sizeof(uint));
        Span<uint> work = ResidueSpan(workOwner, dimension + blockLength);
        Span<uint> x = work[..dimension];
        Span<uint> convolved = work[dimension..];
        try
        {
            //x[i] = binomial[i] · p(i), i in [0, n).
            for(int i = 0; i < dimension; i++)
            {
                x[i] = MulMod(binomialValues[i], values[i]);
            }

            convolver.Convolve(x, convolved);

            //p(k) = leading[k - degreeBound] · T[k], k in [n, m).
            for(int k = dimension; k < blockLength; k++)
            {
                values[k] = MulMod(leading[k - degreeBound], convolved[k]);
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
        Fp24CrtConvolution? localConvolution = convolution;
        if(localConvolution is not null)
        {
            convolution = null;
            localConvolution.Dispose();
        }

        DisposeOwner(ref binomial, dimension);
        DisposeOwner(ref leadingConstants, blockLength - degreeBound);
    }


    /// <summary>
    /// <c>destination[i] = 1/i</c> with <c>destination[0] = 0</c> — the reference's
    /// <c>batch_inverse_arithmetic</c>: prefix factorials, one inversion, then the unwinding products.
    /// </summary>
    /// <param name="destination">Receives the arithmetic inverses.</param>
    private static void BatchInverseArithmetic(Span<uint> destination)
    {
        destination[0] = 0;
        uint product = 1;
        uint index = 0;
        for(int i = 1; i < destination.Length; i++)
        {
            index++;
            destination[i] = product;
            product = MulMod(product, index);
        }

        product = InvertMod(product);
        for(int i = destination.Length; i-- > 0;)
        {
            destination[i] = MulMod(destination[i], product);
            product = MulMod(product, index);
            index--;
        }
    }


    /// <summary>Multiplication modulo <see cref="FieldModulus"/> through a 64-bit intermediate.</summary>
    /// <param name="a">The first residue.</param>
    /// <param name="b">The second residue.</param>
    /// <returns>The product residue.</returns>
    private static uint MulMod(uint a, uint b)
    {
        uint product = (uint)((ulong)a * b % FieldModulus);

        return product;
    }


    /// <summary>Negation modulo <see cref="FieldModulus"/>.</summary>
    /// <param name="a">The residue to negate.</param>
    /// <returns>The negated residue.</returns>
    private static uint NegMod(uint a)
    {
        uint negated = a == 0 ? 0 : FieldModulus - a;

        return negated;
    }


    /// <summary>Fermat inversion <c>a^(q−2)</c>; the exponent is a public field constant and the inputs are public table indices, never secrets.</summary>
    /// <param name="value">The residue to invert.</param>
    /// <returns>The inverse residue.</returns>
    private static uint InvertMod(uint value)
    {
        uint result = 1;
        uint basis = value;
        uint exponent = FieldModulus - 2;
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


    /// <summary>Views a pooled rent as its leading <paramref name="count"/> base-field residues.</summary>
    /// <param name="owner">The pooled rent.</param>
    /// <param name="count">The number of residues.</param>
    /// <returns>The residue span.</returns>
    private static Span<uint> ResidueSpan(IMemoryOwner<byte> owner, int count) => MemoryMarshal.Cast<byte, uint>(owner.Memory.Span)[..count];


    /// <summary>Clears and releases one pooled table rent, idempotently.</summary>
    /// <param name="owner">The rent reference; set to <see langword="null"/>.</param>
    /// <param name="count">The number of residues to clear.</param>
    private static void DisposeOwner(ref IMemoryOwner<byte>? owner, int count)
    {
        IMemoryOwner<byte>? local = owner;
        if(local is not null)
        {
            owner = null;
            MemoryMarshal.Cast<byte, uint>(local.Memory.Span)[..count].Clear();
            local.Dispose();
        }
    }
}
