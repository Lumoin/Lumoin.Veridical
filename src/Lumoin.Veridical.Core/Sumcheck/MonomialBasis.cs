using Lumoin.Veridical.Core.Memory;
using System;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Sumcheck;

/// <summary>
/// The public monomial basis of a <see cref="MonomialBasisMask"/>: an explicit
/// list of exponent vectors <c>e ∈ {0, 1, 2}^d</c>, each naming the monomial
/// <c>m_e(x) = Π_j x_j^{e_j}</c> of per-variable degree at most two — the
/// degree bound that keeps a masked degree-2 sumcheck's round polynomials
/// degree 2. The basis is public protocol shape (the verifier derives the
/// terminal weight vector from it); only the mask's coefficients are secret.
/// </summary>
/// <remarks>
/// <para>
/// Two factory shapes construct this basis:
/// <see cref="SumOfUnivariatesWithPad"/> is the Libra mask — constant,
/// <c>x_j</c>, <c>x_j²</c> — extended by <c>padPairCount</c>
/// weight-bearing pad pairs <c>{m_i, x_1·m_i}</c> over multilinear monomials
/// <c>m_i(x_2…x_d)</c>, whose span contains the round-annihilating
/// combinations <c>(2x_1 − 1)·m_i</c> a rank lemma rotates into; and
/// <see cref="Full"/> is the complete <c>3^d</c> basis for small <c>d</c>,
/// where the pad construction lacks capacity but the full mask is tiny.
/// </para>
/// <para>The basis owns pooled exponent storage. Dispose it only after all borrowed views and masks are finished.</para>
/// </remarks>
[DebuggerDisplay("MonomialBasis (VariableCount = {VariableCount}, Count = {Count})")]
public sealed class MonomialBasis: IDisposable
{
    /// <summary>
    /// The per-variable exponent cap: the stack's highest masked round degree is
    /// the Spartan outer sumcheck's cubic, so bases up to per-variable degree 3
    /// are constructible; each factory enforces the degree its consumer's round
    /// format supports.
    /// </summary>
    private const int MaximumExponent = 3;

    /// <summary>The BaseFold-internal sumcheck's (<c>f·eq_z</c>) per-variable degree: quadratic.</summary>
    private const int QuadraticDegree = 2;

    /// <summary>
    /// The variable-count ceiling for <see cref="Full"/>: <c>Full(d)</c> materialises <c>3^d</c>
    /// exponent vectors; beyond this cap the full basis has no consumer (the padded
    /// sum-of-univariates shape takes over from <c>d ≈ 5</c>) and the allocation would be wasteful.
    /// </summary>
    private const int FullBasisVariableCountCeiling = 8;

    /// <summary>The owned exponent bytes; null after disposal.</summary>
    private OwnedByteBuffer? exponents;


    /// <summary>The masked sumcheck's variable count <c>d</c>.</summary>
    public int VariableCount { get; }

    /// <summary>The number of basis monomials (= the mask's coefficient count).</summary>
    public int Count { get; }


    /// <summary>Takes ownership of the populated exponent buffer.</summary>
    /// <param name="exponents">The exponent storage transferred by the factory.</param>
    /// <param name="variableCount">The width of each exponent vector.</param>
    /// <param name="count">The number of exponent vectors.</param>
    private MonomialBasis(OwnedByteBuffer exponents, int variableCount, int count)
    {
        this.exponents = exponents;
        VariableCount = variableCount;
        Count = count;
    }


    /// <summary>Returns the exponent vector of the basis monomial at <paramref name="index"/>; entry <c>j − 1</c> is the exponent of <c>x_j</c>.</summary>
    /// <returns>A borrowed view valid until this basis is disposed.</returns>
    /// <exception cref="ObjectDisposedException">When this basis has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is outside <c>[0, Count)</c>.</exception>
    public ReadOnlySpan<byte> ExponentsAt(int index)
    {
        OwnedByteBuffer storage = exponents ?? throw new ObjectDisposedException(nameof(MonomialBasis));
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, Count);

        return storage.Bytes.Slice(index * VariableCount, VariableCount);
    }


    /// <summary>
    /// The Libra sum-of-univariates basis with weight-bearing padding: the
    /// constant, then for each degree <c>e = 1 … perVariableDegree</c> the
    /// <c>d</c> monomials <c>x_j^e</c>, then <paramref name="padPairCount"/>
    /// pairs <c>{m_i, x_1·m_i}</c> where <c>m_i</c> enumerates the multilinear
    /// monomials of <c>x_2…x_d</c> smallest-subset-first. Total count
    /// <c>perVariableDegree·d + 1 + 2·padPairCount</c>. The degree matches the
    /// masked sumcheck's per-round degree (2 for the BaseFold-internal
    /// <c>f·eq_z</c>, 3 for the Spartan outer cubic); the pad coordinates carry
    /// nonzero terminal weights, laundering the weighted opening's round
    /// functionals.
    /// </summary>
    /// <param name="variableCount">The masked sumcheck's variable count <c>d</c>; must be positive.</param>
    /// <param name="padPairCount">The number of pad pairs; at most <c>2^{d−1}</c> (the multilinear monomials of <c>x_2…x_d</c>).</param>
    /// <param name="perVariableDegree">The univariate degree of each <c>g_j</c>; in <c>[2, 3]</c>, matching the masked round format. Defaults to 2.</param>
    /// <param name="pool">The pool supplying exponent storage; it must outlive the returned basis.</param>
    /// <returns>The basis, which the caller must dispose after all borrowed views and masks.</returns>
    /// <exception cref="ArgumentNullException">When the pool is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="variableCount"/> is non-positive, <paramref name="padPairCount"/> is negative, the pad exceeds the <c>2^{d−1}</c> capacity, or <paramref name="perVariableDegree"/> is outside <c>[2, 3]</c>.</exception>
    public static MonomialBasis SumOfUnivariatesWithPad(int variableCount, int padPairCount, BaseMemoryPool pool, int perVariableDegree = QuadraticDegree)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegative(padPairCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(perVariableDegree, QuadraticDegree);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(perVariableDegree, MaximumExponent);

        long padCapacity = 1L << (variableCount - 1);
        if(padPairCount > padCapacity)
        {
            throw new ArgumentOutOfRangeException(
                nameof(padPairCount),
                $"At most {padCapacity} pad pair(s) exist over x_2…x_{variableCount} (the multilinear monomials); requested {padPairCount}. Small variable counts use the full basis instead.");
        }

        int count = checked((perVariableDegree * variableCount) + 1 + (2 * padPairCount));
        OwnedByteBuffer? storage = OwnedByteBuffer.Rent(checked(count * variableCount), pool);
        try
        {
            Span<byte> exponents = storage.Bytes;
            exponents.Clear();
            int row = 1;

            //Degree blocks: rows of x_j, then x_j², (then x_j³) — matching the
            //(1, r_j, r_j², …) weight prefix.
            for(int degree = 1; degree <= perVariableDegree; degree++)
            {
                for(int j = 1; j <= variableCount; j++)
                {
                    exponents[(row * variableCount) + (j - 1)] = (byte)degree;
                    row++;
                }
            }

            //Pad pairs: m_i over x_2…x_d by subset index (smallest first), then
            //x_1·m_i. Both stay within per-variable degree 1, so the mask's overall
            //per-variable degree bound of 2 holds with slack.
            for(int i = 0; i < padPairCount; i++)
            {
                for(int variant = 0; variant < 2; variant++)
                {
                    Span<byte> target = exponents.Slice(row * variableCount, variableCount);
                    for(int bit = 0; bit < variableCount - 1; bit++)
                    {
                        if(((i >> bit) & 1) != 0)
                        {
                            target[bit + 1] = 1;
                        }
                    }

                    if(variant == 1)
                    {
                        target[0] = 1;
                    }

                    row++;
                }
            }

            MonomialBasis basis = new(storage, variableCount, count);
            storage = null;

            return basis;
        }
        finally
        {
            storage?.Dispose();
        }
    }


    /// <summary>
    /// The full degree-≤2 basis: all <c>3^d</c> exponent vectors, base-3
    /// smallest-first (the constant monomial first). The small-<c>d</c> route:
    /// the mask's <c>3^d</c> degrees of freedom dwarf every
    /// reveal, so no dedicated pad is needed.
    /// </summary>
    /// <param name="variableCount">The masked sumcheck's variable count <c>d</c>; positive and at most the materialisation ceiling.</param>
    /// <param name="pool">The pool supplying exponent storage; it must outlive the returned basis.</param>
    /// <returns>The basis, which the caller must dispose after all borrowed views and masks.</returns>
    /// <exception cref="ArgumentNullException">When the pool is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="variableCount"/> is non-positive or exceeds the ceiling.</exception>
    public static MonomialBasis Full(int variableCount, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(variableCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(variableCount, FullBasisVariableCountCeiling);

        int count = 1;
        for(int j = 0; j < variableCount; j++)
        {
            count *= QuadraticDegree + 1;
        }

        OwnedByteBuffer? storage = OwnedByteBuffer.Rent(checked(count * variableCount), pool);
        try
        {
            Span<byte> exponents = storage.Bytes;
            exponents.Clear();
            for(int index = 0; index < count; index++)
            {
                int remainder = index;
                Span<byte> target = exponents.Slice(index * variableCount, variableCount);
                for(int j = 0; j < variableCount; j++)
                {
                    target[j] = (byte)(remainder % (QuadraticDegree + 1));
                    remainder /= QuadraticDegree + 1;
                }
            }

            MonomialBasis basis = new(storage, variableCount, count);
            storage = null;

            return basis;
        }
        finally
        {
            storage?.Dispose();
        }
    }


    /// <summary>Clears and releases exponent storage. Repeated disposal has no effect.</summary>
    /// <remarks>Borrowed exponent views and masks must no longer be used. Disposal must not run concurrently with access.</remarks>
    public void Dispose()
    {
        OwnedByteBuffer? storage = exponents;
        exponents = null;
        storage?.Dispose();
    }
}
