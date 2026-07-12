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
/// Two factory shapes cover the statistical-mask design
/// (<c>ZK-STATMASK-DESIGN.md</c> §2, v2):
/// <see cref="SumOfUnivariatesWithPad"/> is the Libra mask — constant,
/// <c>x_j</c>, <c>x_j²</c> — extended by <c>padPairCount</c>
/// weight-bearing pad pairs <c>{m_i, x_1·m_i}</c> over multilinear monomials
/// <c>m_i(x_2…x_d)</c>, whose span contains the round-annihilating
/// combinations <c>(2x_1 − 1)·m_i</c> the §3 rank lemma rotates into; and
/// <see cref="Full"/> is the complete <c>3^d</c> basis for small <c>d</c>,
/// where the pad construction lacks capacity but the full mask is tiny.
/// </para>
/// </remarks>
[DebuggerDisplay("MonomialBasis (VariableCount = {VariableCount}, Count = {Count})")]
public sealed class MonomialBasis
{
    //The per-variable exponent cap: the stack's highest masked round degree is
    //the Spartan outer sumcheck's cubic, so bases up to per-variable degree 3
    //are constructible; each factory enforces the degree its consumer's round
    //format supports.
    private const int MaximumExponent = 3;

    //The BaseFold-internal sumcheck (f·eq_z) is quadratic per variable.
    private const int QuadraticDegree = 2;

    //Full(d) materialises 3^d exponent vectors; beyond this cap the full basis
    //has no consumer (the padded sum-of-univariates shape takes over from
    //d ≈ 5) and the allocation would be wasteful.
    private const int FullBasisVariableCountCeiling = 8;

    private readonly byte[] exponents;


    /// <summary>The masked sumcheck's variable count <c>d</c>.</summary>
    public int VariableCount { get; }

    /// <summary>The number of basis monomials (= the mask's coefficient count).</summary>
    public int Count { get; }


    private MonomialBasis(byte[] exponents, int variableCount, int count)
    {
        this.exponents = exponents;
        VariableCount = variableCount;
        Count = count;
    }


    /// <summary>Returns the exponent vector of the basis monomial at <paramref name="index"/>; entry <c>j − 1</c> is the exponent of <c>x_j</c>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is outside <c>[0, Count)</c>.</exception>
    public ReadOnlySpan<byte> ExponentsAt(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, Count);

        return exponents.AsSpan(index * VariableCount, VariableCount);
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
    /// functionals (design doc §3 condition 2).
    /// </summary>
    /// <param name="variableCount">The masked sumcheck's variable count <c>d</c>; must be positive.</param>
    /// <param name="padPairCount">The number of pad pairs; at most <c>2^{d−1}</c> (the multilinear monomials of <c>x_2…x_d</c>).</param>
    /// <param name="perVariableDegree">The univariate degree of each <c>g_j</c>; in <c>[2, 3]</c>, matching the masked round format. Defaults to 2.</param>
    /// <returns>The basis.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="variableCount"/> is non-positive, <paramref name="padPairCount"/> is negative, the pad exceeds the <c>2^{d−1}</c> capacity, or <paramref name="perVariableDegree"/> is outside <c>[2, 3]</c>.</exception>
    public static MonomialBasis SumOfUnivariatesWithPad(int variableCount, int padPairCount, int perVariableDegree = QuadraticDegree)
    {
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

        int count = (perVariableDegree * variableCount) + 1 + (2 * padPairCount);
        byte[] exponents = new byte[count * variableCount];
        int row = 1;

        //Degree blocks: rows of x_j, then x_j², (then x_j³) — matching the
        //(1, r_j, r_j², …) weight prefix of the design doc.
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
                Span<byte> target = exponents.AsSpan(row * variableCount, variableCount);
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

        return new MonomialBasis(exponents, variableCount, count);
    }


    /// <summary>
    /// The full degree-≤2 basis: all <c>3^d</c> exponent vectors, base-3
    /// smallest-first (the constant monomial first). The small-<c>d</c> route of
    /// the design doc — the mask's <c>3^d</c> degrees of freedom dwarf every
    /// reveal, so no dedicated pad is needed.
    /// </summary>
    /// <param name="variableCount">The masked sumcheck's variable count <c>d</c>; positive and at most the materialisation ceiling.</param>
    /// <returns>The basis.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="variableCount"/> is non-positive or exceeds the ceiling.</exception>
    public static MonomialBasis Full(int variableCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(variableCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(variableCount, FullBasisVariableCountCeiling);

        int count = 1;
        for(int j = 0; j < variableCount; j++)
        {
            count *= QuadraticDegree + 1;
        }

        byte[] exponents = new byte[count * variableCount];
        for(int index = 0; index < count; index++)
        {
            int remainder = index;
            Span<byte> target = exponents.AsSpan(index * variableCount, variableCount);
            for(int j = 0; j < variableCount; j++)
            {
                target[j] = (byte)(remainder % (QuadraticDegree + 1));
                remainder /= QuadraticDegree + 1;
            }
        }

        return new MonomialBasis(exponents, variableCount, count);
    }
}
