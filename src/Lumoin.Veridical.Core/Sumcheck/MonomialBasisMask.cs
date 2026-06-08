using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Sumcheck;

/// <summary>
/// The statistical-ZK sumcheck mask (Libra, IACR ePrint 2019/317 §4.1; lineage
/// CFS, ePrint 2017/305; design <c>ZK-STATMASK-DESIGN.md</c> §2 v2):
/// uniformly random coefficients over an explicit public
/// <see cref="MonomialBasis"/> of per-variable degree at most two, blended into
/// a degree-2 sumcheck as <c>h_k + ρ·s_k</c> so every revealed round
/// coefficient — including the degree-two one a multilinear mask leaves bare —
/// is uniform given the mask's degrees of freedom.
/// </summary>
/// <remarks>
/// <para>
/// Everything is closed-form over the basis — no dense table, no mask
/// codeword: on booleans <c>x = x²</c>, so
/// <c>σ = Σ_b s(b) = Σ_e c_e·2^{d − |supp(e)|}</c>, and the round binding
/// variable <c>X_k</c> (high variable first, <c>k = d … 1</c>, the BaseFold
/// fold order) receives from each monomial the contribution
/// <c>c_e·2^{#{j&lt;k : e_j=0}}·Π_{j&gt;k} r_j^{e_j}·t^{e_k}</c> — routed to
/// <c>c_0</c>, the chain-elided <c>c_1</c>, or <c>c_2</c> by <c>e_k</c>.
/// The terminal value <c>s(r) = Σ_e c_e·m_e(r)</c> is the inner product of the
/// coefficient vector with the public weights <c>m_e(r)</c>
/// (<see cref="BuildWeightVector"/>), which is how the construction binds it: a
/// weighted opening of the committed coefficients (SM.1).
/// </para>
/// <para>
/// The coefficients are secret mask randomness — revealing them retroactively
/// unmasks every blended round — so the buffer is pooled sensitive memory,
/// cleared on dispose. The basis itself is public protocol shape.
/// </para>
/// </remarks>
[DebuggerDisplay("MonomialBasisMask (VariableCount = {VariableCount}, CoefficientCount = {CoefficientCount})")]
public sealed class MonomialBasisMask: SensitiveMemory
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>The public monomial basis the coefficients live on.</summary>
    public MonomialBasis Basis { get; }

    /// <summary>The masked sumcheck's variable count <c>d</c>.</summary>
    public int VariableCount => Basis.VariableCount;

    /// <summary>The coefficient count: the mask's degrees of freedom.</summary>
    public int CoefficientCount => Basis.Count;

    /// <summary>The curve identifying the scalar field.</summary>
    public CurveParameterSet Curve { get; }


    private MonomialBasisMask(IMemoryOwner<byte> owner, MonomialBasis basis, CurveParameterSet curve, Tag tag)
        : base(owner, basis.Count * ScalarSize, tag)
    {
        Basis = basis;
        Curve = curve;
    }


    /// <summary>
    /// Samples a fresh mask: one uniform coefficient per basis monomial from
    /// <paramref name="random"/>. Sample <em>before</em> the blend challenge
    /// <c>ρ</c> is squeezed — the commitment to these coefficients must enter
    /// the transcript first or the blend's soundness argument fails.
    /// </summary>
    /// <param name="basis">The public monomial basis.</param>
    /// <param name="random">The entropy-sourced scalar sampler.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="pool">The pool to rent the coefficient buffer from.</param>
    /// <returns>The sampled mask; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented buffer transfers ownership to the returned mask.")]
    public static MonomialBasisMask Sample(
        MonomialBasis basis,
        ScalarRandomDelegate random,
        CurveParameterSet curve,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(basis);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(pool);

        int coefficientCount = basis.Count;
        IMemoryOwner<byte> owner = pool.Rent(coefficientCount * ScalarSize);
        Span<byte> coefficients = owner.Memory.Span[..(coefficientCount * ScalarSize)];
        Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);
        for(int i = 0; i < coefficientCount; i++)
        {
            _ = random(coefficients.Slice(i * ScalarSize, ScalarSize), curve, scalarTag);
        }

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.PolynomialCoefficients),
            (typeof(CurveParameterSet), (object)curve));

        return new MonomialBasisMask(owner, basis, curve, tag);
    }


    /// <summary>
    /// Computes <c>σ = Σ_b s(b) = Σ_e c_e·2^{d − |supp(e)|}</c> — closed form
    /// because every monomial's boolean sum counts the assignments with its
    /// support variables set.
    /// </summary>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="pool">The pool to rent the result from.</param>
    /// <returns>The mask sum <c>σ</c>; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">When the mask has been disposed.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented buffer transfers ownership to the returned scalar.")]
    public Scalar ComputeSigma(ScalarAddDelegate add, ScalarMultiplyDelegate multiply, SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> coefficients = AsReadOnlySpan();
        int d = VariableCount;

        Span<byte> twoPowers = BuildTwoPowerTable(d, add, stackalloc byte[(d + 1) * ScalarSize]);

        IMemoryOwner<byte> resultOwner = pool.Rent(ScalarSize);
        Span<byte> result = resultOwner.Memory.Span[..ScalarSize];
        result.Clear();

        Span<byte> term = stackalloc byte[ScalarSize];
        for(int i = 0; i < Basis.Count; i++)
        {
            ReadOnlySpan<byte> exponents = Basis.ExponentsAt(i);
            int support = 0;
            for(int j = 0; j < d; j++)
            {
                if(exponents[j] != 0)
                {
                    support++;
                }
            }

            multiply(coefficients.Slice(i * ScalarSize, ScalarSize), twoPowers.Slice((d - support) * ScalarSize, ScalarSize), term, Curve);
            add(result, term, result, Curve);
        }

        return new Scalar(resultOwner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    /// <summary>
    /// Adds the round-<c>k</c> blend to a compressed round polynomial in place:
    /// each basis monomial contributes
    /// <c>c_e·2^{#{j&lt;k : e_j=0}}·Π_{j&gt;k} r_j^{e_j}</c> to <c>c_0</c> when
    /// <c>e_k = 0</c> and to <c>c_2</c> when <c>e_k = 2</c> (the <c>e_k = 1</c>
    /// share lands in the chain-elided linear term the verifier reconstructs
    /// from the running claim), all scaled by <c>ρ</c>.
    /// </summary>
    /// <param name="boundVariable">The variable <c>X_k</c> this round binds; rounds run <c>k = d … 1</c> (high variable first, the BaseFold fold order).</param>
    /// <param name="challengesForVariable">One-based challenge registry: <c>challengesForVariable[j]</c> is the challenge <c>r_j</c> that bound <c>X_j</c>; entries for <c>j &gt; boundVariable</c> must be populated, the rest are unread.</param>
    /// <param name="rho">The squeezed blend scalar <c>ρ</c>, canonical bytes.</param>
    /// <param name="c0">The round polynomial's constant coefficient, blended in place.</param>
    /// <param name="c2">The round polynomial's quadratic coefficient, blended in place.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="boundVariable"/> is outside <c>[1, VariableCount]</c>.</exception>
    /// <exception cref="ArgumentException">When a span argument is not one scalar wide or the registry is too short.</exception>
    /// <exception cref="ObjectDisposedException">When the mask has been disposed.</exception>
    public void AddRoundBlend(
        int boundVariable,
        ReadOnlySpan<Scalar> challengesForVariable,
        ReadOnlySpan<byte> rho,
        Span<byte> c0,
        Span<byte> c2,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply)
    {
        AddRoundBlendCore(boundVariable, challengesForVariable, rho, c0, c2, c3: default, add, multiply);
    }


    /// <summary>
    /// Adds the round-<c>k</c> blend of a degree-3 mask in place: as the
    /// quadratic overload, plus the cubic share <c>e_k = 3</c> routed to
    /// <paramref name="c3"/> — the shape the Spartan outer sumcheck's
    /// degree-3 round format carries.
    /// </summary>
    /// <param name="c3">The round polynomial's cubic coefficient, blended in place.</param>
    /// <inheritdoc cref="AddRoundBlend(int, ReadOnlySpan{Scalar}, ReadOnlySpan{byte}, Span{byte}, Span{byte}, ScalarAddDelegate, ScalarMultiplyDelegate)"/>
    public void AddRoundBlend(
        int boundVariable,
        ReadOnlySpan<Scalar> challengesForVariable,
        ReadOnlySpan<byte> rho,
        Span<byte> c0,
        Span<byte> c2,
        Span<byte> c3,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply)
    {
        ThrowIfNotScalarWide(c3.Length, nameof(c3));

        AddRoundBlendCore(boundVariable, challengesForVariable, rho, c0, c2, c3, add, multiply);
    }


    private void AddRoundBlendCore(
        int boundVariable,
        ReadOnlySpan<Scalar> challengesForVariable,
        ReadOnlySpan<byte> rho,
        Span<byte> c0,
        Span<byte> c2,
        Span<byte> c3,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentOutOfRangeException.ThrowIfLessThan(boundVariable, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(boundVariable, VariableCount);
        ThrowIfNotScalarWide(rho.Length, nameof(rho));
        ThrowIfNotScalarWide(c0.Length, nameof(c0));
        ThrowIfNotScalarWide(c2.Length, nameof(c2));
        if(challengesForVariable.Length < VariableCount + 1)
        {
            throw new ArgumentException(
                $"The challenge registry must carry {VariableCount + 1} one-based entries; received {challengesForVariable.Length}.",
                nameof(challengesForVariable));
        }

        ReadOnlySpan<byte> coefficients = AsReadOnlySpan();
        int d = VariableCount;
        int k = boundVariable;

        Span<byte> twoPowers = BuildTwoPowerTable(d, add, stackalloc byte[(d + 1) * ScalarSize]);

        //The blended sums Σ c_e·factor by the bound variable's exponent; ρ is
        //applied once at the end. The linear share (e_k = 1) is chain-elided.
        Span<byte> constantSum = stackalloc byte[ScalarSize];
        Span<byte> quadraticSum = stackalloc byte[ScalarSize];
        Span<byte> cubicSum = stackalloc byte[ScalarSize];
        constantSum.Clear();
        quadraticSum.Clear();
        cubicSum.Clear();
        bool cubicSeen = false;

        Span<byte> factor = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int i = 0; i < Basis.Count; i++)
        {
            ReadOnlySpan<byte> exponents = Basis.ExponentsAt(i);
            int roundExponent = exponents[k - 1];
            if(roundExponent == 1)
            {
                //The linear share is chain-elided; nothing to blend explicitly.
                continue;
            }

            //2^{#{j<k : e_j=0}} — the free boolean variables each summing to 2
            //for an absent variable and to 1 otherwise.
            int freeZeros = 0;
            for(int j = 1; j < k; j++)
            {
                if(exponents[j - 1] == 0)
                {
                    freeZeros++;
                }
            }

            twoPowers.Slice(freeZeros * ScalarSize, ScalarSize).CopyTo(factor);

            //Π_{j>k} r_j^{e_j} over the bound challenges.
            for(int j = k + 1; j <= d; j++)
            {
                ReadOnlySpan<byte> r = challengesForVariable[j].AsReadOnlySpan();
                for(int e = 0; e < exponents[j - 1]; e++)
                {
                    multiply(factor, r, factor, Curve);
                }
            }

            multiply(coefficients.Slice(i * ScalarSize, ScalarSize), factor, term, Curve);
            if(roundExponent == 0)
            {
                add(constantSum, term, constantSum, Curve);
            }
            else if(roundExponent == 2)
            {
                add(quadraticSum, term, quadraticSum, Curve);
            }
            else
            {
                cubicSeen = true;
                add(cubicSum, term, cubicSum, Curve);
            }
        }

        if(cubicSeen && c3.IsEmpty)
        {
            throw new InvalidOperationException(
                "The basis carries a cubic round share; use the AddRoundBlend overload with the c3 coefficient.");
        }

        multiply(rho, constantSum, term, Curve);
        add(c0, term, c0, Curve);

        multiply(rho, quadraticSum, term, Curve);
        add(c2, term, c2, Curve);

        if(!c3.IsEmpty)
        {
            multiply(rho, cubicSum, term, Curve);
            add(c3, term, c3, Curve);
        }
    }


    /// <summary>
    /// Evaluates the mask at a point: <c>s(r) = Σ_e c_e·m_e(r)</c> — the value
    /// the construction binds by a weighted opening of the committed
    /// coefficients against <see cref="BuildWeightVector"/>'s weights.
    /// </summary>
    /// <param name="point">The point <c>r</c>; one scalar per variable, index <c>i</c> holding <c>r_{i+1}</c> (the MLE storage convention).</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="pool">The pool to rent the result from.</param>
    /// <returns>The evaluation <c>s(r)</c>; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="point"/> does not carry one scalar per variable.</exception>
    /// <exception cref="ObjectDisposedException">When the mask has been disposed.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented buffer transfers ownership to the returned scalar.")]
    public Scalar EvaluateAt(
        ReadOnlySpan<Scalar> point,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        if(point.Length != VariableCount)
        {
            throw new ArgumentException(
                $"The point must carry {VariableCount} scalar(s) (one per variable); received {point.Length}.",
                nameof(point));
        }

        ReadOnlySpan<byte> coefficients = AsReadOnlySpan();

        IMemoryOwner<byte> resultOwner = pool.Rent(ScalarSize);
        Span<byte> result = resultOwner.Memory.Span[..ScalarSize];
        result.Clear();

        Span<byte> monomial = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int i = 0; i < Basis.Count; i++)
        {
            EvaluateMonomial(Basis.ExponentsAt(i), point, monomial, multiply, Curve);
            multiply(coefficients.Slice(i * ScalarSize, ScalarSize), monomial, term, Curve);
            add(result, term, result, Curve);
        }

        return new Scalar(resultOwner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    /// <summary>
    /// Builds the <em>public</em> weight vector <c>w(r) = (m_e(r))_e</c> over
    /// the basis, so that <c>⟨coefficients, w(r)⟩ = s(r)</c>. Static because the
    /// weights carry no secret — they are the verifier's side of the weighted
    /// opening that binds the mask's terminal evaluation. Any destination tail
    /// beyond the basis count is zeroed (the committed coefficient multilinear's
    /// power-of-two filler positions carry zero weight).
    /// </summary>
    /// <param name="basis">The public monomial basis.</param>
    /// <param name="point">The point <c>r</c>; one scalar per variable, the MLE storage convention.</param>
    /// <param name="destination">The weight buffer; at least <c>basis.Count</c> scalars wide, a whole number of scalars.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the point or destination does not match the basis shape.</exception>
    public static void BuildWeightVector(
        MonomialBasis basis,
        ReadOnlySpan<Scalar> point,
        Span<byte> destination,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(basis);
        ArgumentNullException.ThrowIfNull(multiply);
        if(point.Length != basis.VariableCount)
        {
            throw new ArgumentException(
                $"The point must carry {basis.VariableCount} scalar(s) (one per variable); received {point.Length}.",
                nameof(point));
        }

        if(destination.Length < basis.Count * ScalarSize || destination.Length % ScalarSize != 0)
        {
            throw new ArgumentException(
                $"The weight buffer must be a whole number of scalars and at least {basis.Count * ScalarSize} bytes; received {destination.Length}.",
                nameof(destination));
        }

        destination.Clear();
        for(int i = 0; i < basis.Count; i++)
        {
            EvaluateMonomial(basis.ExponentsAt(i), point, destination.Slice(i * ScalarSize, ScalarSize), multiply, curve);
        }
    }


    /// <summary>
    /// Copies the coefficient vector into <paramref name="destination"/> in
    /// basis order, zeroing any tail — the layout the construction commits as a
    /// small multilinear (the zeroed filler positions pair with
    /// <see cref="BuildWeightVector"/>'s zero weights). The destination receives
    /// secret mask randomness; treat it with the same care as this mask.
    /// </summary>
    /// <param name="destination">The buffer to copy into; at least <see cref="CoefficientCount"/> scalars wide, a whole number of scalars.</param>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is too short or not scalar-aligned.</exception>
    /// <exception cref="ObjectDisposedException">When the mask has been disposed.</exception>
    public void CopyCoefficientsTo(Span<byte> destination)
    {
        if(destination.Length < Length || destination.Length % ScalarSize != 0)
        {
            throw new ArgumentException(
                $"The destination must be a whole number of scalars and at least {Length} bytes; received {destination.Length}.",
                nameof(destination));
        }

        ReadOnlySpan<byte> coefficients = AsReadOnlySpan();
        coefficients.CopyTo(destination[..Length]);
        destination[Length..].Clear();
    }


    //m_e(r) = Π_j r_j^{e_j} into result (one scalar wide).
    //
    //Batch seam marker (perf batch): within one monomial the multiplies chain
    //(data-dependent), but across monomials — BuildWeightVector's per-index
    //calls and EvaluateAt's terms — they are independent, exactly the
    //ScalarArithmeticBackend.BatchMultiply shape (the AD.7b lane-interleaved
    //kernel); not pre-designed here per the substrate rule.
    private static void EvaluateMonomial(
        ReadOnlySpan<byte> exponents,
        ReadOnlySpan<Scalar> point,
        Span<byte> result,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        //Field one, big-endian canonical.
        result.Clear();
        result[ScalarSize - 1] = 0x01;

        for(int j = 0; j < exponents.Length; j++)
        {
            ReadOnlySpan<byte> r = point[j].AsReadOnlySpan();
            for(int e = 0; e < exponents[j]; e++)
            {
                multiply(result, r, result, curve);
            }
        }
    }


    //Fills and returns a table of 2^0 … 2^d as canonical scalars by repeated
    //field doubling — the wired curves' scalar fields are odd-prime, so the
    //powers stay nonzero.
    private Span<byte> BuildTwoPowerTable(int d, ScalarAddDelegate add, Span<byte> table)
    {
        table.Clear();
        table[ScalarSize - 1] = 0x01;
        for(int e = 1; e <= d; e++)
        {
            Span<byte> previous = table.Slice((e - 1) * ScalarSize, ScalarSize);
            Span<byte> current = table.Slice(e * ScalarSize, ScalarSize);
            add(previous, previous, current, Curve);
        }

        return table;
    }


    private static void ThrowIfNotScalarWide(int length, string parameterName)
    {
        if(length != ScalarSize)
        {
            throw new ArgumentException($"The span must be exactly {ScalarSize} bytes (one canonical scalar); received {length}.", parameterName);
        }
    }
}
