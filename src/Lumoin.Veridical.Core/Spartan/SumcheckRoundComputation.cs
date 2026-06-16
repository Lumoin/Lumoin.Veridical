using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Pure helpers that compute one round's univariate sumcheck polynomial
/// from the current folded MLE state.
/// </summary>
/// <remarks>
/// <para>
/// Each helper is a pure function of <c>(ReadOnlySpan&lt;byte&gt;, ...)</c>
/// to <see cref="Polynomial"/>. There is no
/// <see cref="FiatShamirTranscript"/> parameter, no operation-label
/// constant, no transcript-state read. The driver classes
/// (<see cref="OuterSumcheckProver"/>, <see cref="InnerSumcheckProver"/>)
/// compose this purity with transcript absorb / squeeze externally;
/// keeping round-polynomial computation pure preserves composability
/// with downstream algebraic transformations (a masking-polynomial
/// wrapper, in particular, adds a fixed contribution to the returned
/// polynomial without touching the sumcheck core).
/// </para>
/// <para>
/// The polynomial is constructed coefficient-wise rather than
/// evaluation-wise. For the outer round (degree 3), each pair
/// <c>(j, j+1)</c> of the folded MLE contributes four coefficients
/// derived from the bilinear-product expansion
/// <c>eq_X(j) · (Az_X(j) · Bz_X(j) − Cz_X(j))</c> where
/// <c>X_factor(j) = X[2j] + X · (X[2j+1] − X[2j])</c>. For the inner
/// round (degree 2) the expansion is <c>ABC_X(j) · z_X(j)</c>.
/// </para>
/// </remarks>
internal static class SumcheckRoundComputation
{
    /// <summary>
    /// Computes one round of the outer (degree-3) sumcheck polynomial
    /// from the current folded <c>(Az, Bz, Cz, eq)</c> MLE state.
    /// </summary>
    /// <param name="azFolded">The current <c>Az</c> MLE evaluations, <c>2^remainingVariableCount × 32</c> bytes.</param>
    /// <param name="bzFolded">The current <c>Bz</c> MLE evaluations.</param>
    /// <param name="czFolded">The current <c>Cz</c> MLE evaluations.</param>
    /// <param name="eqFolded">The current <c>eq(τ, ·)</c> MLE evaluations.</param>
    /// <param name="remainingVariableCount">The number of variables of the current folded MLEs. Must be at least 1.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="pool">The pool to rent scratch and the result buffer from.</param>
    /// <returns>A degree-3 univariate <see cref="Polynomial"/> in coefficient form.</returns>
    public static Polynomial ComputeOuterRoundPolynomial(
        ReadOnlySpan<byte> azFolded,
        ReadOnlySpan<byte> bzFolded,
        ReadOnlySpan<byte> czFolded,
        ReadOnlySpan<byte> eqFolded,
        int remainingVariableCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        if(remainingVariableCount < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(remainingVariableCount),
                remainingVariableCount,
                "Outer round polynomial requires at least one remaining variable.");
        }

        int elementSize = Scalar.SizeBytes;
        int pairCount = 1 << (remainingVariableCount - 1);
        ValidateMleByteLength(azFolded, remainingVariableCount, elementSize, nameof(azFolded));
        ValidateMleByteLength(bzFolded, remainingVariableCount, elementSize, nameof(bzFolded));
        ValidateMleByteLength(czFolded, remainingVariableCount, elementSize, nameof(czFolded));
        ValidateMleByteLength(eqFolded, remainingVariableCount, elementSize, nameof(eqFolded));

        //Output: degree-3 coefficient vector laid out low-degree first.
        IMemoryOwner<byte> outputOwner = pool.Rent(4 * elementSize);
        Span<byte> output = outputOwner.Memory.Span[..(4 * elementSize)];
        output.Clear();
        Span<byte> outC0 = output[..elementSize];
        Span<byte> outC1 = output.Slice(elementSize, elementSize);
        Span<byte> outC2 = output.Slice(2 * elementSize, elementSize);
        Span<byte> outC3 = output.Slice(3 * elementSize, elementSize);

        //Scratch slots: four slopes (azd, bzd, czd, eqd), three
        //"AB − C" coefficients (ac0, ac1, ac2), and two temporaries.
        using IMemoryOwner<byte> scratchOwner = pool.Rent(9 * elementSize);
        Span<byte> scratch = scratchOwner.Memory.Span[..(9 * elementSize)];
        Span<byte> azd = scratch[..elementSize];
        Span<byte> bzd = scratch.Slice(elementSize, elementSize);
        Span<byte> czd = scratch.Slice(2 * elementSize, elementSize);
        Span<byte> eqd = scratch.Slice(3 * elementSize, elementSize);
        Span<byte> ac0 = scratch.Slice(4 * elementSize, elementSize);
        Span<byte> ac1 = scratch.Slice(5 * elementSize, elementSize);
        Span<byte> ac2 = scratch.Slice(6 * elementSize, elementSize);
        Span<byte> temp1 = scratch.Slice(7 * elementSize, elementSize);
        Span<byte> temp2 = scratch.Slice(8 * elementSize, elementSize);

        for(int j = 0; j < pairCount; j++)
        {
            ReadOnlySpan<byte> az0 = azFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> az1 = azFolded.Slice((2 * j + 1) * elementSize, elementSize);
            ReadOnlySpan<byte> bz0 = bzFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> bz1 = bzFolded.Slice((2 * j + 1) * elementSize, elementSize);
            ReadOnlySpan<byte> cz0 = czFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> cz1 = czFolded.Slice((2 * j + 1) * elementSize, elementSize);
            ReadOnlySpan<byte> eq0 = eqFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> eq1 = eqFolded.Slice((2 * j + 1) * elementSize, elementSize);

            //Slopes: X[high] − X[low].
            subtract(az1, az0, azd, curve);
            subtract(bz1, bz0, bzd, curve);
            subtract(cz1, cz0, czd, curve);
            subtract(eq1, eq0, eqd, curve);

            //AB(X) − Cz(X) coefficients.
            //ac0 = az0·bz0 − cz0.
            multiply(az0, bz0, ac0, curve);
            subtract(ac0, cz0, ac0, curve);

            //ac1 = az0·bzd + azd·bz0 − czd.
            multiply(az0, bzd, temp1, curve);
            multiply(azd, bz0, temp2, curve);
            add(temp1, temp2, ac1, curve);
            subtract(ac1, czd, ac1, curve);

            //ac2 = azd·bzd.
            multiply(azd, bzd, ac2, curve);

            //Round-polynomial coefficient contributions:
            //  eq_X(j) · (AB − C)_X(j) = (eq0 + X·eqd) · (ac0 + X·ac1 + X²·ac2).

            //Constant term: eq0·ac0.
            multiply(eq0, ac0, temp1, curve);
            add(outC0, temp1, outC0, curve);

            //Linear term: eq0·ac1 + eqd·ac0.
            multiply(eq0, ac1, temp1, curve);
            multiply(eqd, ac0, temp2, curve);
            add(temp1, temp2, temp1, curve);
            add(outC1, temp1, outC1, curve);

            //Quadratic term: eq0·ac2 + eqd·ac1.
            multiply(eq0, ac2, temp1, curve);
            multiply(eqd, ac1, temp2, curve);
            add(temp1, temp2, temp1, curve);
            add(outC2, temp1, outC2, curve);

            //Cubic term: eqd·ac2.
            multiply(eqd, ac2, temp1, curve);
            add(outC3, temp1, outC3, curve);
        }

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.PolynomialCoefficients),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(PolynomialDegree), (object)new PolynomialDegree(3)));

        return new Polynomial(outputOwner, 3, elementSize, curve, tag);
    }


    /// <summary>
    /// Computes one round of the outer (degree-3) sumcheck polynomial
    /// for the <em>relaxed</em> R1CS identity
    /// <c>eq_X(j) · (Az_X(j) · Bz_X(j) − u · Cz_X(j) − E_X(j))</c>,
    /// where <c>u</c> is the relaxation scalar and <c>E</c> is the
    /// multilinear extension of the error vector.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This generalises <see cref="ComputeOuterRoundPolynomial"/>: the
    /// standard identity is the special case <c>u = 1</c>, <c>E ≡ 0</c>,
    /// and for those inputs this method returns byte-identical
    /// coefficients. The unified Spartan prover drives every instance —
    /// raw-prepared (<c>u = 1</c>, <c>E = 0</c>) or folded
    /// (<c>u ≠ 1</c>, <c>E ≠ 0</c>) — through this single relaxed code
    /// path.
    /// </para>
    /// <para>
    /// The relaxation scalar <c>u</c> is constant in the fold variable
    /// <c>X</c>, so it scales only the per-pair <c>Cz</c> contribution;
    /// the error term <c>E_X</c> is linear in <c>X</c> like the other
    /// MLEs. The product with <c>eq_X</c> stays degree 3.
    /// </para>
    /// </remarks>
    /// <param name="azFolded">The current <c>Az</c> MLE evaluations.</param>
    /// <param name="bzFolded">The current <c>Bz</c> MLE evaluations.</param>
    /// <param name="czFolded">The current <c>Cz</c> MLE evaluations.</param>
    /// <param name="eFolded">The current error-vector MLE evaluations.</param>
    /// <param name="eqFolded">The current <c>eq(τ, ·)</c> MLE evaluations.</param>
    /// <param name="uBytes">The relaxation scalar <c>u</c> in canonical big-endian (32 bytes).</param>
    /// <param name="remainingVariableCount">The number of variables of the current folded MLEs. Must be at least 1.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="curve">The curve whose scalar field the computation is over.</param>
    /// <param name="pool">The pool to rent scratch and the result buffer from.</param>
    /// <param name="batch">
    /// Optional scalar-backend bundle. When present, the per-pair products are
    /// gathered into contiguous columns and driven through its batch operations
    /// in blocks — byte-identical results (field operations are exact and the
    /// coefficient accumulation is commutative), so a SIMD lane-interleaved
    /// backend swaps in without perturbing any proof fixture.
    /// <see langword="null"/> runs the per-element delegates exactly as before.
    /// </param>
    /// <returns>A degree-3 univariate <see cref="Polynomial"/> in coefficient form.</returns>
    public static Polynomial ComputeOuterRoundPolynomialRelaxed(
        ReadOnlySpan<byte> azFolded,
        ReadOnlySpan<byte> bzFolded,
        ReadOnlySpan<byte> czFolded,
        ReadOnlySpan<byte> eFolded,
        ReadOnlySpan<byte> eqFolded,
        ReadOnlySpan<byte> uBytes,
        int remainingVariableCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        if(remainingVariableCount < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(remainingVariableCount),
                remainingVariableCount,
                "Outer round polynomial requires at least one remaining variable.");
        }

        int elementSize = Scalar.SizeBytes;
        int pairCount = 1 << (remainingVariableCount - 1);
        ValidateMleByteLength(azFolded, remainingVariableCount, elementSize, nameof(azFolded));
        ValidateMleByteLength(bzFolded, remainingVariableCount, elementSize, nameof(bzFolded));
        ValidateMleByteLength(czFolded, remainingVariableCount, elementSize, nameof(czFolded));
        ValidateMleByteLength(eFolded, remainingVariableCount, elementSize, nameof(eFolded));
        ValidateMleByteLength(eqFolded, remainingVariableCount, elementSize, nameof(eqFolded));
        if(uBytes.Length != elementSize)
        {
            throw new ArgumentException(
                $"u must be a single canonical scalar of {elementSize} bytes; received {uBytes.Length}.",
                nameof(uBytes));
        }

        if(batch is not null)
        {
            return ComputeOuterRoundPolynomialRelaxedBatched(
                azFolded, bzFolded, czFolded, eFolded, eqFolded, uBytes,
                pairCount, add, subtract, batch, curve, pool);
        }

        IMemoryOwner<byte> outputOwner = pool.Rent(4 * elementSize);
        Span<byte> output = outputOwner.Memory.Span[..(4 * elementSize)];
        output.Clear();
        Span<byte> outC0 = output[..elementSize];
        Span<byte> outC1 = output.Slice(elementSize, elementSize);
        Span<byte> outC2 = output.Slice(2 * elementSize, elementSize);
        Span<byte> outC3 = output.Slice(3 * elementSize, elementSize);

        //Scratch: five slopes (azd, bzd, czd, ed, eqd), three
        //"AB − uC − E" coefficients (ac0, ac1, ac2), two temporaries.
        using IMemoryOwner<byte> scratchOwner = pool.Rent(10 * elementSize);
        Span<byte> scratch = scratchOwner.Memory.Span[..(10 * elementSize)];
        Span<byte> azd = scratch[..elementSize];
        Span<byte> bzd = scratch.Slice(elementSize, elementSize);
        Span<byte> czd = scratch.Slice(2 * elementSize, elementSize);
        Span<byte> ed = scratch.Slice(3 * elementSize, elementSize);
        Span<byte> eqd = scratch.Slice(4 * elementSize, elementSize);
        Span<byte> ac0 = scratch.Slice(5 * elementSize, elementSize);
        Span<byte> ac1 = scratch.Slice(6 * elementSize, elementSize);
        Span<byte> ac2 = scratch.Slice(7 * elementSize, elementSize);
        Span<byte> temp1 = scratch.Slice(8 * elementSize, elementSize);
        Span<byte> temp2 = scratch.Slice(9 * elementSize, elementSize);

        for(int j = 0; j < pairCount; j++)
        {
            ReadOnlySpan<byte> az0 = azFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> az1 = azFolded.Slice((2 * j + 1) * elementSize, elementSize);
            ReadOnlySpan<byte> bz0 = bzFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> bz1 = bzFolded.Slice((2 * j + 1) * elementSize, elementSize);
            ReadOnlySpan<byte> cz0 = czFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> cz1 = czFolded.Slice((2 * j + 1) * elementSize, elementSize);
            ReadOnlySpan<byte> e0 = eFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> e1 = eFolded.Slice((2 * j + 1) * elementSize, elementSize);
            ReadOnlySpan<byte> eq0 = eqFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> eq1 = eqFolded.Slice((2 * j + 1) * elementSize, elementSize);

            //Slopes: X[high] − X[low].
            subtract(az1, az0, azd, curve);
            subtract(bz1, bz0, bzd, curve);
            subtract(cz1, cz0, czd, curve);
            subtract(e1, e0, ed, curve);
            subtract(eq1, eq0, eqd, curve);

            //ac0 = az0·bz0 − u·cz0 − e0.
            multiply(az0, bz0, ac0, curve);
            multiply(uBytes, cz0, temp1, curve);
            subtract(ac0, temp1, ac0, curve);
            subtract(ac0, e0, ac0, curve);

            //ac1 = (az0·bzd + azd·bz0) − u·czd − ed.
            multiply(az0, bzd, temp1, curve);
            multiply(azd, bz0, temp2, curve);
            add(temp1, temp2, ac1, curve);
            multiply(uBytes, czd, temp1, curve);
            subtract(ac1, temp1, ac1, curve);
            subtract(ac1, ed, ac1, curve);

            //ac2 = azd·bzd.
            multiply(azd, bzd, ac2, curve);

            //Round-polynomial coefficient contributions:
            //  eq_X(j) · (AB − uC − E)_X(j) = (eq0 + X·eqd)(ac0 + X·ac1 + X²·ac2).

            //Constant term: eq0·ac0.
            multiply(eq0, ac0, temp1, curve);
            add(outC0, temp1, outC0, curve);

            //Linear term: eq0·ac1 + eqd·ac0.
            multiply(eq0, ac1, temp1, curve);
            multiply(eqd, ac0, temp2, curve);
            add(temp1, temp2, temp1, curve);
            add(outC1, temp1, outC1, curve);

            //Quadratic term: eq0·ac2 + eqd·ac1.
            multiply(eq0, ac2, temp1, curve);
            multiply(eqd, ac1, temp2, curve);
            add(temp1, temp2, temp1, curve);
            add(outC2, temp1, outC2, curve);

            //Cubic term: eqd·ac2.
            multiply(eqd, ac2, temp1, curve);
            add(outC3, temp1, outC3, curve);
        }

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.PolynomialCoefficients),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(PolynomialDegree), (object)new PolynomialDegree(3)));

        return new Polynomial(outputOwner, 3, elementSize, curve, tag);
    }


    /// <summary>
    /// Computes one round of the inner (degree-2) sumcheck polynomial
    /// from the current folded <c>(ABC, z)</c> MLE state.
    /// </summary>
    /// <param name="abcFolded">The current ABC-batched MLE evaluations.</param>
    /// <param name="zFolded">The current <c>z</c> MLE evaluations.</param>
    /// <param name="remainingVariableCount">The number of variables of the current folded MLEs. Must be at least 1.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="curve">The curve whose scalar field the computation is over.</param>
    /// <param name="pool">The pool to rent scratch and the result buffer from.</param>
    /// <param name="batch">Optional scalar-backend bundle; see <see cref="ComputeOuterRoundPolynomialRelaxed"/> — byte-identical results, <see langword="null"/> runs the per-element path.</param>
    /// <returns>A degree-2 univariate <see cref="Polynomial"/> in coefficient form.</returns>
    public static Polynomial ComputeInnerRoundPolynomial(
        ReadOnlySpan<byte> abcFolded,
        ReadOnlySpan<byte> zFolded,
        int remainingVariableCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        if(remainingVariableCount < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(remainingVariableCount),
                remainingVariableCount,
                "Inner round polynomial requires at least one remaining variable.");
        }

        int elementSize = Scalar.SizeBytes;
        int pairCount = 1 << (remainingVariableCount - 1);
        ValidateMleByteLength(abcFolded, remainingVariableCount, elementSize, nameof(abcFolded));
        ValidateMleByteLength(zFolded, remainingVariableCount, elementSize, nameof(zFolded));

        if(batch is not null)
        {
            return ComputeInnerRoundPolynomialBatched(abcFolded, zFolded, pairCount, add, subtract, batch, curve, pool);
        }

        IMemoryOwner<byte> outputOwner = pool.Rent(3 * elementSize);
        Span<byte> output = outputOwner.Memory.Span[..(3 * elementSize)];
        output.Clear();
        Span<byte> outC0 = output[..elementSize];
        Span<byte> outC1 = output.Slice(elementSize, elementSize);
        Span<byte> outC2 = output.Slice(2 * elementSize, elementSize);

        using IMemoryOwner<byte> scratchOwner = pool.Rent(4 * elementSize);
        Span<byte> scratch = scratchOwner.Memory.Span[..(4 * elementSize)];
        Span<byte> abcd = scratch[..elementSize];
        Span<byte> zd = scratch.Slice(elementSize, elementSize);
        Span<byte> temp1 = scratch.Slice(2 * elementSize, elementSize);
        Span<byte> temp2 = scratch.Slice(3 * elementSize, elementSize);

        for(int j = 0; j < pairCount; j++)
        {
            ReadOnlySpan<byte> abc0 = abcFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> abc1 = abcFolded.Slice((2 * j + 1) * elementSize, elementSize);
            ReadOnlySpan<byte> z0 = zFolded.Slice(2 * j * elementSize, elementSize);
            ReadOnlySpan<byte> z1 = zFolded.Slice((2 * j + 1) * elementSize, elementSize);

            //Slopes.
            subtract(abc1, abc0, abcd, curve);
            subtract(z1, z0, zd, curve);

            //Product (abc0 + X·abcd)(z0 + X·zd)
            //  = abc0·z0 + X·(abc0·zd + abcd·z0) + X²·abcd·zd.

            //Constant term: abc0·z0.
            multiply(abc0, z0, temp1, curve);
            add(outC0, temp1, outC0, curve);

            //Linear term: abc0·zd + abcd·z0.
            multiply(abc0, zd, temp1, curve);
            multiply(abcd, z0, temp2, curve);
            add(temp1, temp2, temp1, curve);
            add(outC1, temp1, outC1, curve);

            //Quadratic term: abcd·zd.
            multiply(abcd, zd, temp1, curve);
            add(outC2, temp1, outC2, curve);
        }

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.PolynomialCoefficients),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(PolynomialDegree), (object)new PolynomialDegree(2)));

        return new Polynomial(outputOwner, 2, elementSize, curve, tag);
    }


    /// <summary>
    /// Builds the dense evaluation table of <c>eq(τ, ·)</c> over the
    /// boolean hypercube <c>{0,1}^n</c>, where
    /// <c>eq(τ, x) = Π_i [τ_i · x_i + (1 − τ_i) · (1 − x_i)]</c>.
    /// </summary>
    /// <param name="challenges">The challenge vector τ; one scalar per variable.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="pool">The pool to rent the result MLE's buffer from.</param>
    /// <returns>A multilinear extension of <see cref="MultilinearExtension.VariableCount"/> equal to <c>challenges.Length</c>.</returns>
    /// <remarks>
    /// <para>
    /// The table is built incrementally: starting from <c>[1]</c> and
    /// for each challenge <c>τ_i</c>, doubling the table such that the
    /// low half is multiplied by <c>(1 − τ_i)</c> and the high half by
    /// <c>τ_i</c>. The order of iteration over <paramref name="challenges"/>
    /// matches the codebase MLE-storage convention: <c>challenges[0]</c>
    /// addresses bit 0 of the index (the first variable, the one folded
    /// first in a sumcheck).
    /// </para>
    /// <para>
    /// Pure helper — no transcript, no shared state.
    /// </para>
    /// </remarks>
    public static MultilinearExtension BuildEqEvaluations(
        ReadOnlySpan<Scalar> challenges,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarArithmeticBackend? batch = null)
    {
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        for(int i = 0; i < challenges.Length; i++)
        {
            ArgumentNullException.ThrowIfNull(challenges[i]);
        }

        int variableCount = challenges.Length;
        int elementSize = Scalar.SizeBytes;
        int evaluationCount = 1 << variableCount;
        int bufferSize = evaluationCount * elementSize;

        IMemoryOwner<byte> owner = pool.Rent(bufferSize);
        Span<byte> buffer = owner.Memory.Span[..bufferSize];
        buffer.Clear();

        //Initial state: evals = [1], size = 1. Encode the field one as
        //all-zero bytes with the trailing byte set to 0x01.
        buffer.Slice(elementSize - 1, 1)[0] = 0x01;

        int size = 1;
        if(batch is not null && variableCount > 0)
        {
            //The doubling levels are contiguous halves: high = low ∘ τ_i and
            //low = low − high run as whole-level batch calls against a
            //broadcast τ column — byte-identical, exactly the per-element
            //recurrence.
            int broadcastBytes = (evaluationCount / 2) * elementSize;
            using IMemoryOwner<byte> broadcastOwner = pool.Rent(broadcastBytes);
            Span<byte> broadcast = broadcastOwner.Memory.Span[..broadcastBytes];
            for(int i = 0; i < variableCount; i++)
            {
                ReadOnlySpan<byte> tau = challenges[i].AsReadOnlySpan();
                for(int k = 0; k < size; k++)
                {
                    tau.CopyTo(broadcast.Slice(k * elementSize, elementSize));
                }

                int halfBytes = size * elementSize;
                Span<byte> low = buffer[..halfBytes];
                Span<byte> high = buffer.Slice(halfBytes, halfBytes);
                batch.BatchMultiply(low, broadcast[..halfBytes], high, size, curve);
                batch.BatchSubtract(low, high, low, size, curve);
                size <<= 1;
            }
        }
        else
        {
            for(int i = 0; i < variableCount; i++)
            {
                ReadOnlySpan<byte> tau = challenges[i].AsReadOnlySpan();
                //For each pair (low at slot k, high at slot size + k):
                //  high = low · τ_i,
                //  low  = low − high (which equals low · (1 − τ_i)).
                for(int k = 0; k < size; k++)
                {
                    Span<byte> low = buffer.Slice(k * elementSize, elementSize);
                    Span<byte> high = buffer.Slice((size + k) * elementSize, elementSize);
                    multiply(low, tau, high, curve);
                    subtract(low, high, low, curve);
                }
                size <<= 1;
            }
        }

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.MultilinearExtension),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(MultilinearExtensionDimensions), (object)new MultilinearExtensionDimensions(variableCount, evaluationCount)));

        return new MultilinearExtension(owner, variableCount, elementSize, curve, tag);
    }


    //Pairs per batched block: bounds the pooled column scratch (the relaxed
    //outer path gathers 17 columns, ≈ 0.5 MB at this size) while keeping each
    //BatchMultiply call long enough to amortise its lane setup.
    private const int BatchBlockPairCount = 1024;


    //The batched twin of the relaxed outer loop: the strided per-pair operands
    //are gathered into contiguous columns and the twelve per-pair products
    //become twelve BatchMultiply calls per block. Adds and subtracts stay on
    //the per-element delegates — they are an order cheaper than the modular
    //multiplies on every wired backend (batching them is a recorded follow-on).
    //Field operations are exact and the coefficient accumulation is
    //commutative, so the result is byte-identical to the per-element path.
    private static Polynomial ComputeOuterRoundPolynomialRelaxedBatched(
        ReadOnlySpan<byte> azFolded,
        ReadOnlySpan<byte> bzFolded,
        ReadOnlySpan<byte> czFolded,
        ReadOnlySpan<byte> eFolded,
        ReadOnlySpan<byte> eqFolded,
        ReadOnlySpan<byte> uBytes,
        int pairCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarArithmeticBackend batch,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int elementSize = Scalar.SizeBytes;

        IMemoryOwner<byte> outputOwner = pool.Rent(4 * elementSize);
        Span<byte> output = outputOwner.Memory.Span[..(4 * elementSize)];
        output.Clear();
        Span<byte> outC0 = output[..elementSize];
        Span<byte> outC1 = output.Slice(elementSize, elementSize);
        Span<byte> outC2 = output.Slice(2 * elementSize, elementSize);
        Span<byte> outC3 = output.Slice(3 * elementSize, elementSize);

        //Column layout: az0 azd bz0 bzd cz0 czd e0 ed eq0 eqd uRep ac0 ac1 ac2
        //p1 p2 p3 — seventeen blockSize-long columns in one rent.
        int blockSize = Math.Min(pairCount, BatchBlockPairCount);
        int columnBytes = blockSize * elementSize;
        using IMemoryOwner<byte> columnsOwner = pool.Rent(17 * columnBytes);
        Span<byte> columns = columnsOwner.Memory.Span[..(17 * columnBytes)];
        Span<byte> az0 = columns[..columnBytes];
        Span<byte> azd = columns.Slice(1 * columnBytes, columnBytes);
        Span<byte> bz0 = columns.Slice(2 * columnBytes, columnBytes);
        Span<byte> bzd = columns.Slice(3 * columnBytes, columnBytes);
        Span<byte> cz0 = columns.Slice(4 * columnBytes, columnBytes);
        Span<byte> czd = columns.Slice(5 * columnBytes, columnBytes);
        Span<byte> e0 = columns.Slice(6 * columnBytes, columnBytes);
        Span<byte> ed = columns.Slice(7 * columnBytes, columnBytes);
        Span<byte> eq0 = columns.Slice(8 * columnBytes, columnBytes);
        Span<byte> eqd = columns.Slice(9 * columnBytes, columnBytes);
        Span<byte> uRep = columns.Slice(10 * columnBytes, columnBytes);
        Span<byte> ac0 = columns.Slice(11 * columnBytes, columnBytes);
        Span<byte> ac1 = columns.Slice(12 * columnBytes, columnBytes);
        Span<byte> ac2 = columns.Slice(13 * columnBytes, columnBytes);
        Span<byte> p1 = columns.Slice(14 * columnBytes, columnBytes);
        Span<byte> p2 = columns.Slice(15 * columnBytes, columnBytes);
        Span<byte> p3 = columns.Slice(16 * columnBytes, columnBytes);

        //u is constant in the fold variable; broadcast it once.
        for(int j = 0; j < blockSize; j++)
        {
            uBytes.CopyTo(uRep.Slice(j * elementSize, elementSize));
        }

        for(int blockStart = 0; blockStart < pairCount; blockStart += blockSize)
        {
            int n = Math.Min(blockSize, pairCount - blockStart);
            int usedBytes = n * elementSize;

            //Gather: low halves copied, slopes formed in place.
            for(int j = 0; j < n; j++)
            {
                int low = 2 * (blockStart + j) * elementSize;
                int high = low + elementSize;
                int slot = j * elementSize;
                azFolded.Slice(low, elementSize).CopyTo(az0.Slice(slot, elementSize));
                subtract(azFolded.Slice(high, elementSize), az0.Slice(slot, elementSize), azd.Slice(slot, elementSize), curve);
                bzFolded.Slice(low, elementSize).CopyTo(bz0.Slice(slot, elementSize));
                subtract(bzFolded.Slice(high, elementSize), bz0.Slice(slot, elementSize), bzd.Slice(slot, elementSize), curve);
                czFolded.Slice(low, elementSize).CopyTo(cz0.Slice(slot, elementSize));
                subtract(czFolded.Slice(high, elementSize), cz0.Slice(slot, elementSize), czd.Slice(slot, elementSize), curve);
                eFolded.Slice(low, elementSize).CopyTo(e0.Slice(slot, elementSize));
                subtract(eFolded.Slice(high, elementSize), e0.Slice(slot, elementSize), ed.Slice(slot, elementSize), curve);
                eqFolded.Slice(low, elementSize).CopyTo(eq0.Slice(slot, elementSize));
                subtract(eqFolded.Slice(high, elementSize), eq0.Slice(slot, elementSize), eqd.Slice(slot, elementSize), curve);
            }

            //ac0 = az0·bz0 − u·cz0 − e0; the column compositions run on the
            //bundle's batch subtract.
            batch.BatchMultiply(az0[..usedBytes], bz0[..usedBytes], p1[..usedBytes], n, curve);
            batch.BatchMultiply(uRep[..usedBytes], cz0[..usedBytes], p2[..usedBytes], n, curve);
            batch.BatchSubtract(p1[..usedBytes], p2[..usedBytes], ac0[..usedBytes], n, curve);
            batch.BatchSubtract(ac0[..usedBytes], e0[..usedBytes], ac0[..usedBytes], n, curve);

            //ac1 = (az0·bzd + azd·bz0) − u·czd − ed.
            batch.BatchMultiply(az0[..usedBytes], bzd[..usedBytes], p1[..usedBytes], n, curve);
            batch.BatchMultiply(azd[..usedBytes], bz0[..usedBytes], p2[..usedBytes], n, curve);
            batch.BatchMultiply(uRep[..usedBytes], czd[..usedBytes], p3[..usedBytes], n, curve);
            batch.BatchAdd(p1[..usedBytes], p2[..usedBytes], ac1[..usedBytes], n, curve);
            batch.BatchSubtract(ac1[..usedBytes], p3[..usedBytes], ac1[..usedBytes], n, curve);
            batch.BatchSubtract(ac1[..usedBytes], ed[..usedBytes], ac1[..usedBytes], n, curve);

            //ac2 = azd·bzd.
            batch.BatchMultiply(azd[..usedBytes], bzd[..usedBytes], ac2[..usedBytes], n, curve);

            //Coefficient contributions: (eq0 + X·eqd)(ac0 + X·ac1 + X²·ac2).
            batch.BatchMultiply(eq0[..usedBytes], ac0[..usedBytes], p1[..usedBytes], n, curve);
            AccumulateColumn(outC0, p1, n, add, curve);

            batch.BatchMultiply(eq0[..usedBytes], ac1[..usedBytes], p1[..usedBytes], n, curve);
            batch.BatchMultiply(eqd[..usedBytes], ac0[..usedBytes], p2[..usedBytes], n, curve);
            AccumulateColumnPair(outC1, p1, p2, n, add, curve);

            batch.BatchMultiply(eq0[..usedBytes], ac2[..usedBytes], p1[..usedBytes], n, curve);
            batch.BatchMultiply(eqd[..usedBytes], ac1[..usedBytes], p2[..usedBytes], n, curve);
            AccumulateColumnPair(outC2, p1, p2, n, add, curve);

            batch.BatchMultiply(eqd[..usedBytes], ac2[..usedBytes], p1[..usedBytes], n, curve);
            AccumulateColumn(outC3, p1, n, add, curve);
        }

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.PolynomialCoefficients),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(PolynomialDegree), (object)new PolynomialDegree(3)));

        return new Polynomial(outputOwner, 3, elementSize, curve, tag);
    }


    //The batched twin of the inner loop: four products per pair become four
    //BatchMultiply calls per block; see the relaxed outer twin for the
    //byte-identity argument.
    private static Polynomial ComputeInnerRoundPolynomialBatched(
        ReadOnlySpan<byte> abcFolded,
        ReadOnlySpan<byte> zFolded,
        int pairCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarArithmeticBackend batch,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int elementSize = Scalar.SizeBytes;

        IMemoryOwner<byte> outputOwner = pool.Rent(3 * elementSize);
        Span<byte> output = outputOwner.Memory.Span[..(3 * elementSize)];
        output.Clear();
        Span<byte> outC0 = output[..elementSize];
        Span<byte> outC1 = output.Slice(elementSize, elementSize);
        Span<byte> outC2 = output.Slice(2 * elementSize, elementSize);

        //Columns: abc0 abcd z0 zd p1 p2.
        int blockSize = Math.Min(pairCount, BatchBlockPairCount);
        int columnBytes = blockSize * elementSize;
        using IMemoryOwner<byte> columnsOwner = pool.Rent(6 * columnBytes);
        Span<byte> columns = columnsOwner.Memory.Span[..(6 * columnBytes)];
        Span<byte> abc0 = columns[..columnBytes];
        Span<byte> abcd = columns.Slice(1 * columnBytes, columnBytes);
        Span<byte> z0 = columns.Slice(2 * columnBytes, columnBytes);
        Span<byte> zd = columns.Slice(3 * columnBytes, columnBytes);
        Span<byte> p1 = columns.Slice(4 * columnBytes, columnBytes);
        Span<byte> p2 = columns.Slice(5 * columnBytes, columnBytes);

        for(int blockStart = 0; blockStart < pairCount; blockStart += blockSize)
        {
            int n = Math.Min(blockSize, pairCount - blockStart);
            int usedBytes = n * elementSize;

            for(int j = 0; j < n; j++)
            {
                int low = 2 * (blockStart + j) * elementSize;
                int high = low + elementSize;
                int slot = j * elementSize;
                abcFolded.Slice(low, elementSize).CopyTo(abc0.Slice(slot, elementSize));
                subtract(abcFolded.Slice(high, elementSize), abc0.Slice(slot, elementSize), abcd.Slice(slot, elementSize), curve);
                zFolded.Slice(low, elementSize).CopyTo(z0.Slice(slot, elementSize));
                subtract(zFolded.Slice(high, elementSize), z0.Slice(slot, elementSize), zd.Slice(slot, elementSize), curve);
            }

            //(abc0 + X·abcd)(z0 + X·zd).
            batch.BatchMultiply(abc0[..usedBytes], z0[..usedBytes], p1[..usedBytes], n, curve);
            AccumulateColumn(outC0, p1, n, add, curve);

            batch.BatchMultiply(abc0[..usedBytes], zd[..usedBytes], p1[..usedBytes], n, curve);
            batch.BatchMultiply(abcd[..usedBytes], z0[..usedBytes], p2[..usedBytes], n, curve);
            AccumulateColumnPair(outC1, p1, p2, n, add, curve);

            batch.BatchMultiply(abcd[..usedBytes], zd[..usedBytes], p1[..usedBytes], n, curve);
            AccumulateColumn(outC2, p1, n, add, curve);
        }

        Tag tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.PolynomialCoefficients),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(PolynomialDegree), (object)new PolynomialDegree(2)));

        return new Polynomial(outputOwner, 2, elementSize, curve, tag);
    }


    private static void AccumulateColumn(Span<byte> accumulator, ReadOnlySpan<byte> column, int count, ScalarAddDelegate add, CurveParameterSet curve)
    {
        int elementSize = Scalar.SizeBytes;
        for(int j = 0; j < count; j++)
        {
            add(accumulator, column.Slice(j * elementSize, elementSize), accumulator, curve);
        }
    }


    private static void AccumulateColumnPair(Span<byte> accumulator, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, int count, ScalarAddDelegate add, CurveParameterSet curve)
    {
        int elementSize = Scalar.SizeBytes;
        for(int j = 0; j < count; j++)
        {
            add(accumulator, first.Slice(j * elementSize, elementSize), accumulator, curve);
            add(accumulator, second.Slice(j * elementSize, elementSize), accumulator, curve);
        }
    }


    private static void ValidateMleByteLength(
        ReadOnlySpan<byte> mle,
        int variableCount,
        int elementSize,
        string parameterName)
    {
        int expected = (1 << variableCount) * elementSize;
        if(mle.Length != expected)
        {
            throw new ArgumentException(
                $"MLE span must be {expected} bytes for variableCount = {variableCount}; received {mle.Length}.",
                parameterName);
        }
    }
}