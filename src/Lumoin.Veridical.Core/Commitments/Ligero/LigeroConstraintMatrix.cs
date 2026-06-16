using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// Builds the dot-product test's constraint matrix <c>A</c> — the
/// <c>inner_product_vector</c> of the Ligero argument — from the public linear
/// and quadratic constraints folded with the verifier's challenges
/// <c>αl</c> and <c>αq</c>. Prover and verifier build the identical matrix from
/// the identical challenges, so it lives here as one shared routine rather than
/// being duplicated on each side.
/// </summary>
/// <remarks>
/// <para>
/// <c>A</c> is conceptually <c>[nwqrow, w]</c> — one row of <c>w</c> coefficients
/// for each of the tableau's witness-and-quadratic message rows — stored flat,
/// row-major, in one pooled buffer of <c>nwqrow · w</c> canonical scalars. Row
/// <c>i</c> of <c>A</c> pairs with tableau row <c>FirstWitnessRowIndex + i</c> in
/// the dot-product test: the test forms <c>Σ_i ⟨A[i,:], payload_i⟩</c> over the
/// witness blocks and checks it against <c>Σ_c b[c]·αl[c]</c>.
/// </para>
/// <para>
/// The first <c>nwrow · w</c> entries are addressed by witness index (witness
/// <c>j</c> lives at flat index <c>j</c>); the remaining
/// <c>3 · nqtriples · w</c> entries are the quadratic-operand blocks
/// <c>Ax | Ay | Az</c>. The linear terms accumulate <c>A[w] += k · αl[c]</c>;
/// the quadratic routing binds each operand to its witness by
/// <c>Ax[iw] += αq[iw][0]</c> and <c>A[x] -= αq[iw][0]</c> (and likewise for
/// <c>y</c>, <c>z</c>), so the operand value and the witness value cancel in the
/// dot product exactly when they agree.
/// </para>
/// </remarks>
internal static class LigeroConstraintMatrix
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Builds <c>A</c> into a freshly rented buffer of
    /// <c>WitnessQuadraticRowCount · WitnessPerRow</c> canonical scalars; the
    /// caller owns its disposal.
    /// </summary>
    /// <param name="parameters">The tableau layout.</param>
    /// <param name="linearConstraintCount">The number of linear constraints <c>nl</c> (the length of <paramref name="alphaLinear"/>).</param>
    /// <param name="linearConstraints">The linear terms; each names a constraint, a witness and a coefficient.</param>
    /// <param name="quadraticConstraints">The multiplication constraints; exactly <see cref="LigeroParameters.QuadraticConstraintCount"/> of them.</param>
    /// <param name="alphaLinear">The linear-constraint challenges <c>αl</c>; <c>nl</c> scalars.</param>
    /// <param name="alphaQuadratic">The quadratic-constraint challenges <c>αq</c>; <c>3 · nq</c> scalars, triple <c>iw</c> at offsets <c>3·iw .. 3·iw+2</c>.</param>
    /// <param name="add">Scalar-add backend.</param>
    /// <param name="subtract">Scalar-subtract backend.</param>
    /// <param name="multiply">Scalar-multiply backend.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">Pool to rent the matrix buffer from.</param>
    /// <returns>The pooled <c>A</c> buffer; the caller disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a backend, the parameters or the pool is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a challenge span length does not match.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a term names an index outside its range.</exception>
    public static IMemoryOwner<byte> Build(
        LigeroParameters parameters,
        int linearConstraintCount,
        ReadOnlySpan<LigeroLinearConstraint> linearConstraints,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        ReadOnlySpan<byte> alphaLinear,
        ReadOnlySpan<byte> alphaQuadratic,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(linearConstraintCount);

        int w = parameters.WitnessPerRow;
        int nwrow = parameters.WitnessRowCount;
        int nqtriples = parameters.QuadraticTripleCount;
        int witnessBlock = nwrow * w;
        int total = parameters.WitnessQuadraticRowCount * w;

        if(alphaLinear.Length != linearConstraintCount * ScalarSize)
        {
            throw new ArgumentException($"αl must be {linearConstraintCount * ScalarSize} bytes; received {alphaLinear.Length}.", nameof(alphaLinear));
        }

        if(quadraticConstraints.Length != parameters.QuadraticConstraintCount)
        {
            throw new ArgumentException($"Expected {parameters.QuadraticConstraintCount} quadratic constraints; received {quadraticConstraints.Length}.", nameof(quadraticConstraints));
        }

        if(alphaQuadratic.Length != 3 * parameters.QuadraticConstraintCount * ScalarSize)
        {
            throw new ArgumentException($"αq must be {3 * parameters.QuadraticConstraintCount * ScalarSize} bytes; received {alphaQuadratic.Length}.", nameof(alphaQuadratic));
        }

        IMemoryOwner<byte> owner = pool.Rent(total * ScalarSize);
        try
        {
            Span<byte> matrix = owner.Memory.Span[..(total * ScalarSize)];
            matrix.Clear();

            Span<byte> product = stackalloc byte[ScalarSize];
            Span<byte> accumulator = stackalloc byte[ScalarSize];

            //Linear terms: A[witnessIndex] += coefficient · αl[constraintIndex].
            foreach(LigeroLinearConstraint term in linearConstraints)
            {
                if((uint)term.ConstraintIndex >= (uint)linearConstraintCount)
                {
                    throw new ArgumentOutOfRangeException(nameof(linearConstraints), $"Linear term constraint index {term.ConstraintIndex} is outside [0, {linearConstraintCount}).");
                }

                if((uint)term.WitnessIndex >= (uint)parameters.WitnessCount)
                {
                    throw new ArgumentOutOfRangeException(nameof(linearConstraints), $"Linear term witness index {term.WitnessIndex} is outside [0, {parameters.WitnessCount}).");
                }

                if(term.Coefficient.Length != ScalarSize)
                {
                    throw new ArgumentException($"Linear term coefficient must be {ScalarSize} bytes; received {term.Coefficient.Length}.", nameof(linearConstraints));
                }

                multiply(term.Coefficient.Span, AlphaAt(alphaLinear, term.ConstraintIndex), product, curve);
                AccumulateAdd(matrix, term.WitnessIndex, product, accumulator, add, curve);
            }

            //Quadratic routing: bind each operand row to its witness. The operand
            //blocks Ax | Ay | Az follow the witness block; constraint iw lands at
            //the iw-th slot of each.
            int axBase = witnessBlock;
            int ayBase = axBase + (nqtriples * w);
            int azBase = ayBase + (nqtriples * w);
            for(int iw = 0; iw < quadraticConstraints.Length; iw++)
            {
                LigeroQuadraticConstraint constraint = quadraticConstraints[iw];
                RouteOperand(matrix, axBase + iw, constraint.XIndex, AlphaQuadraticAt(alphaQuadratic, iw, 0), accumulator, add, subtract, curve);
                RouteOperand(matrix, ayBase + iw, constraint.YIndex, AlphaQuadraticAt(alphaQuadratic, iw, 1), accumulator, add, subtract, curve);
                RouteOperand(matrix, azBase + iw, constraint.ZIndex, AlphaQuadraticAt(alphaQuadratic, iw, 2), accumulator, add, subtract, curve);
            }

            return owner;
        }
        catch
        {
            owner.Memory.Span[..(total * ScalarSize)].Clear();
            owner.Dispose();
            throw;
        }
    }


    //Ax[operandSlot] += alpha; A[witnessIndex] -= alpha. The operand value and
    //the witness value then cancel in the dot product iff they are equal.
    private static void RouteOperand(
        Span<byte> matrix,
        int operandSlot,
        int witnessIndex,
        ReadOnlySpan<byte> alpha,
        Span<byte> accumulator,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        CurveParameterSet curve)
    {
        AccumulateAdd(matrix, operandSlot, alpha, accumulator, add, curve);

        subtract(SlotAt(matrix, witnessIndex), alpha, accumulator, curve);
        accumulator.CopyTo(SlotAt(matrix, witnessIndex));
    }


    //matrix[slot] += addend, routed through a scratch because the backends do
    //not promise alias-safe in-place accumulation.
    private static void AccumulateAdd(
        Span<byte> matrix,
        int slot,
        ReadOnlySpan<byte> addend,
        Span<byte> accumulator,
        ScalarAddDelegate add,
        CurveParameterSet curve)
    {
        add(SlotAt(matrix, slot), addend, accumulator, curve);
        accumulator.CopyTo(SlotAt(matrix, slot));
    }


    private static Span<byte> SlotAt(Span<byte> matrix, int slot) => matrix.Slice(slot * ScalarSize, ScalarSize);


    private static ReadOnlySpan<byte> AlphaAt(ReadOnlySpan<byte> alphaLinear, int constraintIndex) =>
        alphaLinear.Slice(constraintIndex * ScalarSize, ScalarSize);


    private static ReadOnlySpan<byte> AlphaQuadraticAt(ReadOnlySpan<byte> alphaQuadratic, int constraintIndex, int component) =>
        alphaQuadratic.Slice(((3 * constraintIndex) + component) * ScalarSize, ScalarSize);
}
