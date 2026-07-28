using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// Selects <c>array[index]</c> from a fixed array of element wires by an element-valued index, a
/// faithful port of google/longfellow-zk's <c>EltMuxer&lt;Logic, N, PP&gt;</c>
/// (<c>circuits/logic/bit_plucker.h</c>): construction interpolates the even-spaced Lagrange basis
/// once and folds it against the array into <see cref="ElementCount"/> monomial coefficient wires,
/// so every subsequent <see cref="Mux"/> costs one <see cref="LongfellowCircuitPolynomial.PowersOfX"/>
/// chain and a dot product regardless of how many times the same array is muxed.
/// </summary>
/// <remarks>
/// The index is not a bit vector but a field element drawn from the plucker point set
/// <c>{2i − (PointSetSize − 1)}</c>: the same encoding <see cref="LongfellowBitPlucker.PluckerPoint"/>
/// defines, shared so witness-side encoders agree byte for byte. Instantiating with
/// <see cref="ElementCount"/> one larger than <see cref="PointSetSize"/> (the reference's
/// <c>EltMuxer&lt;Logic, 9, 8&gt;</c>) keeps the eight-point index encoding while interpolating
/// through nine points, which is how the ECDSA circuit range-checks an advice digit to <c>[0, 7]</c>
/// with a single degree-eight identity.
/// </remarks>
internal sealed class LongfellowEltMuxer
{
    private readonly LongfellowLogicBackend backend;
    private readonly LongfellowCircuitPolynomial polynomial;
    private readonly int[] coefficients;

    /// <summary>The array length <c>N</c> (the reference's <c>kN</c>), also the interpolation point count.</summary>
    public int ElementCount { get; }

    /// <summary>The point-set parameter <c>PP</c> (the reference's <c>kPP</c>) defining the index encoding.</summary>
    public int PointSetSize { get; }


    /// <summary>
    /// Constructs the muxer over an array of element wires, interpolating one even-spaced Lagrange
    /// basis polynomial per array entry and accumulating <c>basis_i[j] · array[i]</c> into the
    /// <c>j</c>-th monomial coefficient wire, exactly as the reference constructor does.
    /// </summary>
    /// <param name="logic">The gadget layer this muxer builds on.</param>
    /// <param name="array">The element wires to select among.</param>
    /// <param name="pointSetSize">The point-set parameter <c>PP</c>; zero selects the reference's default of the array length.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> or <paramref name="array"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="array"/> is empty or longer than the construction-cost cap, or when <paramref name="pointSetSize"/> is negative.</exception>
    public LongfellowEltMuxer(LongfellowLogic logic, int[] array, int pointSetSize = 0)
    {
        ArgumentNullException.ThrowIfNull(logic);
        ArgumentNullException.ThrowIfNull(array);
        ArgumentOutOfRangeException.ThrowIfLessThan(array.Length, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(pointSetSize);

        //The reference instantiates muxers only up to nine entries (the ECDSA range check), and the
        //construction-time interpolation grows as the square of the entry count; the cap keeps a
        //hostile length from driving an unbounded allocation.
        const int MaxElementCount = 16;
        ArgumentOutOfRangeException.ThrowIfGreaterThan(array.Length, MaxElementCount);

        backend = logic.Backend;
        LongfellowLogicFieldOperations field = logic.Field;
        polynomial = new LongfellowCircuitPolynomial(backend);

        ElementCount = array.Length;
        PointSetSize = pointSetSize == 0 ? array.Length : pointSetSize;

        var points = new ReadOnlyMemory<byte>[ElementCount];
        for(int i = 0; i < ElementCount; i++)
        {
            points[i] = LongfellowBitPlucker.PluckerPoint(field, PointSetSize, i);
        }

        coefficients = new int[ElementCount];
        for(int i = 0; i < ElementCount; i++)
        {
            coefficients[i] = backend.Constant(field.Compiler.Zero.Span);
        }

        for(int i = 0; i < ElementCount; i++)
        {
            var values = new ReadOnlyMemory<byte>[ElementCount];
            for(int j = 0; j < ElementCount; j++)
            {
                values[j] = field.OfScalar(j == i ? 1UL : 0UL);
            }

            ReadOnlyMemory<byte>[] basis = LongfellowMonomialInterpolation.MonomialOfLagrange(field, values, points);
            for(int j = 0; j < ElementCount; j++)
            {
                int basisWire = backend.Constant(basis[j].Span);
                int scaled = backend.Mul(basisWire, array[i]);
                coefficients[j] = backend.Add(coefficients[j], scaled);
            }
        }
    }


    /// <summary>
    /// The reference's <c>mux</c>: evaluates the precomputed coefficient wires at
    /// <paramref name="index"/> via a <see cref="LongfellowCircuitPolynomial.PowersOfX"/> chain and a
    /// dot product, yielding the wire holding <c>array[index]</c> for any index drawn from the
    /// point set.
    /// </summary>
    /// <param name="index">The wire holding the plucker-point-encoded index element.</param>
    /// <returns>The wire holding the selected array entry.</returns>
    public int Mux(int index)
    {
        var powers = new int[ElementCount];
        polynomial.PowersOfX(powers, index);

        int result = backend.Constant(backend.Field.Compiler.Zero.Span);
        for(int i = 0; i < ElementCount; i++)
        {
            int term = backend.Mul(coefficients[i], powers[i]);
            result = backend.Add(result, term);
        }

        return result;
    }
}
