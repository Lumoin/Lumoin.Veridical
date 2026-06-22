using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;

/// <summary>
/// Short-Weierstrass elliptic-curve gadgets expressed as Ligero linear + quadratic
/// constraints over a field, composed as extension methods on
/// <see cref="LigeroConstraintSystemBuilder"/> and parameterised by a precomputed
/// <see cref="WeierstrassCurve"/>. The curve is short-Weierstrass
/// <c>y² = x³ + a·x + b</c>.
/// </summary>
/// <remarks>
/// <para>
/// The affine addition and doubling gadgets (and the on-curve check) follow the
/// slope identities and are the only ones that use modular inversion. The
/// complete projective addition follows the Renes–Costello–Batina formula (IACR
/// ePrint 2015/1060, Algorithm 1, general <c>a</c>, with <c>k3b = 3·b</c>); it is
/// an unconditional polynomial identity — valid for the identity
/// <c>O = (0:1:0)</c>, <c>P + P</c>, and <c>P + (−P) = O</c> — and is inversion-
/// free, so the witnessed ladder and multi-scalar gadgets that build on it need
/// no edge-case branching.
/// </para>
/// </remarks>
internal static class WeierstrassGadgetExtensions
{
    private const int ScalarSize = Scalar.SizeBytes;


    //Affine addition (x1,y1)+(x2,y2), generic case P ≠ ±Q. λ = (y2−y1)/(x2−x1);
    //x3 = λ² − x1 − x2; y3 = λ(x1 − x3) − y1. Returns the (x3,y3) wires.
    public static (int X3, int Y3) AddAffinePointAddition(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, int x1, int y1, int x2, int y2)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        Span<byte> dxValue = stackalloc byte[ScalarSize];
        builder.SubtractValues(builder.Value(x2), builder.Value(x1), dxValue);
        Span<byte> dyValue = stackalloc byte[ScalarSize];
        builder.SubtractValues(builder.Value(y2), builder.Value(y1), dyValue);
        Span<byte> inverseDx = stackalloc byte[ScalarSize];
        builder.InvertValue(dxValue, inverseDx);
        Span<byte> lambdaValue = stackalloc byte[ScalarSize];
        builder.MultiplyValues(dyValue, inverseDx, lambdaValue);

        int dx = builder.AddWire(dxValue);
        int dy = builder.AddWire(dyValue);
        int lambda = builder.AddWire(lambdaValue);

        //dx = x2 − x1; dy = y2 − y1.
        builder.AddLinear(curve.Zero.Span, [Term(dx, curve.One), Term(x2, curve.NegativeOne), Term(x1, curve.One)]);
        builder.AddLinear(curve.Zero.Span, [Term(dy, curve.One), Term(y2, curve.NegativeOne), Term(y1, curve.One)]);

        //λ·dx = dy.
        int lambdaDx = builder.Multiply(lambda, dx);
        builder.AddLinear(curve.Zero.Span, [Term(lambdaDx, curve.One), Term(dy, curve.NegativeOne)]);

        //λ² = x3 + x1 + x2.
        int lambdaSquared = builder.Multiply(lambda, lambda);
        Span<byte> lambdaSquaredMinusX1 = stackalloc byte[ScalarSize];
        builder.SubtractValues(builder.Value(lambdaSquared), builder.Value(x1), lambdaSquaredMinusX1);
        Span<byte> x3Value = stackalloc byte[ScalarSize];
        builder.SubtractValues(lambdaSquaredMinusX1, builder.Value(x2), x3Value);
        int x3 = builder.AddWire(x3Value);
        builder.AddLinear(curve.Zero.Span, [Term(lambdaSquared, curve.One), Term(x3, curve.NegativeOne), Term(x1, curve.NegativeOne), Term(x2, curve.NegativeOne)]);

        //x1 − x3; λ·(x1 − x3) = y3 + y1.
        Span<byte> x1MinusX3Value = stackalloc byte[ScalarSize];
        builder.SubtractValues(builder.Value(x1), x3Value, x1MinusX3Value);
        int x1MinusX3 = builder.AddWire(x1MinusX3Value);
        builder.AddLinear(curve.Zero.Span, [Term(x1MinusX3, curve.One), Term(x1, curve.NegativeOne), Term(x3, curve.One)]);
        int lambdaX1MinusX3 = builder.Multiply(lambda, x1MinusX3);
        Span<byte> y3Value = stackalloc byte[ScalarSize];
        builder.SubtractValues(builder.Value(lambdaX1MinusX3), builder.Value(y1), y3Value);
        int y3 = builder.AddWire(y3Value);
        builder.AddLinear(curve.Zero.Span, [Term(lambdaX1MinusX3, curve.One), Term(y3, curve.NegativeOne), Term(y1, curve.NegativeOne)]);

        builder.SetLastOutput(y3);

        return (x3, y3);
    }


    //Affine doubling of (x,y). λ = (3x² + a)/(2y); x3 = λ² − 2x; y3 = λ(x − x3) − y.
    public static (int X3, int Y3) AddAffinePointDoubling(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, int x, int y)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        int xSquared = builder.Multiply(x, x);

        //num = 3·x² + a.
        Span<byte> threeXSquared = stackalloc byte[ScalarSize];
        builder.MultiplyValues(curve.Three.Span, builder.Value(xSquared), threeXSquared);
        Span<byte> numeratorValue = stackalloc byte[ScalarSize];
        builder.AddValues(threeXSquared, curve.A.Span, numeratorValue);
        int numerator = builder.AddWire(numeratorValue);
        builder.AddLinear(curve.A.Span, [Term(numerator, curve.One), Term(xSquared, curve.NegativeThree)]);

        //twoY = 2·y.
        Span<byte> twoYValue = stackalloc byte[ScalarSize];
        builder.AddValues(builder.Value(y), builder.Value(y), twoYValue);
        int twoY = builder.AddWire(twoYValue);
        builder.AddLinear(curve.Zero.Span, [Term(twoY, curve.One), Term(y, curve.NegativeTwo)]);

        //λ = num / twoY; λ·twoY = num.
        Span<byte> inverseTwoY = stackalloc byte[ScalarSize];
        builder.InvertValue(twoYValue, inverseTwoY);
        Span<byte> lambdaValue = stackalloc byte[ScalarSize];
        builder.MultiplyValues(numeratorValue, inverseTwoY, lambdaValue);
        int lambda = builder.AddWire(lambdaValue);
        int lambdaTwoY = builder.Multiply(lambda, twoY);
        builder.AddLinear(curve.Zero.Span, [Term(lambdaTwoY, curve.One), Term(numerator, curve.NegativeOne)]);

        //λ² = x3 + 2x.
        int lambdaSquared = builder.Multiply(lambda, lambda);
        Span<byte> twoX = stackalloc byte[ScalarSize];
        builder.AddValues(builder.Value(x), builder.Value(x), twoX);
        Span<byte> x3Value = stackalloc byte[ScalarSize];
        builder.SubtractValues(builder.Value(lambdaSquared), twoX, x3Value);
        int x3 = builder.AddWire(x3Value);
        builder.AddLinear(curve.Zero.Span, [Term(lambdaSquared, curve.One), Term(x3, curve.NegativeOne), Term(x, curve.NegativeTwo)]);

        //x − x3; λ·(x − x3) = y3 + y.
        Span<byte> xMinusX3Value = stackalloc byte[ScalarSize];
        builder.SubtractValues(builder.Value(x), x3Value, xMinusX3Value);
        int xMinusX3 = builder.AddWire(xMinusX3Value);
        builder.AddLinear(curve.Zero.Span, [Term(xMinusX3, curve.One), Term(x, curve.NegativeOne), Term(x3, curve.One)]);
        int lambdaXMinusX3 = builder.Multiply(lambda, xMinusX3);
        Span<byte> y3Value = stackalloc byte[ScalarSize];
        builder.SubtractValues(builder.Value(lambdaXMinusX3), builder.Value(y), y3Value);
        int y3 = builder.AddWire(y3Value);
        builder.AddLinear(curve.Zero.Span, [Term(lambdaXMinusX3, curve.One), Term(y3, curve.NegativeOne), Term(y, curve.NegativeOne)]);

        builder.SetLastOutput(y3);

        return (x3, y3);
    }


    //Asserts (x,y) is on the curve y² = x³ + a·x + b.
    public static void AddOnCurveCheck(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, int x, int y)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        int xSquared = builder.Multiply(x, x);
        int xCubed = builder.Multiply(xSquared, x);
        int ySquared = builder.Multiply(y, y);

        //ySquared − xCubed − a·x = b.
        builder.AddLinear(curve.B.Span, [Term(ySquared, curve.One), Term(xCubed, curve.NegativeOne), Term(x, curve.NegativeA)]);
        builder.SetLastOutput(ySquared);
    }


    //Affine point negation: returns the wire for −y = −y mod field, constrained by
    //y + (−y) = 0. The x-coordinate is shared, so −(x,y) = (x, −y).
    public static int AddNegateY(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, int y)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        Span<byte> negated = stackalloc byte[ScalarSize];
        builder.Negate(builder.Value(y), negated);
        int negativeY = builder.AddWire(negated);
        builder.AddLinear(curve.Zero.Span, [Term(y, curve.One), Term(negativeY, curve.One)]);

        return negativeY;
    }


    //Complete projective addition (X1:Y1:Z1) + (X2:Y2:Z2), Renes–Costello–Batina
    //Algorithm 1 (general a, k3b = 3·b). Inversion-free: every step is a product
    //(Multiply) or a linear combination (Combine), so it serves both the add and
    //the double steps of the witnessed ladder and the multi-scalar gadget.
    public static (int X3, int Y3, int Z3) AddCompleteProjectiveAddition(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, int x1, int y1, int z1, int x2, int y2, int z2)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        int t0 = builder.Multiply(x1, x2);
        int t1 = builder.Multiply(y1, y2);
        int t2 = builder.Multiply(z1, z2);
        int sumX1Y1 = builder.Combine([Term(x1, curve.One), Term(y1, curve.One)]);
        int sumX2Y2 = builder.Combine([Term(x2, curve.One), Term(y2, curve.One)]);
        int t3Mul = builder.Multiply(sumX1Y1, sumX2Y2);
        int t0PlusT1 = builder.Combine([Term(t0, curve.One), Term(t1, curve.One)]);
        int t3 = builder.Combine([Term(t3Mul, curve.One), Term(t0PlusT1, curve.NegativeOne)]);
        int sumX1Z1 = builder.Combine([Term(x1, curve.One), Term(z1, curve.One)]);
        int sumX2Z2 = builder.Combine([Term(x2, curve.One), Term(z2, curve.One)]);
        int t4Mul = builder.Multiply(sumX1Z1, sumX2Z2);
        int t0PlusT2 = builder.Combine([Term(t0, curve.One), Term(t2, curve.One)]);
        int t4 = builder.Combine([Term(t4Mul, curve.One), Term(t0PlusT2, curve.NegativeOne)]);
        int sumY1Z1 = builder.Combine([Term(y1, curve.One), Term(z1, curve.One)]);
        int sumY2Z2 = builder.Combine([Term(y2, curve.One), Term(z2, curve.One)]);
        int t5Mul = builder.Multiply(sumY1Z1, sumY2Z2);
        int t1PlusT2 = builder.Combine([Term(t1, curve.One), Term(t2, curve.One)]);
        int t5 = builder.Combine([Term(t5Mul, curve.One), Term(t1PlusT2, curve.NegativeOne)]);
        int aT4 = builder.Combine([Term(t4, curve.A)]);
        int k3bT2 = builder.Combine([Term(t2, curve.ThreeB)]);
        int zCenter = builder.Combine([Term(k3bT2, curve.One), Term(aT4, curve.One)]);
        int xCenter = builder.Combine([Term(t1, curve.One), Term(zCenter, curve.NegativeOne)]);
        int zCenter2 = builder.Combine([Term(t1, curve.One), Term(zCenter, curve.One)]);
        int y3FromCenter = builder.Multiply(xCenter, zCenter2);
        int threeT0 = builder.Combine([Term(t0, curve.Three)]);
        int aT2 = builder.Combine([Term(t2, curve.A)]);
        int t1Final = builder.Combine([Term(threeT0, curve.One), Term(aT2, curve.One)]);
        int t0MinusAT2 = builder.Combine([Term(t0, curve.One), Term(aT2, curve.NegativeOne)]);
        int aTimesThat = builder.Combine([Term(t0MinusAT2, curve.A)]);
        int k3bT4 = builder.Combine([Term(t4, curve.ThreeB)]);
        int t4Final = builder.Combine([Term(k3bT4, curve.One), Term(aTimesThat, curve.One)]);
        int crossT1T4 = builder.Multiply(t1Final, t4Final);
        int y3 = builder.Combine([Term(y3FromCenter, curve.One), Term(crossT1T4, curve.One)]);
        int crossT5T4 = builder.Multiply(t5, t4Final);
        int x3FromT3 = builder.Multiply(t3, xCenter);
        int x3 = builder.Combine([Term(x3FromT3, curve.One), Term(crossT5T4, curve.NegativeOne)]);
        int crossT3T1 = builder.Multiply(t3, t1Final);
        int z3FromT5 = builder.Multiply(t5, zCenter2);
        int z3 = builder.Combine([Term(z3FromT5, curve.One), Term(crossT3T1, curve.One)]);

        builder.SetLastOutput(z3);

        return (x3, y3, z3);
    }


    //Point multiplexer: selects the projective point (px:py:pz) when bit = 1 and
    //the identity O = (0:1:0) when bit = 0, as sX = b·px, sY = b·(py−1)+1, sZ = b·pz.
    //The complete addition formula tolerates O, so muxing then adding is unconditional.
    public static (int X, int Y, int Z) AddPointMux(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, int bit, int px, int py, int pz)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        int sX = builder.Multiply(bit, px);
        int bitPy = builder.Multiply(bit, py);
        Span<byte> sYMinusBit = stackalloc byte[ScalarSize];
        builder.SubtractValues(builder.Value(bitPy), builder.Value(bit), sYMinusBit);
        Span<byte> sYValue = stackalloc byte[ScalarSize];
        builder.AddValues(sYMinusBit, curve.One.Span, sYValue);
        int sY = builder.AddWire(sYValue);
        builder.AddLinear(curve.One.Span, [Term(sY, curve.One), Term(bitPy, curve.NegativeOne), Term(bit, curve.One)]);
        int sZ = builder.Multiply(bit, pz);

        return (sX, sY, sZ);
    }


    //General 2:1 projective point mux: returns point b when bit = 0 and point a
    //when bit = 1, coordinate-wise as out = b + bit·(a − b). The bit must be boolean.
    public static (int X, int Y, int Z) MuxPoint(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, int bit, (int X, int Y, int Z) a, (int X, int Y, int Z) b)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        return (MuxCoordinate(builder, curve, bit, a.X, b.X), MuxCoordinate(builder, curve, bit, a.Y, b.Y), MuxCoordinate(builder, curve, bit, a.Z, b.Z));
    }


    //Builds the 8-entry Straus combination table for three projective base points:
    //table[i] = (i&1)·p0 + (i&2)·p1 + (i&4)·p2. Entries are assembled in-circuit by
    //complete additions, so each is an equality-checked witness; the identity entry
    //is the enforced constant O = (0:1:0).
    public static (int X, int Y, int Z)[] AddThreeBaseTable(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, (int X, int Y, int Z) p0, (int X, int Y, int Z) p1, (int X, int Y, int Z) p2)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        var table = new (int X, int Y, int Z)[8];
        table[0] = (builder.AddConstant(curve.Zero.Span), builder.AddConstant(curve.One.Span), builder.AddConstant(curve.Zero.Span));
        table[1] = p0;
        table[2] = p1;
        table[3] = builder.AddCompleteProjectiveAddition(curve, p0.X, p0.Y, p0.Z, p1.X, p1.Y, p1.Z);
        table[4] = p2;
        table[5] = builder.AddCompleteProjectiveAddition(curve, p0.X, p0.Y, p0.Z, p2.X, p2.Y, p2.Z);
        table[6] = builder.AddCompleteProjectiveAddition(curve, p1.X, p1.Y, p1.Z, p2.X, p2.Y, p2.Z);
        table[7] = builder.AddCompleteProjectiveAddition(curve, table[3].X, table[3].Y, table[3].Z, p2.X, p2.Y, p2.Z);

        return table;
    }


    //Selects table[b0 + 2·b1 + 4·b2] with a 7-mux binary tree (resolving b0, then
    //b1, then b2). The bits must be boolean. Constant-time: every entry is touched.
    public static (int X, int Y, int Z) SelectFromTable(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, (int X, int Y, int Z)[] table, int b0, int b1, int b2)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(table);

        (int X, int Y, int Z) m0 = builder.MuxPoint(curve, b0, table[1], table[0]);
        (int X, int Y, int Z) m1 = builder.MuxPoint(curve, b0, table[3], table[2]);
        (int X, int Y, int Z) m2 = builder.MuxPoint(curve, b0, table[5], table[4]);
        (int X, int Y, int Z) m3 = builder.MuxPoint(curve, b0, table[7], table[6]);
        (int X, int Y, int Z) n0 = builder.MuxPoint(curve, b1, m1, m0);
        (int X, int Y, int Z) n1 = builder.MuxPoint(curve, b1, m3, m2);

        return builder.MuxPoint(curve, b2, n1, n0);
    }


    //Witnessed double-and-add ladder computing [k]·P for the scalar whose bits are
    //given most-significant first. Each step doubles the accumulator and
    //conditionally adds P through the mux; the complete formula serves both, so no
    //edge-case branching and every intermediate point is equality-checked.
    public static (int X, int Y, int Z) AddScalarMultiplyLadder(this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, ReadOnlySpan<int> bitsMostSignificantFirst, int px, int py, int pz)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        (int X, int Y, int Z) accumulator = (builder.AddConstant(curve.Zero.Span), builder.AddConstant(curve.One.Span), builder.AddConstant(curve.Zero.Span));
        for(int i = 0; i < bitsMostSignificantFirst.Length; i++)
        {
            accumulator = builder.AddCompleteProjectiveAddition(curve, accumulator.X, accumulator.Y, accumulator.Z, accumulator.X, accumulator.Y, accumulator.Z);
            (int X, int Y, int Z) selected = builder.AddPointMux(curve, bitsMostSignificantFirst[i], px, py, pz);
            accumulator = builder.AddCompleteProjectiveAddition(curve, accumulator.X, accumulator.Y, accumulator.Z, selected.X, selected.Y, selected.Z);
        }

        return accumulator;
    }


    //Witnessed three-scalar multi-scalar multiply acc = [k0]·P0 + [k1]·P1 + [k2]·P2
    //via Straus/Shamir: the 8-point table is built once, then for each bit position
    //(most-significant first) the accumulator is doubled and the table entry indexed
    //by the three scalars' i-th bits is added. Bit arrays are most-significant first
    //and of equal length.
    public static (int X, int Y, int Z) AddThreeScalarMultiScalarMultiply(
        this LigeroConstraintSystemBuilder builder, WeierstrassCurve curve,
        (int X, int Y, int Z) p0, (int X, int Y, int Z) p1, (int X, int Y, int Z) p2,
        ReadOnlySpan<int> bits0MostSignificantFirst, ReadOnlySpan<int> bits1MostSignificantFirst, ReadOnlySpan<int> bits2MostSignificantFirst)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(curve);

        (int X, int Y, int Z)[] table = builder.AddThreeBaseTable(curve, p0, p1, p2);
        (int X, int Y, int Z) accumulator = (builder.AddConstant(curve.Zero.Span), builder.AddConstant(curve.One.Span), builder.AddConstant(curve.Zero.Span));
        for(int i = 0; i < bits0MostSignificantFirst.Length; i++)
        {
            accumulator = builder.AddCompleteProjectiveAddition(curve, accumulator.X, accumulator.Y, accumulator.Z, accumulator.X, accumulator.Y, accumulator.Z);
            (int X, int Y, int Z) selected = builder.SelectFromTable(curve, table, bits0MostSignificantFirst[i], bits1MostSignificantFirst[i], bits2MostSignificantFirst[i]);
            accumulator = builder.AddCompleteProjectiveAddition(curve, accumulator.X, accumulator.Y, accumulator.Z, selected.X, selected.Y, selected.Z);
        }

        return accumulator;
    }


    //out = b + bit·(a − b): equals b when bit = 0 and a when bit = 1.
    private static int MuxCoordinate(LigeroConstraintSystemBuilder builder, WeierstrassCurve curve, int bit, int a, int b)
    {
        int difference = builder.Combine([Term(a, curve.One), Term(b, curve.NegativeOne)]);
        int scaled = builder.Multiply(bit, difference);

        return builder.Combine([Term(scaled, curve.One), Term(b, curve.One)]);
    }


    private static LinearTerm Term(int wire, ReadOnlyMemory<byte> coefficient) => new(wire, coefficient);
}
