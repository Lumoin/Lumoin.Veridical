using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The in-circuit wire handles for one ECDSA verification's advice, a faithful port of
/// google/longfellow-zk's <c>VerifyCircuit::Witness</c> (<c>circuits/ecdsa/verify_circuit.h</c>):
/// the claimed signature point and its inverse certificates, the four-entry precomputed sum table
/// as normalized coordinate pairs, and per scalar bit the packed advice digit plus the unnormalized
/// projective intermediate the verification loop re-anchors on.
/// </summary>
internal sealed class LongfellowEcdsaVerifyWitnessWires
{
    /// <summary>The precomputed sum table's coordinate-pair count (<c>g+pk</c>, <c>g+r</c>, <c>r+pk</c>, <c>g+r+pk</c>, x and y each).</summary>
    public const int PreTableLength = 8;

    /// <summary>The claimed signature point's x coordinate (also the signature scalar <c>r</c> read in the base field).</summary>
    public int Rx { get; }

    /// <summary>The claimed signature point's y coordinate.</summary>
    public int Ry { get; }

    /// <summary>The inverse certificate proving <c>r ≠ 0</c>.</summary>
    public int RxInverse { get; }

    /// <summary>The inverse certificate proving <c>s ≠ 0</c> (the base-field inverse of <c>−s</c>'s canonical value).</summary>
    public int SInverse { get; }

    /// <summary>The inverse certificate proving the public key's x coordinate is nonzero.</summary>
    public int PkInverse { get; }

    /// <summary>The precomputed sum table, <c>x, y</c> interleaved per entry.</summary>
    public int[] Pre { get; }

    /// <summary>The per-bit advice digits, plucker-point-encoded three-bit values, most significant scalar bit first.</summary>
    public int[] Bi { get; }

    /// <summary>The unnormalized projective intermediates' x coordinates, one per loop step but the last.</summary>
    public int[] IntX { get; }

    /// <summary>The unnormalized projective intermediates' y coordinates.</summary>
    public int[] IntY { get; }

    /// <summary>The unnormalized projective intermediates' z coordinates.</summary>
    public int[] IntZ { get; }


    /// <summary>
    /// Constructs the handle bundle from already-produced wires, the path evaluation-mode tests use.
    /// </summary>
    /// <param name="rx">The signature point's x coordinate wire.</param>
    /// <param name="ry">The signature point's y coordinate wire.</param>
    /// <param name="rxInverse">The <c>r ≠ 0</c> certificate wire.</param>
    /// <param name="sInverse">The <c>s ≠ 0</c> certificate wire.</param>
    /// <param name="pkInverse">The public-key certificate wire.</param>
    /// <param name="pre">The precomputed sum table wires.</param>
    /// <param name="bi">The advice digit wires, one per scalar bit.</param>
    /// <param name="intX">The intermediate x wires, one per scalar bit but the last.</param>
    /// <param name="intY">The intermediate y wires.</param>
    /// <param name="intZ">The intermediate z wires.</param>
    /// <exception cref="ArgumentNullException">When an array is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When an array length does not match the digit count's shape.</exception>
    public LongfellowEcdsaVerifyWitnessWires(int rx, int ry, int rxInverse, int sInverse, int pkInverse, int[] pre, int[] bi, int[] intX, int[] intY, int[] intZ)
    {
        ArgumentNullException.ThrowIfNull(pre);
        ArgumentNullException.ThrowIfNull(bi);
        ArgumentNullException.ThrowIfNull(intX);
        ArgumentNullException.ThrowIfNull(intY);
        ArgumentNullException.ThrowIfNull(intZ);

        if(pre.Length != PreTableLength || intX.Length != bi.Length - 1 || intY.Length != bi.Length - 1 || intZ.Length != bi.Length - 1)
        {
            throw new ArgumentException("The advice arrays disagree with the scalar bit count's shape.");
        }

        Rx = rx;
        Ry = ry;
        RxInverse = rxInverse;
        SInverse = sInverse;
        PkInverse = pkInverse;
        Pre = pre;
        Bi = bi;
        IntX = intX;
        IntY = intY;
        IntZ = intZ;
    }


    /// <summary>
    /// The reference's <c>Witness::input</c>: declares every advice wire in the reference order —
    /// the five scalars, the sum table, then per scalar bit the digit followed by the intermediate
    /// triple — which is also the order the witness generator emits values in.
    /// </summary>
    /// <param name="logic">The gadget layer to declare inputs on.</param>
    /// <param name="scalarBitCount">The scalar bit count (the curve's <c>kBits</c>).</param>
    /// <returns>The declared handle bundle.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="scalarBitCount"/> is not positive.</exception>
    public static LongfellowEcdsaVerifyWitnessWires Input(LongfellowLogic logic, int scalarBitCount)
    {
        ArgumentNullException.ThrowIfNull(logic);
        ArgumentOutOfRangeException.ThrowIfLessThan(scalarBitCount, 1);

        int rx = logic.InputElement();
        int ry = logic.InputElement();
        int rxInverse = logic.InputElement();
        int sInverse = logic.InputElement();
        int pkInverse = logic.InputElement();

        var pre = new int[PreTableLength];
        for(int i = 0; i < PreTableLength; i++)
        {
            pre[i] = logic.InputElement();
        }

        var bi = new int[scalarBitCount];
        var intX = new int[scalarBitCount - 1];
        var intY = new int[scalarBitCount - 1];
        var intZ = new int[scalarBitCount - 1];
        for(int i = 0; i < scalarBitCount; i++)
        {
            bi[i] = logic.InputElement();
            if(i < scalarBitCount - 1)
            {
                intX[i] = logic.InputElement();
                intY[i] = logic.InputElement();
                intZ[i] = logic.InputElement();
            }
        }

        return new LongfellowEcdsaVerifyWitnessWires(rx, ry, rxInverse, sInverse, pkInverse, pre, bi, intX, intY, intZ);
    }
}


/// <summary>
/// Verifies an ECDSA signature in-circuit via the triple-scalar-multiplication identity, a faithful
/// port of google/longfellow-zk's <c>VerifyCircuit&lt;Logic, Field, EC&gt;</c>
/// (<c>circuits/ecdsa/verify_circuit.h</c>): the statement <c>identity = g·e + pk·r + (rx,ry)·(−s)</c>
/// checked by a single 256-step loop that muxes a four-point sum table through the advice digits,
/// with the precomputed table itself verified in parallel and every intermediate point re-anchored
/// on advice so the circuit depth stays flat.
/// </summary>
/// <remarks>
/// <para>
/// The sumcheck field is the curve's base field. As in the reference, the caller must separately
/// guarantee <c>e ≠ 0</c> — either the verifier checks the public input, or the hash defining
/// <c>e</c> is recomputed in-circuit, which is what the JWT statement does for the issuer
/// signature. The advice digit encodes three exponent bits as <c>2·b − 7 ∈ {−7, …, 7}</c>, and the
/// degree-eight range identity (the nine-entry muxer) proves each digit lies in the table.
/// </para>
/// <para>
/// The point arithmetic is the Renes–Costello–Batina complete addition and doubling (Algorithms 1
/// and 3), emitted operation for operation in the reference order so the compiled circuit matches
/// the reference compiler's counter for counter.
/// </para>
/// </remarks>
internal sealed class LongfellowEcdsaVerifyCircuit
{
    /// <summary>The precomputed sum table's index of <c>(g+pk)</c>'s x coordinate, matching the reference's <c>PreIndex</c> enum order.</summary>
    private const int GpkX = 0;

    /// <summary>The precomputed sum table's index of <c>(g+pk)</c>'s y coordinate, matching the reference's <c>PreIndex</c> enum order.</summary>
    private const int GpkY = 1;

    /// <summary>The precomputed sum table's index of <c>(g+r)</c>'s x coordinate, matching the reference's <c>PreIndex</c> enum order.</summary>
    private const int GrX = 2;

    /// <summary>The precomputed sum table's index of <c>(g+r)</c>'s y coordinate, matching the reference's <c>PreIndex</c> enum order.</summary>
    private const int GrY = 3;

    /// <summary>The precomputed sum table's index of <c>(r+pk)</c>'s x coordinate, matching the reference's <c>PreIndex</c> enum order.</summary>
    private const int RpkX = 4;

    /// <summary>The precomputed sum table's index of <c>(r+pk)</c>'s y coordinate, matching the reference's <c>PreIndex</c> enum order.</summary>
    private const int RpkY = 5;

    /// <summary>The precomputed sum table's index of <c>(g+r+pk)</c>'s x coordinate, matching the reference's <c>PreIndex</c> enum order.</summary>
    private const int GrpkX = 6;

    /// <summary>The precomputed sum table's index of <c>(g+r+pk)</c>'s y coordinate, matching the reference's <c>PreIndex</c> enum order.</summary>
    private const int GrpkY = 7;

    /// <summary>The range muxer interpolates through one more point than the mux table holds, proving the digit lies in the eight-entry table with a single degree-eight identity.</summary>
    private const int MuxTableLength = 8;

    /// <summary>The gadget layer every operation in this circuit builds on.</summary>
    private LongfellowLogic Logic { get; }

    /// <summary>The gadget layer's backend, used directly for the field-arithmetic operations the point formulas need.</summary>
    private LongfellowLogicBackend Backend { get; }

    /// <summary>The gadget layer's field-operation bundle, supplying the field's constants and characteristic.</summary>
    private LongfellowLogicFieldOperations Field { get; }

    /// <summary>The curve constants this circuit verifies signatures against.</summary>
    private LongfellowEllipticCurveParameters Curve { get; }

    /// <summary>The embedding of scalar two, borrowed from the field for this gadget's lifetime.</summary>
    private ReadOnlyMemory<byte> Two { get; }

    /// <summary>The group order's bits, precomputed once, that <c>r</c> and <c>s</c> are range-checked against.</summary>
    private LongfellowBitWire[] OrderBits { get; }


    /// <summary>
    /// Constructs the gadget over a gadget layer and a curve, precomputing the constant bit pattern
    /// of the group order the scalar range checks compare against (the reference constructor's
    /// <c>bits_n_</c>).
    /// </summary>
    /// <param name="logic">The gadget layer every operation builds on.</param>
    /// <param name="curve">The curve constants.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> or <paramref name="curve"/> is <see langword="null"/>.</exception>
    public LongfellowEcdsaVerifyCircuit(LongfellowLogic logic, LongfellowEllipticCurveParameters curve)
    {
        ArgumentNullException.ThrowIfNull(logic);
        ArgumentNullException.ThrowIfNull(curve);

        this.Logic = logic;
        this.Curve = curve;
        Backend = logic.Backend;
        Field = logic.Field;
        Two = Field.Compiler.IsCharacteristicTwo ? Field.Beta(1) : Field.Two;

        OrderBits = new LongfellowBitWire[curve.ScalarBitCount];
        for(int i = 0; i < curve.ScalarBitCount; i++)
        {
            OrderBits[i] = logic.Bit(curve.OrderBit(i));
        }
    }


    /// <summary>
    /// The reference's <c>verify_signature3</c>: asserts a signature under <c>(pkX, pkY)</c> exists
    /// on the digest <paramref name="e"/>, consuming the advice in <paramref name="witness"/>. The
    /// checks beyond the main loop: the sum table is correct, the recomposed exponents match
    /// <paramref name="e"/> and the claimed <c>r</c>, both points satisfy the curve equation,
    /// <c>r</c>, <c>s</c> and the key's x coordinate are nonzero by inverse certificate, and
    /// <c>r</c> and <c>s</c> are below the group order bit-for-bit.
    /// </summary>
    /// <param name="pkX">The public key's x coordinate wire.</param>
    /// <param name="pkY">The public key's y coordinate wire.</param>
    /// <param name="e">The digest wire.</param>
    /// <param name="witness">The advice wires.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="witness"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the advice's digit count disagrees with the curve's scalar bit count.</exception>
    public void VerifySignature3(int pkX, int pkY, int e, LongfellowEcdsaVerifyWitnessWires witness)
    {
        ArgumentNullException.ThrowIfNull(witness);

        int scalarBitCount = Curve.ScalarBitCount;
        if(witness.Bi.Length != scalarBitCount)
        {
            throw new ArgumentException("The advice's digit count disagrees with the curve's scalar bit count.", nameof(witness));
        }

        int zero = Backend.Constant(Field.Compiler.Zero.Span);
        int one = Backend.Constant(Field.Compiler.One.Span);
        int gx = Backend.Constant(Curve.GeneratorX.Span);
        int gy = Backend.Constant(Curve.GeneratorY.Span);

        int est = zero;
        int rst = zero;
        int sst = zero;

        int ax = zero;
        int ay = one;
        int az = zero;

        //Verify the sum table in parallel with its use, keeping the circuit depth flat.
        (int cgPkX, int cgPkY, int cgPkZ) = AddE(gx, gy, one, pkX, pkY, one);
        (int crGx, int crGy, int crGz) = AddE(witness.Rx, witness.Ry, one, gx, gy, one);
        (int crPkX, int crPkY, int crPkZ) = AddE(witness.Rx, witness.Ry, one, pkX, pkY, one);
        (int crGpkX, int crGpkY, int crGpkZ) = AddE(gx, gy, one, witness.Pre[RpkX], witness.Pre[RpkY], one);
        PointEquality(cgPkX, cgPkY, cgPkZ, witness.Pre[GpkX], witness.Pre[GpkY]);
        PointEquality(crGx, crGy, crGz, witness.Pre[GrX], witness.Pre[GrY]);
        PointEquality(crPkX, crPkY, crPkZ, witness.Pre[RpkX], witness.Pre[RpkY]);
        PointEquality(crGpkX, crGpkY, crGpkZ, witness.Pre[GrpkX], witness.Pre[GrpkY]);

        int[] tableX = [zero, gx, pkX, witness.Pre[GpkX], witness.Rx, witness.Pre[GrX], witness.Pre[RpkX], witness.Pre[GrpkX]];
        int[] tableY = [one, gy, pkY, witness.Pre[GpkY], witness.Ry, witness.Pre[GrY], witness.Pre[RpkY], witness.Pre[GrpkY]];
        int[] tableZ = [zero, one, one, one, one, one, one, one];
        int[] tableE = [zero, one, zero, one, zero, one, zero, one];
        int[] tableR = [zero, zero, one, one, zero, zero, one, one];
        int[] tableS = [zero, zero, zero, zero, one, one, one, one];
        int[] tableV = [zero, zero, zero, zero, zero, zero, zero, zero, one];

        var xx = new LongfellowEltMuxer(Logic, tableX);
        var yy = new LongfellowEltMuxer(Logic, tableY);
        var zz = new LongfellowEltMuxer(Logic, tableZ);
        var ee = new LongfellowEltMuxer(Logic, tableE);
        var rr = new LongfellowEltMuxer(Logic, tableR);
        var ss = new LongfellowEltMuxer(Logic, tableS);
        var vv = new LongfellowEltMuxer(Logic, tableV, MuxTableLength);

        var rBits = new LongfellowBitWire[scalarBitCount];
        var sBits = new LongfellowBitWire[scalarBitCount];

        //Traverse the scalar bits from high order to low order.
        for(int i = 0; i < scalarBitCount; i++)
        {
            int tx = xx.Mux(witness.Bi[i]);
            int ty = yy.Mux(witness.Bi[i]);
            int tz = zz.Mux(witness.Bi[i]);

            int eBi = ee.Mux(witness.Bi[i]);
            int rBi = rr.Mux(witness.Bi[i]);
            int sBi = ss.Mux(witness.Bi[i]);
            int k2 = Backend.Constant(Two.Span);
            est = Backend.Add(eBi, Backend.Mul(k2, est));
            rst = Backend.Add(rBi, Backend.Mul(k2, rst));
            sst = Backend.Add(sBi, Backend.Mul(k2, sst));
            rBits[scalarBitCount - i - 1] = new LongfellowBitWire(Field, rBi);
            sBits[scalarBitCount - i - 1] = new LongfellowBitWire(Field, sBi);

            int range = vv.Mux(witness.Bi[i]);
            _ = Logic.AssertZero(range);

            if(i > 0)
            {
                (ax, ay, az) = DoubleE(ax, ay, az);
            }

            (ax, ay, az) = AddE(ax, ay, az, tx, ty, tz);

            if(i < scalarBitCount - 1)
            {
                //Re-anchoring on the advice point both slices the depth and, through the equality,
                //proves by induction that every advice intermediate is on the curve.
                _ = Logic.AssertEqual(ax, witness.IntX[i]);
                _ = Logic.AssertEqual(ay, witness.IntY[i]);
                _ = Logic.AssertEqual(az, witness.IntZ[i]);

                ax = witness.IntX[i];
                ay = witness.IntY[i];
                az = witness.IntZ[i];
            }
        }

        _ = Logic.AssertZero(ax);
        _ = Logic.AssertZero(az);

        _ = Logic.AssertEqual(est, e);
        _ = Logic.AssertEqual(rst, witness.Rx);

        IsOnCurve(pkX, pkY);
        IsOnCurve(witness.Rx, witness.Ry);

        AssertNonzero(witness.Rx, witness.RxInverse);
        AssertNonzero(sst, witness.SInverse);
        AssertNonzero(pkX, witness.PkInverse);
        LongfellowBitWire rRange = Logic.LessThan(rBits, OrderBits);
        LongfellowBitWire sRange = Logic.LessThan(sBits, OrderBits);
        _ = Logic.AssertOne(rRange);
        _ = Logic.AssertOne(sRange);
    }


    /// <summary>The reference's <c>assert_nonzero</c>: asserts <c>x · witness = 1</c>, the inverse-certificate proof that <c>x</c> is nonzero.</summary>
    /// <param name="x">The wire proven nonzero.</param>
    /// <param name="witnessWire">The claimed inverse wire.</param>
    private void AssertNonzero(int x, int witnessWire)
    {
        int maybeOne = Backend.Mul(x, witnessWire);
        int one = Backend.Constant(Field.Compiler.One.Span);
        _ = Logic.AssertEqual(maybeOne, one);
    }


    /// <summary>The reference's <c>point_equality</c>: asserts the projective point <c>(x : y : z)</c> equals the affine <c>(pX, pY)</c> by cross-multiplication.</summary>
    /// <param name="x">The projective x wire.</param>
    /// <param name="y">The projective y wire.</param>
    /// <param name="z">The projective z wire.</param>
    /// <param name="pX">The affine x wire.</param>
    /// <param name="pY">The affine y wire.</param>
    private void PointEquality(int x, int y, int z, int pX, int pY)
    {
        _ = Logic.AssertEqual(x, Backend.Mul(z, pX));
        _ = Logic.AssertEqual(y, Backend.Mul(z, pY));
    }


    /// <summary>The reference's <c>is_on_curve</c>: asserts <c>y² = x³ + a·x + b</c>.</summary>
    /// <param name="x">The affine x wire.</param>
    /// <param name="y">The affine y wire.</param>
    private void IsOnCurve(int x, int y)
    {
        int yy = Backend.Mul(y, y);
        int xx = Backend.Mul(x, x);
        int xxx = Backend.Mul(x, xx);
        int ax = Backend.MultiplyScaled(Curve.A.Span, x);
        int b = Backend.Constant(Curve.B.Span);
        int axb = Backend.Add(ax, b);
        int rhs = Backend.Add(axb, xxx);
        _ = Logic.AssertEqual(yy, rhs);
    }


    /// <summary>
    /// The reference's <c>addE</c>: Renes–Costello–Batina Algorithm 1, the complete projective
    /// addition for arbitrary prime-order short-Weierstrass curves, emitted operation for operation
    /// in the reference order.
    /// </summary>
    /// <param name="x1">The first point's x wire.</param>
    /// <param name="y1">The first point's y wire.</param>
    /// <param name="z1">The first point's z wire.</param>
    /// <param name="x2">The second point's x wire.</param>
    /// <param name="y2">The second point's y wire.</param>
    /// <param name="z2">The second point's z wire.</param>
    /// <returns>The sum's projective coordinate wires.</returns>
    private (int X3, int Y3, int Z3) AddE(int x1, int y1, int z1, int x2, int y2, int z2)
    {
        int t0 = Backend.Mul(x1, x2);
        int t1 = Backend.Mul(y1, y2);
        int t2 = Backend.Mul(z1, z2);
        int t3 = Backend.Add(x1, y1);
        int t4 = Backend.Add(x2, y2);
        t3 = Backend.Mul(t3, t4);
        t4 = Backend.Add(t0, t1);
        t3 = Backend.Sub(t3, t4);
        t4 = Backend.Add(x1, z1);
        int t5 = Backend.Add(x2, z2);
        t4 = Backend.Mul(t4, t5);
        t5 = Backend.Add(t0, t2);
        t4 = Backend.Sub(t4, t5);
        t5 = Backend.Add(y1, z1);
        int x3 = Backend.Add(y2, z2);
        t5 = Backend.Mul(t5, x3);
        x3 = Backend.Add(t1, t2);
        t5 = Backend.Sub(t5, x3);
        int a = Backend.Constant(Curve.A.Span);
        int z3 = Backend.Mul(a, t4);
        int k3b = Backend.Constant(Curve.BTimes3.Span);
        x3 = Backend.Mul(k3b, t2);
        z3 = Backend.Add(x3, z3);
        x3 = Backend.Sub(t1, z3);
        z3 = Backend.Add(t1, z3);
        int y3 = Backend.Mul(x3, z3);
        t1 = Backend.Add(t0, t0);
        t1 = Backend.Add(t1, t0);
        t2 = Backend.Mul(a, t2);
        t4 = Backend.Mul(k3b, t4);
        t1 = Backend.Add(t1, t2);
        t2 = Backend.Sub(t0, t2);
        t2 = Backend.Mul(a, t2);
        t4 = Backend.Add(t4, t2);
        t0 = Backend.Mul(t1, t4);
        y3 = Backend.Add(y3, t0);
        t0 = Backend.Mul(t5, t4);
        x3 = Backend.Mul(t3, x3);
        x3 = Backend.Sub(x3, t0);
        t0 = Backend.Mul(t3, t1);
        z3 = Backend.Mul(t5, z3);
        z3 = Backend.Add(z3, t0);

        return (x3, y3, z3);
    }


    /// <summary>
    /// The reference's <c>doubleE</c>: Renes–Costello–Batina Algorithm 3, the exception-free
    /// projective doubling, emitted operation for operation in the reference order.
    /// </summary>
    /// <param name="x">The point's x wire.</param>
    /// <param name="y">The point's y wire.</param>
    /// <param name="z">The point's z wire.</param>
    /// <returns>The doubled point's projective coordinate wires.</returns>
    private (int X3, int Y3, int Z3) DoubleE(int x, int y, int z)
    {
        int t0 = Backend.Mul(x, x);
        int t1 = Backend.Mul(y, y);
        int t2 = Backend.Mul(z, z);
        int t3 = Backend.Mul(x, y);
        t3 = Backend.Add(t3, t3);
        int z3 = Backend.Mul(x, z);
        z3 = Backend.Add(z3, z3);
        int a = Backend.Constant(Curve.A.Span);
        int k3b = Backend.Constant(Curve.BTimes3.Span);
        int x3 = Backend.Mul(a, z3);
        int y3 = Backend.Mul(k3b, t2);
        y3 = Backend.Add(x3, y3);
        x3 = Backend.Sub(t1, y3);
        y3 = Backend.Add(t1, y3);
        y3 = Backend.Mul(x3, y3);
        x3 = Backend.Mul(t3, x3);
        z3 = Backend.Mul(k3b, z3);
        t2 = Backend.Mul(a, t2);
        t3 = Backend.Sub(t0, t2);
        t3 = Backend.Mul(a, t3);
        t3 = Backend.Add(t3, z3);
        z3 = Backend.Add(t0, t0);
        t0 = Backend.Add(z3, t0);
        t0 = Backend.Add(t0, t2);
        t0 = Backend.Mul(t0, t3);
        y3 = Backend.Add(y3, t0);
        t2 = Backend.Mul(y, z);
        t2 = Backend.Add(t2, t2);
        t0 = Backend.Mul(t2, t3);
        x3 = Backend.Sub(x3, t0);
        z3 = Backend.Mul(t2, t1);
        z3 = Backend.Add(z3, z3);
        z3 = Backend.Add(z3, z3);

        return (x3, y3, z3);
    }
}
