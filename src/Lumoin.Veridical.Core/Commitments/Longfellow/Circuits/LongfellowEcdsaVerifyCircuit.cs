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
    //Indices into the precomputed sum table (the reference's PreIndex enum; the order is load-bearing).
    private const int GpkX = 0;
    private const int GpkY = 1;
    private const int GrX = 2;
    private const int GrY = 3;
    private const int RpkX = 4;
    private const int RpkY = 5;
    private const int GrpkX = 6;
    private const int GrpkY = 7;

    //The range muxer interpolates through one more point than the mux table holds, proving the
    //digit lies in the eight-entry table with a single degree-eight identity.
    private const int MuxTableLength = 8;

    private readonly LongfellowLogic logic;
    private readonly LongfellowLogicBackend backend;
    private readonly LongfellowLogicFieldOperations field;
    private readonly LongfellowEllipticCurveParameters curve;
    private readonly ReadOnlyMemory<byte> two;
    private readonly LongfellowBitWire[] orderBits;


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

        this.logic = logic;
        this.curve = curve;
        backend = logic.Backend;
        field = logic.Field;
        two = field.OfScalar(2);

        orderBits = new LongfellowBitWire[curve.ScalarBitCount];
        for(int i = 0; i < curve.ScalarBitCount; i++)
        {
            orderBits[i] = logic.Bit(curve.OrderBit(i));
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

        int scalarBitCount = curve.ScalarBitCount;
        if(witness.Bi.Length != scalarBitCount)
        {
            throw new ArgumentException("The advice's digit count disagrees with the curve's scalar bit count.", nameof(witness));
        }

        int zero = backend.Constant(field.Compiler.Zero.Span);
        int one = backend.Constant(field.Compiler.One.Span);
        int gx = backend.Constant(curve.GeneratorX.Span);
        int gy = backend.Constant(curve.GeneratorY.Span);

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

        var xx = new LongfellowEltMuxer(logic, tableX);
        var yy = new LongfellowEltMuxer(logic, tableY);
        var zz = new LongfellowEltMuxer(logic, tableZ);
        var ee = new LongfellowEltMuxer(logic, tableE);
        var rr = new LongfellowEltMuxer(logic, tableR);
        var ss = new LongfellowEltMuxer(logic, tableS);
        var vv = new LongfellowEltMuxer(logic, tableV, MuxTableLength);

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
            int k2 = backend.Constant(two.Span);
            est = backend.Add(eBi, backend.Mul(k2, est));
            rst = backend.Add(rBi, backend.Mul(k2, rst));
            sst = backend.Add(sBi, backend.Mul(k2, sst));
            rBits[scalarBitCount - i - 1] = new LongfellowBitWire(field, rBi);
            sBits[scalarBitCount - i - 1] = new LongfellowBitWire(field, sBi);

            int range = vv.Mux(witness.Bi[i]);
            _ = logic.AssertZero(range);

            if(i > 0)
            {
                (ax, ay, az) = DoubleE(ax, ay, az);
            }

            (ax, ay, az) = AddE(ax, ay, az, tx, ty, tz);

            if(i < scalarBitCount - 1)
            {
                //Re-anchoring on the advice point both slices the depth and, through the equality,
                //proves by induction that every advice intermediate is on the curve.
                _ = logic.AssertEqual(ax, witness.IntX[i]);
                _ = logic.AssertEqual(ay, witness.IntY[i]);
                _ = logic.AssertEqual(az, witness.IntZ[i]);

                ax = witness.IntX[i];
                ay = witness.IntY[i];
                az = witness.IntZ[i];
            }
        }

        _ = logic.AssertZero(ax);
        _ = logic.AssertZero(az);

        _ = logic.AssertEqual(est, e);
        _ = logic.AssertEqual(rst, witness.Rx);

        IsOnCurve(pkX, pkY);
        IsOnCurve(witness.Rx, witness.Ry);

        AssertNonzero(witness.Rx, witness.RxInverse);
        AssertNonzero(sst, witness.SInverse);
        AssertNonzero(pkX, witness.PkInverse);
        LongfellowBitWire rRange = logic.LessThan(rBits, orderBits);
        LongfellowBitWire sRange = logic.LessThan(sBits, orderBits);
        _ = logic.AssertOne(rRange);
        _ = logic.AssertOne(sRange);
    }


    /// <summary>The reference's <c>assert_nonzero</c>: asserts <c>x · witness = 1</c>, the inverse-certificate proof that <c>x</c> is nonzero.</summary>
    /// <param name="x">The wire proven nonzero.</param>
    /// <param name="witnessWire">The claimed inverse wire.</param>
    private void AssertNonzero(int x, int witnessWire)
    {
        int maybeOne = backend.Mul(x, witnessWire);
        int one = backend.Constant(field.Compiler.One.Span);
        _ = logic.AssertEqual(maybeOne, one);
    }


    /// <summary>The reference's <c>point_equality</c>: asserts the projective point <c>(x : y : z)</c> equals the affine <c>(pX, pY)</c> by cross-multiplication.</summary>
    /// <param name="x">The projective x wire.</param>
    /// <param name="y">The projective y wire.</param>
    /// <param name="z">The projective z wire.</param>
    /// <param name="pX">The affine x wire.</param>
    /// <param name="pY">The affine y wire.</param>
    private void PointEquality(int x, int y, int z, int pX, int pY)
    {
        _ = logic.AssertEqual(x, backend.Mul(z, pX));
        _ = logic.AssertEqual(y, backend.Mul(z, pY));
    }


    /// <summary>The reference's <c>is_on_curve</c>: asserts <c>y² = x³ + a·x + b</c>.</summary>
    /// <param name="x">The affine x wire.</param>
    /// <param name="y">The affine y wire.</param>
    private void IsOnCurve(int x, int y)
    {
        int yy = backend.Mul(y, y);
        int xx = backend.Mul(x, x);
        int xxx = backend.Mul(x, xx);
        int ax = backend.MultiplyScaled(curve.A.Span, x);
        int b = backend.Constant(curve.B.Span);
        int axb = backend.Add(ax, b);
        int rhs = backend.Add(axb, xxx);
        _ = logic.AssertEqual(yy, rhs);
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
        int t0 = backend.Mul(x1, x2);
        int t1 = backend.Mul(y1, y2);
        int t2 = backend.Mul(z1, z2);
        int t3 = backend.Add(x1, y1);
        int t4 = backend.Add(x2, y2);
        t3 = backend.Mul(t3, t4);
        t4 = backend.Add(t0, t1);
        t3 = backend.Sub(t3, t4);
        t4 = backend.Add(x1, z1);
        int t5 = backend.Add(x2, z2);
        t4 = backend.Mul(t4, t5);
        t5 = backend.Add(t0, t2);
        t4 = backend.Sub(t4, t5);
        t5 = backend.Add(y1, z1);
        int x3 = backend.Add(y2, z2);
        t5 = backend.Mul(t5, x3);
        x3 = backend.Add(t1, t2);
        t5 = backend.Sub(t5, x3);
        int a = backend.Constant(curve.A.Span);
        int z3 = backend.Mul(a, t4);
        int k3b = backend.Constant(curve.BTimes3.Span);
        x3 = backend.Mul(k3b, t2);
        z3 = backend.Add(x3, z3);
        x3 = backend.Sub(t1, z3);
        z3 = backend.Add(t1, z3);
        int y3 = backend.Mul(x3, z3);
        t1 = backend.Add(t0, t0);
        t1 = backend.Add(t1, t0);
        t2 = backend.Mul(a, t2);
        t4 = backend.Mul(k3b, t4);
        t1 = backend.Add(t1, t2);
        t2 = backend.Sub(t0, t2);
        t2 = backend.Mul(a, t2);
        t4 = backend.Add(t4, t2);
        t0 = backend.Mul(t1, t4);
        y3 = backend.Add(y3, t0);
        t0 = backend.Mul(t5, t4);
        x3 = backend.Mul(t3, x3);
        x3 = backend.Sub(x3, t0);
        t0 = backend.Mul(t3, t1);
        z3 = backend.Mul(t5, z3);
        z3 = backend.Add(z3, t0);

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
        int t0 = backend.Mul(x, x);
        int t1 = backend.Mul(y, y);
        int t2 = backend.Mul(z, z);
        int t3 = backend.Mul(x, y);
        t3 = backend.Add(t3, t3);
        int z3 = backend.Mul(x, z);
        z3 = backend.Add(z3, z3);
        int a = backend.Constant(curve.A.Span);
        int k3b = backend.Constant(curve.BTimes3.Span);
        int x3 = backend.Mul(a, z3);
        int y3 = backend.Mul(k3b, t2);
        y3 = backend.Add(x3, y3);
        x3 = backend.Sub(t1, y3);
        y3 = backend.Add(t1, y3);
        y3 = backend.Mul(x3, y3);
        x3 = backend.Mul(t3, x3);
        z3 = backend.Mul(k3b, z3);
        t2 = backend.Mul(a, t2);
        t3 = backend.Sub(t0, t2);
        t3 = backend.Mul(a, t3);
        t3 = backend.Add(t3, z3);
        z3 = backend.Add(t0, t0);
        t0 = backend.Add(z3, t0);
        t0 = backend.Add(t0, t2);
        t0 = backend.Mul(t0, t3);
        y3 = backend.Add(y3, t0);
        t2 = backend.Mul(y, z);
        t2 = backend.Add(t2, t2);
        t0 = backend.Mul(t2, t3);
        x3 = backend.Sub(x3, t0);
        z3 = backend.Mul(t2, t1);
        z3 = backend.Add(z3, z3);
        z3 = backend.Add(z3, z3);

        return (x3, y3, z3);
    }
}
