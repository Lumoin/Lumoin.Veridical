using System;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// Computes the advice column for one in-circuit ECDSA verification, a faithful port of
/// google/longfellow-zk's <c>VerifyWitness3&lt;EC, ScalarField&gt;</c>
/// (<c>circuits/ecdsa/verify_witness.h</c>): given the public key and the signature triple
/// <c>(e, r, s)</c> it recovers the signature point <c>R = (e/s)·G + (r/s)·Q</c>, builds the
/// four-entry precomputed sum table, walks the triple-scalar identity
/// <c>id = g·e + pk·r + R·(−s)</c> recording the packed advice digits and every unnormalized
/// projective intermediate, and emits the whole column in the exact order
/// <see cref="LongfellowEcdsaVerifyWitnessWires.Input"/> declares wires in.
/// </summary>
/// <remarks>
/// <para>
/// All arithmetic runs in the canonical domain over injected delegates: the base field through the
/// gadget layer's <see cref="LongfellowLogicFieldOperations"/> bundle, the order field through
/// canonical-in/out scalar delegates. The reference's Montgomery round-trips collapse away in this
/// domain; the emitted values are byte-for-byte the reference's <c>to_bytes_field</c> outputs. The
/// point arithmetic is the same Renes–Costello–Batina complete addition and doubling the circuit
/// emits, so the recorded intermediates match the circuit's computation exactly, unnormalized z
/// coordinates included.
/// </para>
/// <para>
/// Witness generation is variable-time, as the reference's is: it runs prover-side over the
/// prover's own credential. Inversion follows the Fermat convention that zero maps to zero (the
/// reference leaves the corresponding certificate at zero and lets the final identity check reject),
/// so a malformed signature makes <see cref="ComputeWitness"/> return <see langword="false"/> or
/// yields an unsatisfiable column rather than throwing.
/// </para>
/// </remarks>
internal sealed class LongfellowEcdsaVerifyWitness
{
    //The packed digit's plucker-point domain: three exponent bits index an eight-entry table.
    private const int DigitTableLength = 8;

    private readonly LongfellowLogicFieldOperations field;
    private readonly ScalarMultiplyDelegate orderMultiply;
    private readonly ScalarSubtractDelegate orderSubtract;
    private readonly ScalarInvertDelegate orderInvert;
    private readonly CurveParameterSet orderCurve;
    private readonly LongfellowEllipticCurveParameters curve;
    private readonly byte[] basePrime;
    private readonly byte[] curveA;
    private readonly byte[] curveBTimes3;

    private readonly byte[] rx;
    private readonly byte[] ry;
    private readonly byte[] rxInverse;
    private readonly byte[] sInverse;
    private readonly byte[] pkInverse;
    private readonly byte[][] pre;
    private readonly byte[][] bi;
    private readonly byte[][] intX;
    private readonly byte[][] intY;
    private readonly byte[][] intZ;

    /// <summary>The column length in elements: the five scalars, the sum table, and per scalar bit the digit plus (all but the last step) the intermediate triple.</summary>
    public int ElementCount { get; }


    /// <summary>
    /// Constructs the generator over a base-field bundle, the order-field delegates, and the curve.
    /// </summary>
    /// <param name="field">The base-field bundle (addition and multiplication through <see cref="LongfellowLogicFieldOperations.Compiler"/>, genuine subtraction and inversion on the bundle itself).</param>
    /// <param name="orderMultiply">The order-field multiplication, canonical in and out.</param>
    /// <param name="orderSubtract">The order-field subtraction, canonical in and out.</param>
    /// <param name="orderInvert">The order-field inversion, canonical in and out.</param>
    /// <param name="orderCurve">The curve parameter set the order-field delegates dispatch on.</param>
    /// <param name="curve">The curve constants.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public LongfellowEcdsaVerifyWitness(
        LongfellowLogicFieldOperations field,
        ScalarMultiplyDelegate orderMultiply,
        ScalarSubtractDelegate orderSubtract,
        ScalarInvertDelegate orderInvert,
        CurveParameterSet orderCurve,
        LongfellowEllipticCurveParameters curve)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(orderMultiply);
        ArgumentNullException.ThrowIfNull(orderSubtract);
        ArgumentNullException.ThrowIfNull(orderInvert);
        ArgumentNullException.ThrowIfNull(curve);

        this.field = field;
        this.orderMultiply = orderMultiply;
        this.orderSubtract = orderSubtract;
        this.orderInvert = orderInvert;
        this.orderCurve = orderCurve;
        this.curve = curve;
        curveA = curve.A.ToArray();
        curveBTimes3 = curve.BTimes3.ToArray();

        basePrime = DeriveBasePrime(field);

        int bits = curve.ScalarBitCount;
        ElementCount = 5 + LongfellowEcdsaVerifyWitnessWires.PreTableLength + bits + (3 * (bits - 1));

        rx = new byte[Scalar.SizeBytes];
        ry = new byte[Scalar.SizeBytes];
        rxInverse = new byte[Scalar.SizeBytes];
        sInverse = new byte[Scalar.SizeBytes];
        pkInverse = new byte[Scalar.SizeBytes];
        pre = NewElementArray(LongfellowEcdsaVerifyWitnessWires.PreTableLength);
        bi = NewElementArray(bits);
        intX = NewElementArray(bits);
        intY = NewElementArray(bits);
        intZ = NewElementArray(bits);
    }


    /// <summary>
    /// The reference's <c>compute_witness</c>: fills the advice for the signature triple, returning
    /// whether the triple-scalar walk terminated at the identity — the witness-side signature
    /// verification itself.
    /// </summary>
    /// <param name="pkX">The public key's x coordinate, canonical big-endian.</param>
    /// <param name="pkY">The public key's y coordinate, canonical big-endian.</param>
    /// <param name="e">The digest as a raw 256-bit big-endian value.</param>
    /// <param name="r">The signature's <c>r</c> as a raw 256-bit big-endian value.</param>
    /// <param name="s">The signature's <c>s</c> as a raw 256-bit big-endian value.</param>
    /// <returns>Whether the signature verified.</returns>
    /// <exception cref="ArgumentException">When an input is not exactly <see cref="Scalar.SizeBytes"/> bytes.</exception>
    public bool ComputeWitness(ReadOnlySpan<byte> pkX, ReadOnlySpan<byte> pkY, ReadOnlySpan<byte> e, ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        if(pkX.Length != Scalar.SizeBytes || pkY.Length != Scalar.SizeBytes || e.Length != Scalar.SizeBytes
            || r.Length != Scalar.SizeBytes || s.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"Witness inputs are canonical {Scalar.SizeBytes}-byte scalars.");
        }

        //Order-field copies of the raw inputs; the digit stream below keeps using the raw e and r
        //bits, exactly as the reference walks the unreduced naturals.
        Span<byte> eOrder = stackalloc byte[Scalar.SizeBytes];
        Span<byte> rOrder = stackalloc byte[Scalar.SizeBytes];
        Span<byte> sOrder = stackalloc byte[Scalar.SizeBytes];
        ReduceOnce(e, curve.Order.Span, eOrder);
        ReduceOnce(r, curve.Order.Span, rOrder);
        ReduceOnce(s, curve.Order.Span, sOrder);

        //u1 = e/s and u2 = r/s in the order field; a zero s yields zero quotients under the
        //Fermat zero-maps-to-zero convention and the walk below rejects.
        Span<byte> sQuotient = stackalloc byte[Scalar.SizeBytes];
        InvertOrder(sOrder, sQuotient);
        Span<byte> u1 = stackalloc byte[Scalar.SizeBytes];
        Span<byte> u2 = stackalloc byte[Scalar.SizeBytes];
        orderMultiply(eOrder, sQuotient, u1, orderCurve);
        orderMultiply(rOrder, sQuotient, u2, orderCurve);

        //Recover R = u1·G + u2·Q; the base field has no square root here, exactly the reference's
        //reason for recomputing R instead of decompressing it from r.
        ProjectivePoint generatorTerm = ScalarMultiplyPoint(curve.GeneratorX.Span, curve.GeneratorY.Span, u1);
        ProjectivePoint keyTerm = ScalarMultiplyPoint(pkX, pkY, u2);
        ProjectivePoint recovered = AddPoints(generatorTerm, keyTerm);
        Normalize(ref recovered);

        //rx is the signature scalar r read in the base field; ry is the recovered point's y.
        ReduceOnce(r, basePrime, rx);
        recovered.Y.CopyTo(ry.AsSpan());

        Array.Clear(rxInverse);
        if(!LongfellowCompilerFieldOperations.ElementIsZero(rx))
        {
            field.Invert(rx, rxInverse, field.Compiler.Curve);
        }

        //The certificate for s is the BASE-field inverse of −s's canonical order-field value, the
        //reference's cross-field reinterpretation.
        Span<byte> negatedS = stackalloc byte[Scalar.SizeBytes];
        Span<byte> zeroOrder = stackalloc byte[Scalar.SizeBytes];
        orderSubtract(zeroOrder, sOrder, negatedS, orderCurve);
        Array.Clear(sInverse);
        if(!LongfellowCompilerFieldOperations.ElementIsZero(negatedS))
        {
            field.Invert(negatedS, sInverse, field.Compiler.Curve);
        }

        Array.Clear(pkInverse);
        if(!LongfellowCompilerFieldOperations.ElementIsZero(pkX))
        {
            field.Invert(pkX, pkInverse, field.Compiler.Curve);
        }

        FillPreTable(pkX, pkY);

        //Walk the triple-scalar identity from the identity point, recording digits and the
        //unnormalized intermediates the circuit re-anchors on.
        var digitTable = BuildDigitTable(pkX, pkY);
        ProjectivePoint accumulator = Identity();
        int bits = curve.ScalarBitCount;
        for(int i = 0; i < bits; i++)
        {
            int bitIndex = bits - i - 1;
            int digit = BitAt(e, bitIndex) + (2 * BitAt(r, bitIndex)) + (4 * BitAt(negatedS, bitIndex));

            LongfellowBitPlucker.PluckerPoint(field, DigitTableLength, digit).Span.CopyTo(bi[i]);

            if(i > 0)
            {
                accumulator = DoublePoint(accumulator);
            }

            accumulator = AddPoints(accumulator, digitTable[digit]);

            accumulator.X.CopyTo(intX[i].AsSpan());
            accumulator.Y.CopyTo(intY[i].AsSpan());
            accumulator.Z.CopyTo(intZ[i].AsSpan());
        }

        return LongfellowCompilerFieldOperations.ElementIsZero(accumulator.X)
            && LongfellowCompilerFieldOperations.ElementIsZero(accumulator.Z);
    }


    /// <summary>
    /// The reference's <c>fill_witness</c>: writes the column in declaration order — the five
    /// scalars, the sum table, then per scalar bit the digit followed by (all but the last step)
    /// the intermediate triple — as contiguous canonical elements.
    /// </summary>
    /// <param name="destination">Receives <see cref="ElementCount"/> elements of <see cref="Scalar.SizeBytes"/> bytes each.</param>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is not exactly the column's byte length.</exception>
    public void FillWitness(Span<byte> destination)
    {
        if(destination.Length != ElementCount * Scalar.SizeBytes)
        {
            throw new ArgumentException($"The column is exactly {ElementCount} elements of {Scalar.SizeBytes} bytes.", nameof(destination));
        }

        int cursor = 0;
        WriteElement(destination, ref cursor, rx);
        WriteElement(destination, ref cursor, ry);
        WriteElement(destination, ref cursor, rxInverse);
        WriteElement(destination, ref cursor, sInverse);
        WriteElement(destination, ref cursor, pkInverse);
        for(int i = 0; i < pre.Length; i++)
        {
            WriteElement(destination, ref cursor, pre[i]);
        }

        int bits = curve.ScalarBitCount;
        for(int i = 0; i < bits; i++)
        {
            WriteElement(destination, ref cursor, bi[i]);
            if(i < bits - 1)
            {
                WriteElement(destination, ref cursor, intX[i]);
                WriteElement(destination, ref cursor, intY[i]);
                WriteElement(destination, ref cursor, intZ[i]);
            }
        }
    }


    /// <summary>
    /// The reference's sum-table construction: <c>g+pk</c>, <c>g+r</c>, <c>r+pk</c> from the
    /// left-hand/right-hand coordinate sequences, each normalized by its z coordinate when nonzero,
    /// then <c>g+r+pk</c> from the normalized <c>g+r</c> entry.
    /// </summary>
    /// <param name="pkX">The public key's x coordinate.</param>
    /// <param name="pkY">The public key's y coordinate.</param>
    private void FillPreTable(ReadOnlySpan<byte> pkX, ReadOnlySpan<byte> pkY)
    {
        Span<byte> one = stackalloc byte[Scalar.SizeBytes];
        field.Compiler.One.Span.CopyTo(one);

        var leftX = new byte[3][];
        var leftY = new byte[3][];
        var rightX = new byte[3][];
        var rightY = new byte[3][];
        leftX[0] = curve.GeneratorX.ToArray();
        leftY[0] = curve.GeneratorY.ToArray();
        rightX[0] = pkX.ToArray();
        rightY[0] = pkY.ToArray();
        leftX[1] = curve.GeneratorX.ToArray();
        leftY[1] = curve.GeneratorY.ToArray();
        rightX[1] = rx;
        rightY[1] = ry;
        leftX[2] = pkX.ToArray();
        leftY[2] = pkY.ToArray();
        rightX[2] = rx;
        rightY[2] = ry;

        for(int i = 0; i < 3; i++)
        {
            ProjectivePoint sum = AddPoints(
                new ProjectivePoint(leftX[i], leftY[i], one.ToArray()),
                new ProjectivePoint(rightX[i], rightY[i], one.ToArray()));
            NormalizeIntoPair(sum, pre[2 * i], pre[(2 * i) + 1]);
        }

        ProjectivePoint grpk = AddPoints(
            new ProjectivePoint(pre[2], pre[3], one.ToArray()),
            new ProjectivePoint(pkX.ToArray(), pkY.ToArray(), one.ToArray()));
        NormalizeIntoPair(grpk, pre[6], pre[7]);
    }


    /// <summary>Scales a sum's x and y by its inverted z (the reference's per-entry table normalization: the inversion is skipped for a zero z but the multiplication is not, so an identity sum zeroes both coordinates and the proof fails downstream).</summary>
    /// <param name="point">The sum to normalize.</param>
    /// <param name="destinationX">Receives the x coordinate.</param>
    /// <param name="destinationY">Receives the y coordinate.</param>
    private void NormalizeIntoPair(ProjectivePoint point, byte[] destinationX, byte[] destinationY)
    {
        Span<byte> scale = stackalloc byte[Scalar.SizeBytes];
        if(!LongfellowCompilerFieldOperations.ElementIsZero(point.Z))
        {
            field.Invert(point.Z, scale, field.Compiler.Curve);
        }

        field.Compiler.Multiply(point.X, scale, destinationX, field.Compiler.Curve);
        field.Compiler.Multiply(point.Y, scale, destinationY, field.Compiler.Curve);
    }


    /// <summary>Builds the digit-indexed addend table: identity, <c>g</c>, <c>pk</c>, <c>g+pk</c>, <c>r</c>, <c>g+r</c>, <c>r+pk</c>, <c>g+r+pk</c>.</summary>
    /// <param name="pkX">The public key's x coordinate.</param>
    /// <param name="pkY">The public key's y coordinate.</param>
    /// <returns>The addend table.</returns>
    private ProjectivePoint[] BuildDigitTable(ReadOnlySpan<byte> pkX, ReadOnlySpan<byte> pkY)
    {
        byte[] one = field.Compiler.One.ToArray();
        byte[] zero = new byte[Scalar.SizeBytes];

        return
        [
            new ProjectivePoint(zero, one, (byte[])zero.Clone()),
            new ProjectivePoint(curve.GeneratorX.ToArray(), curve.GeneratorY.ToArray(), (byte[])one.Clone()),
            new ProjectivePoint(pkX.ToArray(), pkY.ToArray(), (byte[])one.Clone()),
            new ProjectivePoint(pre[0], pre[1], (byte[])one.Clone()),
            new ProjectivePoint(rx, ry, (byte[])one.Clone()),
            new ProjectivePoint(pre[2], pre[3], (byte[])one.Clone()),
            new ProjectivePoint(pre[4], pre[5], (byte[])one.Clone()),
            new ProjectivePoint(pre[6], pre[7], (byte[])one.Clone()),
        ];
    }


    /// <summary>A projective point over canonical base-field elements.</summary>
    /// <param name="X">The x coordinate.</param>
    /// <param name="Y">The y coordinate.</param>
    /// <param name="Z">The z coordinate.</param>
    private readonly record struct ProjectivePoint(byte[] X, byte[] Y, byte[] Z);


    /// <summary>The projective identity <c>(0 : 1 : 0)</c>.</summary>
    /// <returns>The identity point.</returns>
    private ProjectivePoint Identity()
    {
        return new ProjectivePoint(new byte[Scalar.SizeBytes], field.Compiler.One.ToArray(), new byte[Scalar.SizeBytes]);
    }


    /// <summary>Variable-time double-and-add over the scalar's bits, most significant first, from the projective identity.</summary>
    /// <param name="baseX">The base point's affine x coordinate.</param>
    /// <param name="baseY">The base point's affine y coordinate.</param>
    /// <param name="scalar">The canonical scalar.</param>
    /// <returns>The unnormalized product point.</returns>
    private ProjectivePoint ScalarMultiplyPoint(ReadOnlySpan<byte> baseX, ReadOnlySpan<byte> baseY, ReadOnlySpan<byte> scalar)
    {
        var basePoint = new ProjectivePoint(baseX.ToArray(), baseY.ToArray(), field.Compiler.One.ToArray());
        ProjectivePoint accumulator = Identity();
        for(int i = (Scalar.SizeBytes * 8) - 1; i >= 0; i--)
        {
            accumulator = DoublePoint(accumulator);
            if(BitAt(scalar, i) != 0)
            {
                accumulator = AddPoints(accumulator, basePoint);
            }
        }

        return accumulator;
    }


    /// <summary>Renes–Costello–Batina Algorithm 1 over concrete canonical elements, the same complete addition the circuit emits.</summary>
    /// <param name="p1">The first point.</param>
    /// <param name="p2">The second point.</param>
    /// <returns>The sum.</returns>
    private ProjectivePoint AddPoints(ProjectivePoint p1, ProjectivePoint p2)
    {
        byte[] t0 = Mul(p1.X, p2.X);
        byte[] t1 = Mul(p1.Y, p2.Y);
        byte[] t2 = Mul(p1.Z, p2.Z);
        byte[] t3 = AddF(p1.X, p1.Y);
        byte[] t4 = AddF(p2.X, p2.Y);
        t3 = Mul(t3, t4);
        t4 = AddF(t0, t1);
        t3 = SubF(t3, t4);
        t4 = AddF(p1.X, p1.Z);
        byte[] t5 = AddF(p2.X, p2.Z);
        t4 = Mul(t4, t5);
        t5 = AddF(t0, t2);
        t4 = SubF(t4, t5);
        t5 = AddF(p1.Y, p1.Z);
        byte[] x3 = AddF(p2.Y, p2.Z);
        t5 = Mul(t5, x3);
        x3 = AddF(t1, t2);
        t5 = SubF(t5, x3);
        byte[] z3 = Mul(curveA, t4);
        x3 = Mul(curveBTimes3, t2);
        z3 = AddF(x3, z3);
        x3 = SubF(t1, z3);
        z3 = AddF(t1, z3);
        byte[] y3 = Mul(x3, z3);
        t1 = AddF(t0, t0);
        t1 = AddF(t1, t0);
        t2 = Mul(curveA, t2);
        t4 = Mul(curveBTimes3, t4);
        t1 = AddF(t1, t2);
        t2 = SubF(t0, t2);
        t2 = Mul(curveA, t2);
        t4 = AddF(t4, t2);
        t0 = Mul(t1, t4);
        y3 = AddF(y3, t0);
        t0 = Mul(t5, t4);
        x3 = Mul(t3, x3);
        x3 = SubF(x3, t0);
        t0 = Mul(t3, t1);
        z3 = Mul(t5, z3);
        z3 = AddF(z3, t0);

        return new ProjectivePoint(x3, y3, z3);
    }


    /// <summary>Renes–Costello–Batina Algorithm 3 over concrete canonical elements, the same complete doubling the circuit emits.</summary>
    /// <param name="p">The point to double.</param>
    /// <returns>The doubled point.</returns>
    private ProjectivePoint DoublePoint(ProjectivePoint p)
    {
        byte[] t0 = Mul(p.X, p.X);
        byte[] t1 = Mul(p.Y, p.Y);
        byte[] t2 = Mul(p.Z, p.Z);
        byte[] t3 = Mul(p.X, p.Y);
        t3 = AddF(t3, t3);
        byte[] z3 = Mul(p.X, p.Z);
        z3 = AddF(z3, z3);
        byte[] x3 = Mul(curveA, z3);
        byte[] y3 = Mul(curveBTimes3, t2);
        y3 = AddF(x3, y3);
        x3 = SubF(t1, y3);
        y3 = AddF(t1, y3);
        y3 = Mul(x3, y3);
        x3 = Mul(t3, x3);
        z3 = Mul(curveBTimes3, z3);
        t2 = Mul(curveA, t2);
        t3 = SubF(t0, t2);
        t3 = Mul(curveA, t3);
        t3 = AddF(t3, z3);
        z3 = AddF(t0, t0);
        t0 = AddF(z3, t0);
        t0 = AddF(t0, t2);
        t0 = Mul(t0, t3);
        y3 = AddF(y3, t0);
        t2 = Mul(p.Y, p.Z);
        t2 = AddF(t2, t2);
        t0 = Mul(t2, t3);
        x3 = SubF(x3, t0);
        z3 = Mul(t2, t1);
        z3 = AddF(z3, z3);
        z3 = AddF(z3, z3);

        return new ProjectivePoint(x3, y3, z3);
    }


    /// <summary>The reference's <c>normalize</c>: divides x and y by z in place when z is nonzero; the identity representation passes through untouched.</summary>
    /// <param name="point">The point to normalize.</param>
    private void Normalize(ref ProjectivePoint point)
    {
        if(LongfellowCompilerFieldOperations.ElementIsZero(point.Z))
        {
            return;
        }

        Span<byte> inverse = stackalloc byte[Scalar.SizeBytes];
        field.Invert(point.Z, inverse, field.Compiler.Curve);
        byte[] x = new byte[Scalar.SizeBytes];
        byte[] y = new byte[Scalar.SizeBytes];
        field.Compiler.Multiply(point.X, inverse, x, field.Compiler.Curve);
        field.Compiler.Multiply(point.Y, inverse, y, field.Compiler.Curve);
        point = new ProjectivePoint(x, y, field.Compiler.One.ToArray());
    }


    /// <summary>Order-field inversion under the Fermat zero-maps-to-zero convention.</summary>
    /// <param name="value">The canonical value to invert.</param>
    /// <param name="destination">Receives the inverse, or zero for a zero input.</param>
    private void InvertOrder(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        if(LongfellowCompilerFieldOperations.ElementIsZero(value))
        {
            destination.Clear();

            return;
        }

        orderInvert(value, destination, orderCurve);
    }


    /// <summary>The base-field product of two elements.</summary>
    /// <param name="a">The first factor.</param>
    /// <param name="b">The second factor.</param>
    /// <returns>The product.</returns>
    private byte[] Mul(byte[] a, byte[] b)
    {
        var result = new byte[Scalar.SizeBytes];
        field.Compiler.Multiply(a, b, result, field.Compiler.Curve);

        return result;
    }


    /// <summary>The base-field sum of two elements.</summary>
    /// <param name="a">The first addend.</param>
    /// <param name="b">The second addend.</param>
    /// <returns>The sum.</returns>
    private byte[] AddF(byte[] a, byte[] b)
    {
        var result = new byte[Scalar.SizeBytes];
        field.Compiler.Add(a, b, result, field.Compiler.Curve);

        return result;
    }


    /// <summary>The base-field difference of two elements.</summary>
    /// <param name="a">The minuend.</param>
    /// <param name="b">The subtrahend.</param>
    /// <returns>The difference.</returns>
    private byte[] SubF(byte[] a, byte[] b)
    {
        var result = new byte[Scalar.SizeBytes];
        field.Subtract(a, b, result, field.Compiler.Curve);

        return result;
    }


    /// <summary>Reads bit <paramref name="index"/> of a canonical big-endian value, least significant bit first.</summary>
    /// <param name="value">The value.</param>
    /// <param name="index">The bit index.</param>
    /// <returns>The bit.</returns>
    private static int BitAt(ReadOnlySpan<byte> value, int index)
    {
        return (value[Scalar.SizeBytes - 1 - (index / 8)] >> (index % 8)) & 1;
    }


    /// <summary>
    /// The base prime as the bundle's minus-one constant plus one; deriving it from the bundle keeps
    /// every raw-value reduction in agreement with the delegates' own modulus.
    /// </summary>
    /// <param name="field">The base-field bundle.</param>
    /// <returns>The prime, canonical big-endian.</returns>
    internal static byte[] DeriveBasePrime(LongfellowLogicFieldOperations field)
    {
        var prime = new byte[Scalar.SizeBytes];
        field.Compiler.MinusOne.Span.CopyTo(prime);
        for(int i = Scalar.SizeBytes - 1; i >= 0; i--)
        {
            prime[i]++;
            if(prime[i] != 0)
            {
                break;
            }
        }

        return prime;
    }


    /// <summary>Reduces a raw 256-bit value once modulo <paramref name="modulus"/>: values below twice the modulus land in canonical range with a single conditional subtraction.</summary>
    /// <param name="value">The raw big-endian value.</param>
    /// <param name="modulus">The modulus.</param>
    /// <param name="destination">Receives the reduced value.</param>
    private static void ReduceOnce(ReadOnlySpan<byte> value, ReadOnlySpan<byte> modulus, Span<byte> destination)
    {
        bool subtract = CompareBigEndian(value, modulus) >= 0;
        if(!subtract)
        {
            value.CopyTo(destination);

            return;
        }

        int borrow = 0;
        for(int i = Scalar.SizeBytes - 1; i >= 0; i--)
        {
            int difference = value[i] - modulus[i] - borrow;
            borrow = difference < 0 ? 1 : 0;
            destination[i] = (byte)(difference & 0xFF);
        }
    }


    /// <summary>Compares two big-endian values as unsigned integers.</summary>
    /// <param name="a">The first value.</param>
    /// <param name="b">The second value.</param>
    /// <returns>A negative, zero or positive sign.</returns>
    private static int CompareBigEndian(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for(int i = 0; i < Scalar.SizeBytes; i++)
        {
            if(a[i] != b[i])
            {
                return a[i] < b[i] ? -1 : 1;
            }
        }

        return 0;
    }


    /// <summary>Writes one element into the column and advances the cursor.</summary>
    /// <param name="destination">The column.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="element">The element to write.</param>
    private static void WriteElement(Span<byte> destination, ref int cursor, byte[] element)
    {
        element.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
        cursor++;
    }


    /// <summary>Allocates an array of zeroed canonical elements.</summary>
    /// <param name="count">The element count.</param>
    /// <returns>The array.</returns>
    private static byte[][] NewElementArray(int count)
    {
        var array = new byte[count][];
        for(int i = 0; i < count; i++)
        {
            array[i] = new byte[Scalar.SizeBytes];
        }

        return array;
    }
}
