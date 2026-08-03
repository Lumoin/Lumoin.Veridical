using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The evaluation-mode semantic gates for the ported ECDSA verification circuit, following
/// google/longfellow-zk <c>circuits/ecdsa/verify_test.cc</c>: every accepting vector's advice
/// column satisfies <c>VerifySignature3</c> under a panicking evaluation backend, every rejecting
/// vector latches the assertion backend, and the production witness generator's column agrees
/// element for element with the independently written BigInteger reference filler.
/// </summary>
[TestClass]
internal sealed class LongfellowEcdsaVerifyCircuitTests
{
    /// <summary>The field element width in bytes used for every column entry.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The P-256 scalar bit count driving the advice shape.</summary>
    private const int ScalarBitCount = 256;

    /// <summary>The P-256 base field's modulus.</summary>
    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The curve constants shared by the circuit and the witness generator.</summary>
    private static LongfellowEllipticCurveParameters Curve { get; } = LongfellowEllipticCurveParameters.CreateP256();

    /// <summary>The order-field multiplication delegate.</summary>
    private static ScalarMultiplyDelegate OrderMultiply { get; } = P256ScalarMontgomeryBackend.GetMultiply();

    /// <summary>The order-field subtraction delegate.</summary>
    private static ScalarSubtractDelegate OrderSubtract { get; } = P256ScalarMontgomeryBackend.GetSubtract();

    /// <summary>The order-field inversion delegate.</summary>
    private static ScalarInvertDelegate OrderInvert { get; } = P256ScalarMontgomeryBackend.GetInvert();


    /// <summary>Pins that every accepting reference vector's advice satisfies the circuit under a panicking evaluation backend.</summary>
    [TestMethod]
    public void TheAcceptingVectorsSatisfyTheCircuitInEvaluation()
    {
        foreach(LongfellowEcdsaTestVectors.SignatureTuple tuple in LongfellowEcdsaTestVectors.Accepting)
        {
            RunVector(tuple, out bool computed, out LongfellowEvaluationLogicBackend backend);

            Assert.IsTrue(computed, "The accepting vector's witness walk must terminate at the identity.");
            Assert.IsFalse(backend.AssertionFailed, "The accepting vector must satisfy every circuit assertion.");
        }
    }


    /// <summary>Pins that every rejecting reference vector trips at least one circuit assertion.</summary>
    [TestMethod]
    public void TheRejectingVectorsLatchTheAssertionBackend()
    {
        foreach(LongfellowEcdsaTestVectors.SignatureTuple tuple in LongfellowEcdsaTestVectors.Rejecting)
        {
            RunVector(tuple, out _, out LongfellowEvaluationLogicBackend backend);

            Assert.IsTrue(backend.AssertionFailed, "The rejecting vector must trip a circuit assertion.");
        }
    }


    /// <summary>Pins the production witness generator's column against the independently written BigInteger reference filler, element for element.</summary>
    [TestMethod]
    public void TheProductionWitnessAgreesWithTheBigIntegerReference()
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        foreach(LongfellowEcdsaTestVectors.SignatureTuple tuple in LongfellowEcdsaTestVectors.Accepting)
        {
            var generator = new LongfellowEcdsaVerifyWitness(field, OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve);
            byte[] pkX = ParseScalar(tuple.PkX);
            byte[] pkY = ParseScalar(tuple.PkY);
            byte[] e = ParseScalar(tuple.E);
            byte[] r = ParseScalar(tuple.R);
            byte[] s = ParseScalar(tuple.S);

            Assert.IsTrue(generator.ComputeWitness(pkX, pkY, e, r, s), "The accepting vector must produce a witness.");

            byte[] column = new byte[generator.ElementCount * ScalarSize];
            generator.FillWitness(column);

            System.Collections.Generic.IReadOnlyList<byte[]> reference = EcdsaSignatureWitness.Fill(
                ToBigInteger(pkX), ToBigInteger(pkY), ToBigInteger(e), ToBigInteger(r), ToBigInteger(s));

            Assert.AreEqual(reference.Count, generator.ElementCount, "Both fillers must emit the same column length.");
            for(int i = 0; i < reference.Count; i++)
            {
                Assert.AreSequenceEqual(reference[i], column.AsSpan(i * ScalarSize, ScalarSize).ToArray(), $"Column element {i} must agree between the production and reference fillers.");
            }
        }
    }


    /// <summary>
    /// Computes a vector's advice with the production generator, interns it as evaluation-backend
    /// wires in the declaration order, and runs <c>VerifySignature3</c> under a latching backend.
    /// </summary>
    /// <param name="tuple">The signature vector.</param>
    /// <param name="computed">Receives the witness walk's verdict.</param>
    /// <param name="backend">Receives the backend for latch inspection.</param>
    private static void RunVector(LongfellowEcdsaTestVectors.SignatureTuple tuple, out bool computed, out LongfellowEvaluationLogicBackend backend)
    {
        LongfellowLogicFieldOperations field = NewFp256Bundle();
        backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);

        byte[] pkX = ParseScalar(tuple.PkX);
        byte[] pkY = ParseScalar(tuple.PkY);
        byte[] e = ParseScalar(tuple.E);
        byte[] r = ParseScalar(tuple.R);
        byte[] s = ParseScalar(tuple.S);

        var generator = new LongfellowEcdsaVerifyWitness(field, OrderMultiply, OrderSubtract, OrderInvert, CurveParameterSet.P256, Curve);
        computed = generator.ComputeWitness(pkX, pkY, e, r, s);

        byte[] column = new byte[generator.ElementCount * ScalarSize];
        generator.FillWitness(column);

        LongfellowEcdsaVerifyWitnessWires wires = InternColumn(backend, column);
        var circuit = new LongfellowEcdsaVerifyCircuit(logic, Curve);
        circuit.VerifySignature3(backend.Constant(pkX), backend.Constant(pkY), backend.Constant(e), wires);
    }


    /// <summary>
    /// Interns an advice column as evaluation wires in the exact order
    /// <see cref="LongfellowEcdsaVerifyWitnessWires.Input"/> declares them, which is also the
    /// column's emit order — so this helper doubles as an order gate between the generator and the
    /// circuit's declaration.
    /// </summary>
    /// <param name="backend">The evaluation backend to intern into.</param>
    /// <param name="column">The advice column.</param>
    /// <returns>The wire bundle.</returns>
    private static LongfellowEcdsaVerifyWitnessWires InternColumn(LongfellowEvaluationLogicBackend backend, byte[] column)
    {
        int cursor = 0;
        int Next()
        {
            int wire = backend.Constant(column.AsSpan(cursor * ScalarSize, ScalarSize));
            cursor++;

            return wire;
        }

        int rx = Next();
        int ry = Next();
        int rxInverse = Next();
        int sInverse = Next();
        int pkInverse = Next();

        var pre = new int[LongfellowEcdsaVerifyWitnessWires.PreTableLength];
        for(int i = 0; i < pre.Length; i++)
        {
            pre[i] = Next();
        }

        var bi = new int[ScalarBitCount];
        var intX = new int[ScalarBitCount - 1];
        var intY = new int[ScalarBitCount - 1];
        var intZ = new int[ScalarBitCount - 1];
        for(int i = 0; i < ScalarBitCount; i++)
        {
            bi[i] = Next();
            if(i < ScalarBitCount - 1)
            {
                intX[i] = Next();
                intY[i] = Next();
                intZ[i] = Next();
            }
        }

        return new LongfellowEcdsaVerifyWitnessWires(rx, ry, rxInverse, sInverse, pkInverse, pre, bi, intX, intY, intZ);
    }


    /// <summary>Builds the P-256 base field bundle over the BigInteger reference delegates.</summary>
    /// <returns>The bundle.</returns>
    private static LongfellowLogicFieldOperations NewFp256Bundle()
    {
        return LongfellowLogicFieldOperations.CreateFp256(
            P256BaseFieldReference.GetAdd(),
            P256BaseFieldReference.GetSubtract(),
            P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(),
            Canonical(Prime - 1));
    }


    /// <summary>Parses a reference vector scalar — hexadecimal with a <c>0x</c> prefix or plain decimal — into its canonical big-endian form.</summary>
    /// <param name="text">The scalar text.</param>
    /// <returns>The canonical bytes.</returns>
    private static byte[] ParseScalar(string text)
    {
        BigInteger value = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? BigInteger.Parse("0" + text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture)
            : BigInteger.Parse(text, CultureInfo.InvariantCulture);

        return Canonical(value);
    }


    /// <summary>Encodes a non-negative integer as a canonical big-endian scalar, zero-padded to <see cref="ScalarSize"/> bytes.</summary>
    /// <param name="value">The non-negative integer to encode.</param>
    /// <returns>The canonical bytes.</returns>
    private static byte[] Canonical(BigInteger value)
    {
        byte[] canonical = new byte[ScalarSize];
        byte[] bigEndian = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        bigEndian.CopyTo(canonical.AsSpan(ScalarSize - bigEndian.Length));

        return canonical;
    }


    /// <summary>Reads a canonical big-endian scalar as an unsigned integer.</summary>
    /// <param name="canonical">The canonical bytes.</param>
    /// <returns>The integer.</returns>
    private static BigInteger ToBigInteger(ReadOnlySpan<byte> canonical)
    {
        return new BigInteger(canonical, isUnsigned: true, isBigEndian: true);
    }
}
