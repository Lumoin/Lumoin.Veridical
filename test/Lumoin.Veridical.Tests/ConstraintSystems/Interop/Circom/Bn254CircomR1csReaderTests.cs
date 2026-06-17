using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Pipelines;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;

/// <summary>
/// BN254 counterpart of <see cref="CircomR1csReaderTests"/>: parses the
/// BN254 multiplier2 <c>.r1cs</c> fixture (the BLS bytes with the header
/// prime swapped to BN254's <c>r</c>) requested under
/// <see cref="CurveParameterSet.Bn254"/>, and proves/verifies the parsed
/// instance with the BN254 base Spartan backends. Exercises the
/// CircomR1csReader's BN254 prime dispatch (U.9) and the U.10 curve-broadened
/// construction path end-to-end from a parsed fixture.
/// </summary>
[TestClass]
internal sealed class Bn254CircomR1csReaderTests
{
    [TestMethod]
    public void Bn254Multiplier2R1csParsesIntoExpectedShape()
    {
        using RawR1csInstance instance = ReadFixture(CircomR1csFixtures.Bn254Multiplier2Bytes);

        Assert.AreEqual(2, instance.A.RowCount, "A.RowCount");
        Assert.AreEqual(4, instance.A.ColumnCount, "A.ColumnCount");
        Assert.AreEqual(0, instance.PublicInputCount, "PublicInputCount");

        Assert.AreEqual(2, instance.A.NonzeroCount, "A.NonzeroCount");
        Assert.AreEqual(2, instance.B.NonzeroCount, "B.NonzeroCount");
        Assert.AreEqual(2, instance.C.NonzeroCount, "C.NonzeroCount");

        //Same triples as the BLS fixture — C0: a*b=c, C1: 1*1=1 padding.
        Assert.AreEqual((0, 2), instance.A.GetTriplePosition(0), "A[0] at constraint 0, wire 2 (a)");
        Assert.AreEqual((0, 3), instance.B.GetTriplePosition(0), "B[0] at constraint 0, wire 3 (b)");
        Assert.AreEqual((0, 1), instance.C.GetTriplePosition(0), "C[0] at constraint 0, wire 1 (c)");

        Assert.AreEqual(CurveParameterSet.Bn254.Code, instance.Curve.Code, "parsed instance curve");
    }


    [TestMethod]
    public void Bn254Multiplier2RequestedAsBls12Curve381Rejected()
    {
        //The BN254-prime file requested under BLS12-381 is a prime mismatch and
        //must be rejected — the mirror of the BLS suite's Bn254-field rejection.
        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(
                CircomR1csFixtures.Bn254Multiplier2Bytes, CurveParameterSet.Bls12Curve381);
        });
    }


    [TestMethod]
    public void Bn254Multiplier2ParsedInstanceProvesAndVerifiesWithStandardSpartan()
    {
        const int rowCount = 2;
        const int columnCount = 4;

        using RawR1csWitness witness = BuildMultiplier2Witness();
        using SpartanProver prover = BuildBaseProver(columnCount);
        using SpartanVerifier verifier = BuildBaseVerifier(columnCount);

        using RawR1csInstance proverInstance = ReadFixture(CircomR1csFixtures.Bn254Multiplier2Bytes);
        using RawR1csInstance verifierInstance = ReadFixture(CircomR1csFixtures.Bn254Multiplier2Bytes);
        Assert.AreEqual(rowCount, proverInstance.A.RowCount);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);

        Assert.IsTrue(verified, "Base Spartan failed to verify a Circom-parsed BN254 multiplier2 instance.");
    }


    private static RawR1csInstance ReadFixture(byte[] fixtureBytes) =>
        ReadFixture(fixtureBytes, CurveParameterSet.Bn254);


    private static RawR1csInstance ReadFixture(byte[] fixtureBytes, CurveParameterSet curve)
    {
        var stream = new MemoryStream(fixtureBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            curve,
            Pool,
            CancellationToken.None);
    }


    private static RawR1csWitness BuildMultiplier2Witness()
    {
        //z = (1, c, a, b) = (1, 33, 3, 11): a*b=c with a=3, b=11.
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(33), witness[..scalarSize]);
        WriteCanonical(new BigInteger(3), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(11), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, CurveParameterSet.Bn254, Pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver.")]
    private static SpartanProver BuildBaseProver(int columnCount)
    {
        return new SpartanProver(new SpartanProvingKey(BuildProvider(BuildCommitmentKey(columnCount))));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier.")]
    private static SpartanVerifier BuildBaseVerifier(int columnCount)
    {
        return new SpartanVerifier(new SpartanVerifyingKey(BuildProvider(BuildCommitmentKey(columnCount))));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bn254,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the caller.")]
    private static HyraxCommitmentKey BuildCommitmentKey(int columnCount)
    {
        int columnVariableCount = BitOperations.Log2((uint)columnCount);
        HyraxCommitmentDimensions commitmentDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);
        return HyraxCommitmentKey.Derive(
            commitmentDims.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bn254, HashToCurve, Pool);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bn254BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % r) + r) % r;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = Bn254BigIntegerScalarReference.GetAdd();
    private static ScalarSubtractDelegate Subtract { get; } = Bn254BigIntegerScalarReference.GetSubtract();
    private static ScalarMultiplyDelegate Multiply { get; } = Bn254BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate Invert { get; } = Bn254BigIntegerScalarReference.GetInvert();
    private static ScalarRandomDelegate ScalarRandom { get; } = Bn254BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bn254Msm;
    private static G1HashToCurveDelegate HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;
}
