using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Diagnostics;

/// <summary>
/// Tests for the <see cref="SpartanProofInspector"/> shape: construct a
/// proof for a known small circuit and assert the inspector's report
/// matches the expected dimensions.
/// </summary>
[TestClass]
internal sealed class SpartanProofInspectorTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();


    [TestMethod]
    public void InspectReturnsExpectedDimensions()
    {
        //2-multiplication circuit: m=2, n=8 → outer rounds = 1, inner rounds = 3.
        //Hyrax dimensions for variable count 3: row count = 4, column count = 2; IPA rounds = log_2(2) = 1.
        using SpartanProof proof = BuildProof();
        SpartanProofReport report = SpartanProofInspector.Inspect(proof);

        Assert.AreEqual(4, report.WitnessCommitmentRowCount);
        Assert.AreEqual(1, report.OuterRoundCount);
        Assert.AreEqual(3, report.InnerRoundCount);
        Assert.AreEqual(1, report.IpaRoundCount);
        Assert.AreEqual(proof.AsReadOnlySpan().Length, report.TotalByteLength);
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, report.Curve);
    }


    [TestMethod]
    public void InspectReportsTagSummaryWithExpectedEntries()
    {
        using SpartanProof proof = BuildProof();
        SpartanProofReport report = SpartanProofInspector.Inspect(proof);

        Assert.IsNotNull(report.TagSummary);
        Assert.Contains("AlgebraicRole", report.TagSummary);
        Assert.Contains("CurveParameterSet", report.TagSummary);
        Assert.Contains("SpartanProofDimensions", report.TagSummary);
    }


    [TestMethod]
    public void InspectRejectsNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => SpartanProofInspector.Inspect(null!));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers via using.")]
    private static SpartanProof BuildProof()
    {
        using RawR1csInstance instance = BuildInstance();
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            2,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            SensitiveMemoryPool<byte>.Shared);
        var provingKey = new SpartanProvingKey(HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true));
        using var prover = new SpartanProver(provingKey);
        using RawR1csWitness witness = BuildWitness();
        using FiatShamirTranscript transcript = FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            SensitiveMemoryPool<byte>.Shared);

        return prover.Prove(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            SensitiveMemoryPool<byte>.Shared);
    }


    private static RawR1csInstance BuildInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        int[] aRows = [0, 1];
        int[] aCols = [1, 4];
        int[] bRows = [0, 1];
        int[] bCols = [2, 5];
        int[] cRows = [0, 1];
        int[] cCols = [3, 6];

        byte[] onesValues = new byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, onesValues.AsSpan(0, scalarSize));
        WriteCanonical(BigInteger.One, onesValues.AsSpan(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, 2, 8, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, 2, 8, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, 2, 8, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, SensitiveMemoryPool<byte>.Shared);
    }


    private static RawR1csWitness BuildWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[7 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(2), witnessBytes.AsSpan(3 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(7), witnessBytes.AsSpan(4 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(14), witnessBytes.AsSpan(5 * scalarSize, scalarSize));
        WriteCanonical(BigInteger.Zero, witnessBytes.AsSpan(6 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
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
}