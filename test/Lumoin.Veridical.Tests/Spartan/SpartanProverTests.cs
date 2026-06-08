using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end smoke tests for <see cref="SpartanProver"/>. Builds a
/// small two-multiplication R1CS instance, runs <c>Prove</c> with a
/// satisfying witness, and exercises the witness-satisfaction
/// preflight check with a deliberately broken witness.
/// </summary>
[TestClass]
internal sealed class SpartanProverTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    private const int RowCount = 2;
    private const int ColumnCount = 8;
    private const int WitnessSize = 7;
    private const int HyraxVectorLength = 4;


    [TestMethod]
    public void ProveOnSatisfyingWitnessProducesWellFormedProof()
    {
        using SpartanProver prover = BuildProver();
        using RawR1csInstance instance = BuildTwoMultiplyInstance();
        using RawR1csWitness witness = BuildSatisfyingWitness(x: 3, y: 5, p: 2, q: 7);
        using FiatShamirTranscript transcript = FreshTranscript();

        using SpartanProof proof = prover.Prove(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            SensitiveMemoryPool<byte>.Shared);

        //Structural checks: round counts match the instance dimensions.
        int expectedOuterRounds = BitOperations.Log2((uint)RowCount);
        int expectedInnerRounds = BitOperations.Log2((uint)ColumnCount);
        Assert.AreEqual(expectedOuterRounds, proof.OuterRoundCount);
        Assert.AreEqual(expectedInnerRounds, proof.InnerRoundCount);
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, proof.Curve);

        for(int i = 0; i < proof.OuterRoundCount; i++)
        {
            Assert.AreEqual(3 * Scalar.SizeBytes, proof.GetOuterRoundCompressedBytes(i).Length);
        }
        for(int i = 0; i < proof.InnerRoundCount; i++)
        {
            Assert.AreEqual(2 * Scalar.SizeBytes, proof.GetInnerRoundCompressedBytes(i).Length);
        }

        Assert.AreEqual(AlgebraicRole.ZkProof, proof.Tag.Get<AlgebraicRole>());
    }


    [TestMethod]
    public void ProveOnUnsatisfyingWitnessThrowsR1csNotSatisfied()
    {
        using SpartanProver prover = BuildProver();
        using RawR1csInstance instance = BuildTwoMultiplyInstance();
        using RawR1csWitness brokenWitness = BuildBrokenWitness();
        using FiatShamirTranscript transcript = FreshTranscript();

        var exception = Assert.ThrowsExactly<R1csNotSatisfiedException>(() =>
            _ = prover.Prove(
                instance, brokenWitness, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
                SensitiveMemoryPool<byte>.Shared));

        //Constraint 0 fails (w0 * w1 != w2). The exception carries diagnostic detail.
        Assert.AreEqual(new R1csConstraintIndex(0), exception.ConstraintIndex);
        Assert.AreEqual("c_0", exception.ConstraintIndexDisplay);
        Assert.IsNotNull(exception.LeftHandSideHex);
        Assert.IsNotNull(exception.RightHandSideHex);
        Assert.AreNotEqual(exception.LeftHandSideHex, exception.RightHandSideHex);
        //Constraint 0 references variables w0 = z[1] (in A), w1 = z[2] (in B), w2 = z[3] (in C).
        Assert.HasCount(3, exception.InvolvedVariables);
    }


    [TestMethod]
    public void ProveBuildsProofOfCorrectByteLength()
    {
        //Cross-checks the SpartanProof.GetBufferSizeBytes computation.
        using SpartanProver prover = BuildProver();
        using RawR1csInstance instance = BuildTwoMultiplyInstance();
        using RawR1csWitness witness = BuildSatisfyingWitness(x: 11, y: 13, p: 17, q: 19);
        using FiatShamirTranscript transcript = FreshTranscript();

        using SpartanProof proof = prover.Prove(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            SensitiveMemoryPool<byte>.Shared);

        int expectedLength = SpartanProof.GetBufferSizeBytes(
            proof.WitnessCommitmentRowCount,
            proof.OuterRoundCount,
            proof.InnerRoundCount,
            proof.IpaRoundCount,
            proof.ErrorIpaRoundCount,
            proof.Curve);
        Assert.AreEqual(expectedLength, proof.AsReadOnlySpan().Length);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the HyraxCommitmentKey and SpartanProvingKey transfers through the chained constructors to the returned SpartanProver, which the test method disposes via the using declaration.")]
    private static SpartanProver BuildProver()
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            HyraxVectorLength,
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

        return new SpartanProver(provingKey);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            SensitiveMemoryPool<byte>.Shared);
    }


    /// <summary>
    /// Builds a 2×8 R1CS instance encoding two independent multiplication
    /// constraints:
    ///   c0: z[1] · z[2] = z[3]
    ///   c1: z[4] · z[5] = z[6]
    /// with z = (1, w0, w1, w2, w3, w4, w5, w6), zero public inputs,
    /// witness length 7. Both rows and columns are powers of two.
    /// </summary>
    private static RawR1csInstance BuildTwoMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        const int Nnz = 2;
        int[] aRows = [0, 1];
        int[] aCols = [1, 4];
        int[] bRows = [0, 1];
        int[] bCols = [2, 5];
        int[] cRows = [0, 1];
        int[] cCols = [3, 6];

        byte[] onesValues = new byte[Nnz * scalarSize];
        WriteCanonical(BigInteger.One, onesValues.AsSpan(0, scalarSize));
        WriteCanonical(BigInteger.One, onesValues.AsSpan(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, RowCount, ColumnCount, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, RowCount, ColumnCount, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, RowCount, ColumnCount, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, SensitiveMemoryPool<byte>.Shared);
    }


    private static RawR1csWitness BuildSatisfyingWitness(int x, int y, int p, int q)
    {
        //Witness: (x, y, x*y, p, q, p*q, 0). w6 unused.
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[WitnessSize * scalarSize];
        WriteCanonical(new BigInteger(x), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(y), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger((long)x * y), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(p), witnessBytes.AsSpan(3 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(q), witnessBytes.AsSpan(4 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger((long)p * q), witnessBytes.AsSpan(5 * scalarSize, scalarSize));
        WriteCanonical(BigInteger.Zero, witnessBytes.AsSpan(6 * scalarSize, scalarSize));

        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
    }


    private static RawR1csWitness BuildBrokenWitness()
    {
        //Witness: (3, 5, 16, 2, 7, 14, 0). The third element should be 15 to satisfy c0; setting it to 16 violates it.
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[WitnessSize * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(16), witnessBytes.AsSpan(2 * scalarSize, scalarSize)); //wrong on purpose
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