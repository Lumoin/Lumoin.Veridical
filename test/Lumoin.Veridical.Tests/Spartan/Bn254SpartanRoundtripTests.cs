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
/// End-to-end BN254 Spartan round-trip: the prover proves a satisfying witness
/// over BN254 and the verifier accepts. The BN254 counterpart of
/// <see cref="SpartanRoundtripTests"/>. Field arithmetic comes from the env-aware
/// BN254 bundle (SIMD when supported, BigInteger otherwise — byte-identical); the
/// rest is the BN254 reference. This is the U.10 test that exercises the construction
/// code opened in U.9 with a real second curve.
/// </summary>
[TestClass]
internal sealed class Bn254SpartanRoundtripTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bn254.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bn254.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bn254.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bn254.Invert;
    private static ScalarRandomDelegate Random { get; } = Bn254BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bn254Msm;
    private static G1HashToCurveDelegate HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    private static readonly BigInteger Order = Bn254BigIntegerScalarReference.FieldOrder;
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public void ProverAndVerifierAgreeOnSatisfyingWitnessSmall()
    {
        //(m=2, n=4): z[1]·z[2]=z[3] plus the trivial padding z[0]·z[0]=z[0].
        ExerciseRoundtrip(rowCount: 2, columnCount: 4);
    }


    [TestMethod]
    public void ProverAndVerifierAgreeWithPublicInput()
    {
        //(m=2, n=4) with one public input: w0·w1 = public; z = (1, 15, 3, 5).
        ExerciseRoundtripWithPublic(rowCount: 2, columnCount: 4);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; disposal happens before the assertion completes.")]
    private static void ExerciseRoundtrip(int rowCount, int columnCount)
    {
        int columnVariableCount = BitOperations.Log2((uint)columnCount);
        HyraxCommitmentDimensions commitmentDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);

        using SpartanProver prover = BuildProver(commitmentDims.ColumnCount);
        using SpartanVerifier verifier = BuildVerifier(commitmentDims.ColumnCount);

        using RawR1csInstance proverInstance = BuildOneMultiplyInstance(rowCount, columnCount);
        using RawR1csInstance verifierInstance = BuildOneMultiplyInstance(rowCount, columnCount);
        using RawR1csWitness witness = BuildOneMultiplyWitness();

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);

        Assert.IsTrue(verified, $"BN254 round-trip verification failed for m={rowCount}, n={columnCount}.");
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; disposal happens before the assertion completes.")]
    private static void ExerciseRoundtripWithPublic(int rowCount, int columnCount)
    {
        int columnVariableCount = BitOperations.Log2((uint)columnCount);
        HyraxCommitmentDimensions commitmentDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);

        using SpartanProver prover = BuildProver(commitmentDims.ColumnCount);
        using SpartanVerifier verifier = BuildVerifier(commitmentDims.ColumnCount);

        using RawR1csInstance proverInstance = BuildPublicInputInstance(rowCount, columnCount);
        using RawR1csInstance verifierInstance = BuildPublicInputInstance(rowCount, columnCount);
        using RawR1csWitness witness = BuildPublicInputWitness();

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);

        Assert.IsTrue(verified, "BN254 round-trip with a public input failed.");
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver.")]
    private static SpartanProver BuildProver(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bn254, HashToCurve, Pool);
        return new SpartanProver(new SpartanProvingKey(BuildProvider(commitmentKey)));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier.")]
    private static SpartanVerifier BuildVerifier(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bn254, HashToCurve, Pool);
        return new SpartanVerifier(new SpartanVerifyingKey(BuildProvider(commitmentKey)));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bn254,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);
    }


    private static RawR1csInstance BuildOneMultiplyInstance(int rowCount, int columnCount)
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> aCols = [1, 0];
        ReadOnlySpan<int> bCols = [2, 0];
        ReadOnlySpan<int> cCols = [3, 0];
        ReadOnlySpan<int> rows = [0, 1];

        Span<byte> ones = stackalloc byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, ones[..scalarSize]);
        WriteCanonical(BigInteger.One, ones.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, ones, rowCount, columnCount, CurveParameterSet.Bn254, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, ones, rowCount, columnCount, CurveParameterSet.Bn254, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, ones, rowCount, columnCount, CurveParameterSet.Bn254, Pool);
        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, Pool);
    }


    private static RawR1csWitness BuildOneMultiplyWitness()
    {
        //z = (1, 3, 5, 15): c0 3·5=15, c1 1·1=1.
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, CurveParameterSet.Bn254, Pool);
    }


    private static RawR1csInstance BuildPublicInputInstance(int rowCount, int columnCount)
    {
        //z = (1, public, w0, w1); c0: z[2]·z[3]=z[1]; c1 padding.
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = [0, 1];
        ReadOnlySpan<int> aCols = [2, 0];
        ReadOnlySpan<int> bCols = [3, 0];
        ReadOnlySpan<int> cCols = [1, 0];

        Span<byte> ones = stackalloc byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, ones[..scalarSize]);
        WriteCanonical(BigInteger.One, ones.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, ones, rowCount, columnCount, CurveParameterSet.Bn254, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, ones, rowCount, columnCount, CurveParameterSet.Bn254, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, ones, rowCount, columnCount, CurveParameterSet.Bn254, Pool);

        Span<byte> publicInput = stackalloc byte[scalarSize];
        WriteCanonical(new BigInteger(15), publicInput);
        return RawR1csInstance.Create(a, b, c, publicInput, Pool);
    }


    private static RawR1csWitness BuildPublicInputWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[2 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, CurveParameterSet.Bn254, Pool);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger nonNegative = ((value % Order) + Order) % Order;
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
