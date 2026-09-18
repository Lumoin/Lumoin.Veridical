using Lumoin.Veridical.Backends.Managed;
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
/// rest is the BN254 reference. The construction is curve-generic, so this
/// exercises the same prove/verify path with a real second curve rather than
/// only BLS12-381.
/// </summary>
[TestClass]
internal sealed class Bn254SpartanRoundtripTests
{
    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF (squeeze) backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BN254 scalar reduction delegate (wide bytes to a canonical scalar), from the BigInteger reference.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();

    /// <summary>The BN254 scalar field addition delegate, from the environment-aware bundle (SIMD when the host supports it, BigInteger otherwise) — byte-identical to the reference.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bn254.Add;

    /// <summary>The BN254 scalar field subtraction delegate, from the same environment-aware bundle as <see cref="Add"/>.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bn254.Subtract;

    /// <summary>The BN254 scalar field multiplication delegate, from the same environment-aware bundle as <see cref="Add"/>.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bn254.Multiply;

    /// <summary>The BN254 scalar field inversion delegate, from the same environment-aware bundle as <see cref="Add"/>.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bn254.Invert;

    /// <summary>The BN254 scalar sampler the prover's blinds and challenges are drawn from, from the BigInteger reference.</summary>
    private static ScalarRandomDelegate Random { get; } = Bn254BigIntegerScalarReference.GetRandom();

    /// <summary>The BN254 G1 point addition delegate, from the BigInteger reference.</summary>
    private static G1AddDelegate G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();

    /// <summary>The BN254 G1 scalar-multiplication delegate, from the BigInteger reference.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BN254 G1 multi-scalar-multiplication delegate, from the test backend.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bn254Msm;

    /// <summary>The BN254 G1 on-curve check delegate, from the BigInteger reference.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bn254BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>The BN254 G1 prime-order-subgroup membership delegate, from the BigInteger reference.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bn254BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    /// <summary>The BN254 G1 hash-to-curve delegate the Hyrax commitment key derives its generators with, from the BigInteger reference.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The independent BigInteger-reference multilinear-extension evaluator the sumcheck rounds use.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The independent BigInteger-reference multilinear-extension fold the sumcheck rounds use.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    /// <summary>The BN254 scalar field order, the modulus <see cref="WriteCanonical"/> reduces every constructed witness and instance value against.</summary>
    private static BigInteger Order { get; } = Bn254BigIntegerScalarReference.FieldOrder;

    /// <summary>The shared pool every rental in this file draws from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>Verifies that the BN254 prover and verifier agree on a small, purely private satisfying witness (<c>m=2, n=4</c>: <c>z[1]·z[2]=z[3]</c> plus the trivial padding row <c>z[0]·z[0]=z[0]</c>).</summary>
    [TestMethod]
    public void ProverAndVerifierAgreeOnSatisfyingWitnessSmall()
    {
        //(m=2, n=4): z[1]·z[2]=z[3] plus the trivial padding z[0]·z[0]=z[0].
        ExerciseRoundtrip(rowCount: 2, columnCount: 4);
    }


    /// <summary>Verifies that the BN254 prover and verifier agree when the instance carries one public input (<c>m=2, n=4</c>, one public input: <c>w0·w1 = public</c>; <c>z = (1, 15, 3, 5)</c>).</summary>
    [TestMethod]
    public void ProverAndVerifierAgreeWithPublicInput()
    {
        //(m=2, n=4) with one public input: w0·w1 = public; z = (1, 15, 3, 5).
        ExerciseRoundtripWithPublic(rowCount: 2, columnCount: 4);
    }


    /// <summary>Proves and verifies the purely private one-multiply instance of the given shape over BN254, asserting the verifier accepts.</summary>
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


    /// <summary>Proves and verifies the one-public-input instance of the given shape over BN254, asserting the verifier accepts.</summary>
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


    /// <summary>Builds a BN254 Spartan prover over a freshly derived Hyrax commitment key sized to <paramref name="hyraxVectorLength"/>.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver.")]
    private static SpartanProver BuildProver(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bn254, HashToCurve, Pool);
        return new SpartanProver(new SpartanProvingKey(BuildProvider(commitmentKey)));
    }


    /// <summary>Builds a BN254 Spartan verifier over a freshly derived Hyrax commitment key sized to <paramref name="hyraxVectorLength"/>.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier.")]
    private static SpartanVerifier BuildVerifier(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bn254, HashToCurve, Pool);
        return new SpartanVerifier(new SpartanVerifyingKey(BuildProvider(commitmentKey)));
    }


    /// <summary>Wraps <paramref name="commitmentKey"/> as a BN254 Hyrax polynomial-commitment provider, taking ownership of the key.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bn254,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup,
            ownsKey: true);
    }


    /// <summary>Creates a fresh transcript under the Spartan v1 domain label, seeded with no extra context bytes.</summary>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);
    }


    /// <summary>Builds the purely private one-multiply R1CS instance of the given shape: row 0 is <c>z[1]·z[2]=z[3]</c>, row 1 the trivial padding <c>z[0]·z[0]=z[0]</c>, with no public input.</summary>
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


    /// <summary>Builds the witness <c>z = (1, 3, 5, 15)</c> satisfying <see cref="BuildOneMultiplyInstance"/>: row 0 <c>3·5=15</c>, row 1 <c>1·1=1</c>.</summary>
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


    /// <summary>Builds the one-public-input R1CS instance of the given shape: witness layout <c>z = (1, public, w0, w1)</c>, row 0 <c>z[2]·z[3]=z[1]</c>, row 1 the trivial padding row.</summary>
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


    /// <summary>Builds the private witness values <c>w0 = 3</c>, <c>w1 = 5</c> satisfying <see cref="BuildPublicInputInstance"/> against its public input <c>15</c>.</summary>
    private static RawR1csWitness BuildPublicInputWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[2 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, CurveParameterSet.Bn254, Pool);
    }


    /// <summary>Reduces <paramref name="value"/> modulo <see cref="Order"/> into a nonnegative representative and writes it as a big-endian canonical scalar.</summary>
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
