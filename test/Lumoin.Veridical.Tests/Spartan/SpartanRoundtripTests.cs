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
using System.Text;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end round-trip tests: the prover constructs a proof for a
/// satisfying witness and the verifier accepts it. Run for several
/// small circuit sizes to exercise the full protocol against varying
/// outer- and inner-sumcheck round counts.
/// </summary>
[TestClass]
internal sealed class SpartanRoundtripTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    //Field ops from the env-aware bundle (SIMD when supported, BigInteger otherwise);
    //byte-identical to the reference, so results — and fixtures — are unchanged.
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


    [TestMethod]
    public void ProverAndVerifierAgreeOnSatisfyingWitnessSmall()
    {
        //(m=2, n=4): one mult constraint padded with a trivial second
        //constraint (z[0] · z[0] = z[0]) which is satisfied by z[0] = 1.
        ExerciseRoundtrip(2, 4, BuildOneMultiplyInstance, BuildOneMultiplyWitness);
    }


    [TestMethod]
    public void ProverAndVerifierAgreeOnSatisfyingWitnessMedium()
    {
        //(m=2, n=8): the two-multiplication circuit from G.2.
        ExerciseRoundtrip(2, 8, BuildTwoMultiplyInstance, BuildTwoMultiplyWitness);
    }


    [TestMethod]
    public void ProverAndVerifierAgreeOnSatisfyingWitnessLarger()
    {
        //(m=4, n=8): four multiplication constraints.
        ExerciseRoundtrip(4, 8, BuildFourMultiplyInstance, BuildFourMultiplyWitness);
    }


    [TestMethod]
    public void ProverAndVerifierAgreeWithPublicInputs()
    {
        //Tests the eval_PublicAndOne computation by including a non-zero
        //public input. Circuit: z[1] · z[2] = z[3], with z[1] public.
        //z layout = (1, public_input, witness_0, witness_1).
        //Satisfying assignment: public_input = 3, w0 = 5, w1 = 15.
        ExerciseRoundtrip(2, 4, BuildMultiplyInstanceWithPublic, BuildMultiplyWitnessWithPublic);
    }


    private delegate RawR1csInstance RawInstanceFactory(int rowCount, int columnCount);
    private delegate RawR1csWitness RawWitnessFactory();


    [SuppressMessage("Reliability", "CA2000", Justification = "Test method composes ownership transfers through using declarations and intermediate references; final disposal happens before the assertion completes.")]
    private static void ExerciseRoundtrip(
        int rowCount,
        int columnCount,
        RawInstanceFactory instanceFactory,
        RawWitnessFactory witnessFactory)
    {
        int columnVariableCount = BitOperations.Log2((uint)columnCount);
        HyraxCommitmentDimensions commitmentDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);

        //Two separate instances of the proving key and verifying key —
        //one for the prover, one for the verifier — built from identical
        //inputs.
        using SpartanProver prover = BuildProver(commitmentDims.ColumnCount);
        using SpartanVerifier verifier = BuildVerifier(commitmentDims.ColumnCount);

        //The instance is now a Prove/Verify parameter, not part of the key;
        //the prover and verifier each take their own copy built from
        //identical inputs.
        using RawR1csInstance proverInstance = instanceFactory(rowCount, columnCount);
        using RawR1csInstance verifierInstance = instanceFactory(rowCount, columnCount);
        using RawR1csWitness witness = witnessFactory();
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsTrue(verified, $"Round-trip verification failed for m={rowCount}, n={columnCount}.");
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver via its constructor chain.")]
    private static SpartanProver BuildProver(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var provingKey = new SpartanProvingKey(BuildProvider(commitmentKey));

        return new SpartanProver(provingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier via its constructor chain.")]
    private static SpartanVerifier BuildVerifier(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(commitmentKey));

        return new SpartanVerifier(verifyingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Builds a 2×4 instance encoding constraint 0: <c>z[1] · z[2] = z[3]</c>
    /// plus a trivial padding constraint 1: <c>z[0] · z[0] = z[0]</c>.
    /// z layout: <c>(1, w0, w1, w2)</c>. Zero public inputs.
    /// </summary>
    private static RawR1csInstance BuildOneMultiplyInstance(int rowCount, int columnCount)
    {
        int scalarSize = Scalar.SizeBytes;
        int[] aRows = [0, 1];
        int[] aCols = [1, 0];
        int[] bRows = [0, 1];
        int[] bCols = [2, 0];
        int[] cRows = [0, 1];
        int[] cCols = [3, 0];

        byte[] onesValues = new byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, onesValues.AsSpan(0, scalarSize));
        WriteCanonical(BigInteger.One, onesValues.AsSpan(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
    }


    private static RawR1csWitness BuildOneMultiplyWitness()
    {
        //Witness: (3, 5, 15). z = (1, 3, 5, 15). c0: 3 * 5 = 15 ✓. c1: 1 * 1 = 1 ✓.
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Builds a 2×8 instance encoding two independent multiplications.
    /// z layout: <c>(1, w0, w1, w2, w3, w4, w5, w6)</c>.
    /// </summary>
    private static RawR1csInstance BuildTwoMultiplyInstance(int rowCount, int columnCount)
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

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
    }


    private static RawR1csWitness BuildTwoMultiplyWitness()
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
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Builds a 4×8 instance with four independent multiplication
    /// constraints. z layout: <c>(1, w0, w1, w2, w3, w4, w5, w6)</c>.
    /// Constraint i: <c>z[2i+1] · z[2i+2] = z[2i+3]</c>... wait,
    /// we want 4 constraints using 7 witness slots. Constraints:
    /// c0: w0 · w1 = w2
    /// c1: w3 · w4 = w5
    /// c2: w0 · w0 = w6   (square gadget)
    /// c3: 1 · 1 = 1     (trivial padding)
    /// </summary>
    private static RawR1csInstance BuildFourMultiplyInstance(int rowCount, int columnCount)
    {
        int scalarSize = Scalar.SizeBytes;
        int[] aRows = [0, 1, 2, 3];
        int[] aCols = [1, 4, 1, 0];
        int[] bRows = [0, 1, 2, 3];
        int[] bCols = [2, 5, 1, 0];
        int[] cRows = [0, 1, 2, 3];
        int[] cCols = [3, 6, 7, 0];

        byte[] onesValues = new byte[4 * scalarSize];
        for(int i = 0; i < 4; i++)
        {
            WriteCanonical(BigInteger.One, onesValues.AsSpan(i * scalarSize, scalarSize));
        }

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
    }


    private static RawR1csWitness BuildFourMultiplyWitness()
    {
        //Witness: w0=3, w1=5, w2=15 (w0·w1), w3=2, w4=7, w5=14 (w3·w4), w6=9 (w0·w0).
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[7 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(2), witnessBytes.AsSpan(3 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(7), witnessBytes.AsSpan(4 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(14), witnessBytes.AsSpan(5 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(9), witnessBytes.AsSpan(6 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// 2×4 instance with one public input. z layout: <c>(1, public, w0, w1)</c>.
    /// c0: <c>z[2] · z[3] = z[1]</c> — that is, w0 · w1 = public.
    /// c1: trivial <c>z[0] · z[0] = z[0]</c>.
    /// </summary>
    private static RawR1csInstance BuildMultiplyInstanceWithPublic(int rowCount, int columnCount)
    {
        int scalarSize = Scalar.SizeBytes;
        int[] aRows = [0, 1];
        int[] aCols = [2, 0];
        int[] bRows = [0, 1];
        int[] bCols = [3, 0];
        int[] cRows = [0, 1];
        int[] cCols = [1, 0];

        byte[] onesValues = new byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, onesValues.AsSpan(0, scalarSize));
        WriteCanonical(BigInteger.One, onesValues.AsSpan(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, rowCount, columnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        byte[] publicInputBytes = new byte[scalarSize];
        WriteCanonical(new BigInteger(15), publicInputBytes);

        return RawR1csInstance.Create(a, b, c, publicInputBytes, BaseMemoryPool.Shared);
    }


    private static RawR1csWitness BuildMultiplyWitnessWithPublic()
    {
        //Witness: w0 = 3, w1 = 5. z = (1, 15, 3, 5). c0: 3 * 5 = 15 ✓. c1: 1 * 1 = 1 ✓.
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[2 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
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