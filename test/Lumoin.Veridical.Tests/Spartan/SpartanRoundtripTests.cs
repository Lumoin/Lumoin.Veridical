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
    /// <summary>The Fiat–Shamir hash delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    /// <summary>The Fiat–Shamir squeeze delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    /// <summary>The BLS12-381 scalar-field canonical-reduction delegate this test proves and verifies over.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    /// <summary>The BLS12-381 scalar-field addition delegate this test proves and verifies over, drawn from the env-aware bundle (SIMD when supported, BigInteger otherwise) that is byte-identical to the reference.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    /// <summary>The BLS12-381 scalar-field subtraction delegate this test proves and verifies over, drawn from the env-aware bundle (SIMD when supported, BigInteger otherwise) that is byte-identical to the reference.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    /// <summary>The BLS12-381 scalar-field multiplication delegate this test proves and verifies over, drawn from the env-aware bundle (SIMD when supported, BigInteger otherwise) that is byte-identical to the reference.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    /// <summary>The BLS12-381 scalar-field inversion delegate this test proves and verifies over, drawn from the env-aware bundle (SIMD when supported, BigInteger otherwise) that is byte-identical to the reference.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    /// <summary>The BLS12-381 scalar-field random-sampling delegate this test's prover draws blinding scalars from.</summary>
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    /// <summary>The BLS12-381 G1 point-addition delegate this test's commitment scheme uses.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    /// <summary>The BLS12-381 G1 scalar-multiplication delegate this test's commitment scheme uses.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    /// <summary>The BLS12-381 G1 multi-scalar-multiplication delegate this test's commitment scheme uses.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    /// <summary>The BLS12-381 G1 on-curve check delegate the Hyrax commitment scheme uses.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    /// <summary>The BLS12-381 G1 prime-order-subgroup check delegate the Hyrax commitment scheme uses.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    /// <summary>The BLS12-381 G1 hash-to-curve delegate used to derive the Hyrax commitment key's generators.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    /// <summary>The multilinear-extension evaluation delegate this test's Spartan prover and verifier use.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    /// <summary>The multilinear-extension folding delegate this test's Spartan prover and verifier use.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();


    /// <summary>Verifies that the prover and verifier agree on a satisfying witness for a small (m=2, n=4) one-multiplication circuit.</summary>
    [TestMethod]
    public void ProverAndVerifierAgreeOnSatisfyingWitnessSmall()
    {
        //(m=2, n=4): one mult constraint padded with a trivial second
        //constraint (z[0] · z[0] = z[0]) which is satisfied by z[0] = 1.
        ExerciseRoundtrip(2, 4, BuildOneMultiplyInstance, BuildOneMultiplyWitness);
    }


    /// <summary>Verifies that the prover and verifier agree on a satisfying witness for a medium (m=2, n=8) two-multiplication circuit.</summary>
    [TestMethod]
    public void ProverAndVerifierAgreeOnSatisfyingWitnessMedium()
    {
        //(m=2, n=8): the two-multiplication circuit.
        ExerciseRoundtrip(2, 8, BuildTwoMultiplyInstance, BuildTwoMultiplyWitness);
    }


    /// <summary>Verifies that the prover and verifier agree on a satisfying witness for a larger (m=4, n=8) four-multiplication circuit.</summary>
    [TestMethod]
    public void ProverAndVerifierAgreeOnSatisfyingWitnessLarger()
    {
        //(m=4, n=8): four multiplication constraints.
        ExerciseRoundtrip(4, 8, BuildFourMultiplyInstance, BuildFourMultiplyWitness);
    }


    /// <summary>Verifies that the prover and verifier agree on a satisfying witness when the circuit carries a non-zero public input.</summary>
    [TestMethod]
    public void ProverAndVerifierAgreeWithPublicInputs()
    {
        //Tests the eval_PublicAndOne computation by including a non-zero
        //public input. Circuit: z[1] · z[2] = z[3], with z[1] public.
        //z layout = (1, public_input, witness_0, witness_1).
        //Satisfying assignment: public_input = 3, w0 = 5, w1 = 15.
        ExerciseRoundtrip(2, 4, BuildMultiplyInstanceWithPublic, BuildMultiplyWitnessWithPublic);
    }


    /// <summary>Builds a raw R1CS instance of the given shape, for <see cref="ExerciseRoundtrip"/> to prove and verify.</summary>
    /// <param name="rowCount">The number of constraint rows the instance's matrices have.</param>
    /// <param name="columnCount">The number of witness columns the instance's matrices have.</param>
    private delegate RawR1csInstance RawInstanceFactory(int rowCount, int columnCount);
    /// <summary>Builds the witness matching a <see cref="RawInstanceFactory"/>-built instance, for <see cref="ExerciseRoundtrip"/> to prove and verify.</summary>
    private delegate RawR1csWitness RawWitnessFactory();


    /// <summary>
    /// Compiles a prover and verifier from identical Hyrax-backed keys, proves the given instance
    /// and witness, and asserts that the verifier accepts the proof.
    /// </summary>
    /// <param name="rowCount">The number of constraint rows to build the instance with.</param>
    /// <param name="columnCount">The number of witness columns to build the instance with.</param>
    /// <param name="instanceFactory">Builds the prover's and the verifier's own copy of the instance.</param>
    /// <param name="witnessFactory">Builds the witness the prover proves against.</param>
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

        //The instance is a Prove/Verify parameter, not part of the key;
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


    /// <summary>Builds a Spartan prover over a fresh Hyrax-backed proving key sized for the given vector length.</summary>
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


    /// <summary>Builds a Spartan verifier over a fresh Hyrax-backed verifying key sized for the given vector length.</summary>
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


    /// <summary>Builds the Hyrax polynomial commitment provider this test's Spartan prover and verifier commit through, over the given commitment key.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup,
            ownsKey: true);
    }


    /// <summary>Creates a fresh Fiat–Shamir transcript for one prove or verify run, seeded with the Spartan domain label.</summary>
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


    /// <summary>Builds the witness <c>(w0, w1, w2) = (3, 5, 15)</c> satisfying <see cref="BuildOneMultiplyInstance"/>.</summary>
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


    /// <summary>Builds the seven-slot witness satisfying <see cref="BuildTwoMultiplyInstance"/>'s two independent multiplications, with the trailing padding slot zero.</summary>
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
    /// Builds a 4×8 instance with four constraints over seven witness slots. z layout:
    /// <c>(1, w0, w1, w2, w3, w4, w5, w6)</c>. Constraints:
    /// c0: <c>w0 · w1 = w2</c>;
    /// c1: <c>w3 · w4 = w5</c>;
    /// c2: <c>w0 · w0 = w6</c> (square gadget);
    /// c3: <c>1 · 1 = 1</c> (trivial padding).
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


    /// <summary>Builds the seven-slot witness satisfying <see cref="BuildFourMultiplyInstance"/>'s four constraints.</summary>
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


    /// <summary>Builds the witness <c>(w0, w1) = (3, 5)</c> satisfying <see cref="BuildMultiplyInstanceWithPublic"/>'s public-output constraint.</summary>
    private static RawR1csWitness BuildMultiplyWitnessWithPublic()
    {
        //Witness: w0 = 3, w1 = 5. z = (1, 15, 3, 5). c0: 3 * 5 = 15 ✓. c1: 1 * 1 = 1 ✓.
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[2 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>Reduces a <see cref="BigInteger"/> modulo the BLS12-381 scalar-field order and writes it as a canonical big-endian scalar.</summary>
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