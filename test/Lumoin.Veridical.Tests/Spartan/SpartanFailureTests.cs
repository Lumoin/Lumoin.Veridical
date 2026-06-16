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
/// Failure-path tests: the verifier rejects tampered proofs and proofs
/// against the wrong instance. Bit-flip tests exercise every named
/// section of the proof byte layout.
/// </summary>
[TestClass]
internal sealed class SpartanFailureTests
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
    private const int HyraxVectorLength = 2;


    [TestMethod]
    public void WitnessCommitmentBitFlipRejected()
    {
        VerifyBitFlipRejected(proof => 0, "witness commitment");
    }


    [TestMethod]
    public void OuterSumcheckRoundPolynomialBitFlipRejected()
    {
        VerifyBitFlipRejected(
            proof => proof.WitnessCommitmentRowCount * WellKnownCurves.Bls12Curve381G1CompressedSizeBytes,
            "outer round poly");
    }


    [TestMethod]
    public void ClaimedAzBitFlipRejected()
    {
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes),
            "claim_Az");
    }


    [TestMethod]
    public void ClaimedBzBitFlipRejected()
    {
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes)
                + Scalar.SizeBytes,
            "claim_Bz");
    }


    [TestMethod]
    public void ClaimedCzBitFlipRejected()
    {
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes)
                + (2 * Scalar.SizeBytes),
            "claim_Cz");
    }


    [TestMethod]
    public void ErrorEvaluationBitFlipRejected()
    {
        //E(r_x) sits between the three outer claims and the inner rounds.
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes)
                + (3 * Scalar.SizeBytes),
            "E(r_x)");
    }


    [TestMethod]
    public void InnerSumcheckRoundPolynomialBitFlipRejected()
    {
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes)
                + (4 * Scalar.SizeBytes),
            "inner round poly");
    }


    [TestMethod]
    public void EvalWBitFlipRejected()
    {
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes)
                + (4 * Scalar.SizeBytes)
                + (proof.InnerRoundCount * 2 * Scalar.SizeBytes),
            "eval_W");
    }


    [TestMethod]
    public void ErrorOpeningBitFlipRejected()
    {
        //The error-commitment opening proof at r_x precedes the witness
        //opening. Flipping its leading C_f byte breaks the error opening.
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes)
                + (4 * Scalar.SizeBytes)
                + (proof.InnerRoundCount * 2 * Scalar.SizeBytes)
                + Scalar.SizeBytes,
            "error opening");
    }


    [TestMethod]
    public void HyraxOpeningBitFlipRejected()
    {
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes)
                + (4 * Scalar.SizeBytes)
                + (proof.InnerRoundCount * 2 * Scalar.SizeBytes)
                + Scalar.SizeBytes
                + HyraxOpeningProof.GetBufferSizeBytes(proof.ErrorIpaRoundCount, proof.Curve),
            "Hyrax opening");
    }


    [TestMethod]
    public void VerifyAgainstDifferentInstanceRejected()
    {
        //Generate a proof against one instance; attempt to verify against
        //a different instance with the same dimensions.
        using SpartanProver prover = BuildProver();
        using RawR1csInstance proverInstance = BuildTwoMultiplyInstance();
        using RawR1csWitness witness = BuildSatisfyingWitness();
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

        using SpartanVerifier wrongVerifier = BuildVerifier();
        using RawR1csInstance wrongInstance = BuildDifferentMultiplyInstance();
        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = wrongVerifier.Verify(
            proof, wrongInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Verification must reject a proof generated against a different instance.");
    }


    private delegate int ProofOffsetSelector(SpartanProof proof);


    [SuppressMessage("Reliability", "CA2000", Justification = "Test method composes ownership transfers through using declarations; final disposal happens before the assertion completes.")]
    private static void VerifyBitFlipRejected(ProofOffsetSelector offsetSelector, string regionDescription)
    {
        using SpartanProver prover = BuildProver();
        using RawR1csInstance instance = BuildTwoMultiplyInstance();
        using RawR1csWitness witness = BuildSatisfyingWitness();
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof originalProof = prover.Prove(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

        //Copy the proof bytes, flip one byte at the selected offset, and
        //reconstruct a SpartanProof over the tampered bytes for verify.
        byte[] tamperedBytes = originalProof.AsReadOnlySpan().ToArray();
        int offset = offsetSelector(originalProof);
        tamperedBytes[offset] ^= 0xFF;

        //Reconstruct a SpartanProof from the tampered bytes. The
        //SpartanProof internal constructor takes ownership of a buffer
        //owner; we use the public Build path via raw bytes is not
        //available, so we rent + copy + use the internal constructor
        //via FromBytesAdapter, or here just rebuild via a fresh public
        //factory if it existed. For simplicity, we exercise tampering
        //by passing the byte-modified buffer to a fresh proof
        //instance constructed from the raw tampered bytes.
        using SpartanProof tamperedProof = RehydrateProof(
            tamperedBytes,
            originalProof.WitnessCommitmentRowCount,
            originalProof.OuterRoundCount,
            originalProof.InnerRoundCount,
            originalProof.IpaRoundCount,
            originalProof.ErrorIpaRoundCount,
            originalProof.Curve);

        using SpartanVerifier verifier = BuildVerifier();
        using RawR1csInstance verifierInstance = BuildTwoMultiplyInstance();
        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            tamperedProof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsFalse(verified, $"Verification must reject a proof with a flipped byte in the {regionDescription} region (offset {offset}).");
    }


    private static SpartanProof RehydrateProof(
        byte[] proofBytes,
        int witnessRowCount,
        int outerRoundCount,
        int innerRoundCount,
        int ipaRoundCount,
        int errorIpaRoundCount,
        CurveParameterSet curve)
    {
        return SpartanProof.FromBytes(
            proofBytes, witnessRowCount, outerRoundCount, innerRoundCount, ipaRoundCount, errorIpaRoundCount,
            curve, BaseMemoryPool.Shared);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through chained constructors to the returned SpartanProver.")]
    private static SpartanProver BuildProver()
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            HyraxVectorLength,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var provingKey = new SpartanProvingKey(BuildProvider(commitmentKey));

        return new SpartanProver(provingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through chained constructors to the returned SpartanVerifier.")]
    private static SpartanVerifier BuildVerifier()
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            HyraxVectorLength,
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


    private static RawR1csInstance BuildTwoMultiplyInstance()
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

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, RowCount, ColumnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, RowCount, ColumnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, RowCount, ColumnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// A different 2×8 instance: two multiplications wired differently
    /// so the proof for <see cref="BuildTwoMultiplyInstance"/> is not
    /// also a valid proof for this instance.
    /// </summary>
    private static RawR1csInstance BuildDifferentMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        //Different column assignment: c0: z[2] · z[3] = z[4], c1: z[5] · z[6] = z[7].
        int[] aRows = [0, 1];
        int[] aCols = [2, 5];
        int[] bRows = [0, 1];
        int[] bCols = [3, 6];
        int[] cRows = [0, 1];
        int[] cCols = [4, 7];

        byte[] onesValues = new byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, onesValues.AsSpan(0, scalarSize));
        WriteCanonical(BigInteger.One, onesValues.AsSpan(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, RowCount, ColumnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, RowCount, ColumnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, RowCount, ColumnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
    }


    private static RawR1csWitness BuildSatisfyingWitness()
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