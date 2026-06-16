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
/// Soundness and failure-path coverage for BN254: an unsatisfying witness is
/// rejected at prove time (base and masked provers), and a valid proof with a
/// single flipped byte is rejected by the verifier. The BN254 counterparts of
/// the BLS <see cref="SpartanFailureTests"/> / <see cref="MaskedSpartanSoundnessTests"/>
/// legs, confirming the U.10 curve-broadened prove/verify path keeps the
/// soundness contract over a second curve.
/// </summary>
[TestClass]
internal sealed class Bn254SpartanSoundnessTests
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
    private static CurveParameterSet Curve => CurveParameterSet.Bn254;
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const int HyraxVectorLength = 2;


    [TestMethod]
    public void BaseSpartanUnsatisfyingWitnessThrowsAtProveTime()
    {
        //z = (1, 3, 5, 99): constraint 0 wants z[1]·z[2] = z[3], i.e. 3·5 = 15,
        //not 99. The R1CS-satisfaction check at the start of Prove rejects it.
        using SpartanProver prover = BuildBaseProver();
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildUnsatisfyingWitness();
        using FiatShamirTranscript transcript = FreshTranscript();

        Assert.ThrowsExactly<R1csNotSatisfiedException>(() =>
        {
            using SpartanProof _ = prover.Prove(
                instance, witness, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);
        });
    }


    [TestMethod]
    public void MaskedSpartanUnsatisfyingWitnessThrowsAtProveTime()
    {
        using MaskedSpartanProver prover = BuildMaskedProver();
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildUnsatisfyingWitness();
        using FiatShamirTranscript transcript = FreshTranscript();

        Assert.ThrowsExactly<R1csNotSatisfiedException>(() =>
        {
            using MaskedSpartanProof _ = prover.Prove(
                instance, witness, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);
        });
    }


    [TestMethod]
    public void WitnessCommitmentBitFlipRejected()
    {
        //Flip the leading byte of the witness commitment (offset 0).
        VerifyBitFlipRejected(_ => 0, "witness commitment");
    }


    [TestMethod]
    public void ClaimAzBitFlipRejected()
    {
        //claim_Az sits after the witness commitment and the outer round
        //polynomials; flipping it breaks the outer terminating identity.
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.GetG1CompressedSizeBytes(proof.Curve))
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes),
            "claim_Az");
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; disposal happens before the assertion completes.")]
    private static void VerifyBitFlipRejected(Func<SpartanProof, int> offsetSelector, string regionDescription)
    {
        using SpartanProver prover = BuildBaseProver();
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildOneMultiplyWitness();
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof originalProof = prover.Prove(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        byte[] tamperedBytes = originalProof.AsReadOnlySpan().ToArray();
        int offset = offsetSelector(originalProof);
        tamperedBytes[offset] ^= 0xFF;

        using SpartanProof tamperedProof = RehydrateProof(tamperedBytes, originalProof);

        using SpartanVerifier verifier = BuildBaseVerifier();
        using RawR1csInstance verifierInstance = BuildOneMultiplyInstance();
        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            tamperedProof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);

        Assert.IsFalse(verified, $"Verification must reject a BN254 proof with a flipped byte in the {regionDescription} region (offset {offset}).");
    }


    private static SpartanProof RehydrateProof(byte[] proofBytes, SpartanProof template)
    {
        return SpartanProof.FromBytes(
            proofBytes,
            template.WitnessCommitmentRowCount,
            template.OuterRoundCount,
            template.InnerRoundCount,
            template.IpaRoundCount,
            template.ErrorIpaRoundCount,
            template.Curve,
            Pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver.")]
    private static SpartanProver BuildBaseProver() =>
        new(new SpartanProvingKey(BuildProvider()));


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier.")]
    private static SpartanVerifier BuildBaseVerifier() =>
        new(new SpartanVerifyingKey(BuildProvider()));


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanProver.")]
    private static MaskedSpartanProver BuildMaskedProver() =>
        new(new SpartanProvingKey(BuildProvider()));


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the caller.")]
    private static HyraxCommitmentKey BuildCommitmentKey() =>
        HyraxCommitmentKey.Derive(
            HyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, Pool);


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider() =>
        HyraxPolynomialCommitmentScheme.Create(
            BuildCommitmentKey(),
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);


    private static FiatShamirTranscript FreshTranscript() =>
        FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);


    //One multiplication plus padding: c0 z[1]·z[2]=z[3], c1 z[0]·z[0]=z[0]. (m=2, n=4).
    private static RawR1csInstance BuildOneMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = [0, 1];
        ReadOnlySpan<int> aCols = [1, 0];
        ReadOnlySpan<int> bCols = [2, 0];
        ReadOnlySpan<int> cCols = [3, 0];

        Span<byte> ones = stackalloc byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, ones[..scalarSize]);
        WriteCanonical(BigInteger.One, ones.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, ones, 2, 4, Curve, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, ones, 2, 4, Curve, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, ones, 2, 4, Curve, Pool);
        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, Pool);
    }


    //z = (1, 3, 5, 15): satisfies c0 (3·5=15) and c1 (1·1=1).
    private static RawR1csWitness BuildOneMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    //z = (1, 3, 5, 99): violates c0 (3·5 != 99).
    private static RawR1csWitness BuildUnsatisfyingWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(99), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
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
