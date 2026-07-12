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
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// BN254 parity for the masked Spartan2 verifier-robustness leg: every
/// tampering with the wire bytes of a valid masked proof — the mask
/// commitments, the mask sums <c>σ</c>, the filler sums <c>σ_F</c>, a blended
/// round polynomial, and the coefficient-granular top-degree zeroing — is
/// rejected by the verifier. Mirrors the BLS12-381
/// <see cref="MaskedSpartanFailureTests"/> over the second wired curve, so the
/// curve-broadened masked path keeps the same rejection contract.
/// </summary>
[TestClass]
internal sealed class Bn254MaskedSpartanFailureTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bn254.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bn254.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bn254.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bn254.Invert;
    private static ScalarRandomDelegate ScalarRandom { get; } = Bn254BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bn254Msm;
    private static G1HashToCurveDelegate HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    private static readonly BigInteger Order = Bn254BigIntegerScalarReference.FieldOrder;
    private static CurveParameterSet Curve => CurveParameterSet.Bn254;
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const int HyraxVectorLength = 4;

    //The masking section carries four scalars after the three commitments:
    //σ_outer, σ_inner, and the two filler sums.
    private const int MaskSumScalarCount = 4;

    //The compressed round storage orders (c_0, c_2, …, c_d) with c_1 elided:
    //the outer degree-3 rounds store three scalars with the cubic term in the
    //last slot, the inner degree-2 rounds store two with the quadratic term in
    //the last slot.
    private const int OuterRoundStoredScalarCount = 3;
    private const int InnerRoundStoredScalarCount = 2;
    private const int OuterTopCoefficientSlot = OuterRoundStoredScalarCount - 1;
    private const int InnerTopCoefficientSlot = InnerRoundStoredScalarCount - 1;

    //The outer terminating section: the three claims (Az, Bz, Cz) and E(r_x).
    private const int OuterClaimScalarCount = 4;


    [TestMethod]
    public void OuterMaskCommitmentTamperRejected()
    {
        VerifyTamperRejected(
            p => HyraxCommitment.GetBufferSizeBytes(p.WitnessCommitmentRowCount, p.Curve),
            "outer masking commitment");
    }


    [TestMethod]
    public void InnerMaskCommitmentTamperRejected()
    {
        VerifyTamperRejected(
            p => HyraxCommitment.GetBufferSizeBytes(p.WitnessCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.OuterMaskCommitmentRowCount, p.Curve),
            "inner masking commitment");
    }


    [TestMethod]
    public void OuterMaskSumTamperRejected()
    {
        VerifyTamperRejected(p => CommitmentsEndOffset(p), "z_outer");
    }


    [TestMethod]
    public void InnerMaskSumTamperRejected()
    {
        VerifyTamperRejected(p => CommitmentsEndOffset(p) + Scalar.SizeBytes, "z_inner");
    }


    [TestMethod]
    public void OuterMaskFillerSumTamperRejected()
    {
        VerifyTamperRejected(p => CommitmentsEndOffset(p) + (2 * Scalar.SizeBytes), "outer σ_F");
    }


    [TestMethod]
    public void InnerMaskFillerSumTamperRejected()
    {
        VerifyTamperRejected(p => CommitmentsEndOffset(p) + (3 * Scalar.SizeBytes), "inner σ_F");
    }


    [TestMethod]
    public void OuterRoundPolynomialTamperRejected()
    {
        VerifyTamperRejected(p => MaskingSectionEndOffset(p), "outer round polynomial");
    }


    [TestMethod]
    public void OuterRoundTopCoefficientZeroedRejected()
    {
        //Zeroing exactly the degree-3 (top) coefficient of the first blended
        //outer round polynomial is the coefficient-granular malicious-prover
        //tamper: the constant term and the transcript framing stay intact, so
        //only the round identity and the challenge chain can catch it.
        VerifyZeroedScalarRejected(
            p => MaskingSectionEndOffset(p) + (OuterTopCoefficientSlot * Scalar.SizeBytes),
            "outer round polynomial top (degree-3) coefficient");
    }


    [TestMethod]
    public void InnerRoundTopCoefficientZeroedRejected()
    {
        //The inner degree-2 counterpart: zero the quadratic coefficient of the
        //first blended inner round polynomial.
        VerifyZeroedScalarRejected(
            p => InnerRoundsOffset(p) + (InnerTopCoefficientSlot * Scalar.SizeBytes),
            "inner round polynomial top (degree-2) coefficient");
    }


    private delegate int MaskedProofOffsetSelector(MaskedSpartanProof proof);

    private delegate void ProofRegionMutator(Span<byte> region);


    private static void VerifyTamperRejected(MaskedProofOffsetSelector offsetSelector, string region)
    {
        VerifyMutationRejected(offsetSelector, regionLength: 1, static bytes => bytes[0] ^= 0xFF, $"a flipped byte in the {region} region");
    }


    private static void VerifyZeroedScalarRejected(MaskedProofOffsetSelector offsetSelector, string region)
    {
        VerifyMutationRejected(offsetSelector, Scalar.SizeBytes, static bytes => bytes.Clear(), $"a zeroed {region}");
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Test method composes ownership transfers through using declarations.")]
    private static void VerifyMutationRejected(MaskedProofOffsetSelector offsetSelector, int regionLength, ProofRegionMutator mutate, string tamperDescription)
    {
        using MaskedSpartanProver prover = BuildMaskedProver();
        using RawR1csInstance proverInstance = BuildTwoMultiplyInstance();
        using RawR1csWitness witness = BuildTwoMultiplyWitness();
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof originalProof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        byte[] tamperedBytes = originalProof.AsReadOnlySpan().ToArray();
        int offset = offsetSelector(originalProof);
        Span<byte> targetRegion = tamperedBytes.AsSpan(offset, regionLength);
        byte[] regionBeforeMutation = targetRegion.ToArray();
        mutate(targetRegion);

        //A mutation that leaves the bytes unchanged (e.g. zeroing an
        //already-zero coefficient) would make the rejection assertion vacuous.
        Assert.IsFalse(
            targetRegion.SequenceEqual(regionBeforeMutation),
            $"The tamper ({tamperDescription}, offset {offset}) must change the proof bytes.");

        using MaskedSpartanProof tamperedProof = Rehydrate(tamperedBytes, originalProof);

        using MaskedSpartanVerifier verifier = BuildMaskedVerifier();
        using RawR1csInstance verifierInstance = BuildTwoMultiplyInstance();
        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            tamperedProof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);

        Assert.IsFalse(verified, $"The BN254 masked verifier must reject a proof with {tamperDescription} (offset {offset}).");
    }


    //The end of the three commitment sections, where the four mask scalars
    //start. Computed from the proof's own dimensions so a layout change moves
    //every derived offset with it.
    private static int CommitmentsEndOffset(MaskedSpartanProof proof)
    {
        return HyraxCommitment.GetBufferSizeBytes(proof.WitnessCommitmentRowCount, proof.Curve)
            + HyraxCommitment.GetBufferSizeBytes(proof.OuterMaskCommitmentRowCount, proof.Curve)
            + HyraxCommitment.GetBufferSizeBytes(proof.InnerMaskCommitmentRowCount, proof.Curve);
    }


    //The masking section ends after the commitments and the four mask scalars
    //(σ_outer, σ_inner, and the two filler sums); the outer rounds start here.
    private static int MaskingSectionEndOffset(MaskedSpartanProof proof)
    {
        return CommitmentsEndOffset(proof) + (MaskSumScalarCount * Scalar.SizeBytes);
    }


    //The outer terminating claims (claim_Az, claim_Bz, claim_Cz, E(r_x)) start
    //after the outer round polynomials.
    private static int OuterClaimsOffset(MaskedSpartanProof proof)
    {
        return MaskingSectionEndOffset(proof)
            + (proof.OuterRoundCount * OuterRoundStoredScalarCount * Scalar.SizeBytes);
    }


    //The inner round polynomials start after the outer claims section.
    private static int InnerRoundsOffset(MaskedSpartanProof proof)
    {
        return OuterClaimsOffset(proof) + (OuterClaimScalarCount * Scalar.SizeBytes);
    }


    private static MaskedSpartanProof Rehydrate(byte[] proofBytes, MaskedSpartanProof template)
    {
        return MaskedSpartanProof.FromBytes(
            proofBytes,
            template.WitnessCommitmentRowCount,
            template.OuterMaskCommitmentRowCount,
            template.InnerMaskCommitmentRowCount,
            template.OuterRoundCount,
            template.InnerRoundCount,
            template.WitnessIpaRoundCount,
            template.OuterMaskIpaRoundCount,
            template.InnerMaskIpaRoundCount,
            template.ErrorIpaRoundCount,
            template.Curve,
            Pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanProver.")]
    private static MaskedSpartanProver BuildMaskedProver() =>
        new(new SpartanProvingKey(BuildProvider(BuildCommitmentKey())));


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanVerifier.")]
    private static MaskedSpartanVerifier BuildMaskedVerifier() =>
        new(new SpartanVerifyingKey(BuildProvider(BuildCommitmentKey())));


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to whatever owns the provider.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the provider that consumes it.")]
    private static HyraxCommitmentKey BuildCommitmentKey()
    {
        //The statistical masks' single-row vector commitments need more
        //generators than the small witness matrices; a longer key derives the
        //same per-index generators, so flooring is byte-neutral for the rest.
        return HyraxCommitmentKey.Derive(
            Math.Max(HyraxVectorLength, MaskedSpartanTestFixtures.MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, Pool);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);
    }


    //Two multiplications: c0 z[1]·z[2]=z[3], c1 z[4]·z[5]=z[6]. (m=2, n=8).
    private static RawR1csInstance BuildTwoMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = [0, 1];
        ReadOnlySpan<int> aCols = [1, 4];
        ReadOnlySpan<int> bCols = [2, 5];
        ReadOnlySpan<int> cCols = [3, 6];

        Span<byte> ones = stackalloc byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, ones[..scalarSize]);
        WriteCanonical(BigInteger.One, ones.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, ones, 2, 8, Curve, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, ones, 2, 8, Curve, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, ones, 2, 8, Curve, Pool);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, Pool);
    }


    //z = (1, 3, 5, 15, 2, 7, 14, 0): c0 3·5=15, c1 2·7=14.
    private static RawR1csWitness BuildTwoMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[7 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witness.Slice(2 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(2), witness.Slice(3 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(7), witness.Slice(4 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(14), witness.Slice(5 * scalarSize, scalarSize));
        WriteCanonical(BigInteger.Zero, witness.Slice(6 * scalarSize, scalarSize));

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
