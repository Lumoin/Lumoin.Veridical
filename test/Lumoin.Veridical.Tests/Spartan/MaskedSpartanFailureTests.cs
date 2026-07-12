using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Verifier-robustness leg of the masked Spartan2 correctness gate:
/// every tampering with the wire bytes of a valid masked proof is
/// rejected by the verifier. Confirms the verifier's catches both
/// <see cref="ArgumentException"/> and
/// <see cref="InvalidOperationException"/> raised during decode and
/// downstream algebraic operations and translates them to a false
/// return rather than propagating.
/// </summary>
[TestClass]
internal sealed class MaskedSpartanFailureTests
{
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
    public void WitnessCommitmentTamperRejected()
    {
        VerifyTamperRejected(_ => 0, "witness commitment");
    }


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
        VerifyTamperRejected(
            p => HyraxCommitment.GetBufferSizeBytes(p.WitnessCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.OuterMaskCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.InnerMaskCommitmentRowCount, p.Curve),
            "z_outer");
    }


    [TestMethod]
    public void InnerMaskSumTamperRejected()
    {
        VerifyTamperRejected(
            p => HyraxCommitment.GetBufferSizeBytes(p.WitnessCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.OuterMaskCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.InnerMaskCommitmentRowCount, p.Curve)
                + Scalar.SizeBytes,
            "z_inner");
    }


    [TestMethod]
    public void OuterMaskFillerSumTamperRejected()
    {
        VerifyTamperRejected(
            p => HyraxCommitment.GetBufferSizeBytes(p.WitnessCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.OuterMaskCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.InnerMaskCommitmentRowCount, p.Curve)
                + (2 * Scalar.SizeBytes),
            "outer σ_F");
    }


    [TestMethod]
    public void InnerMaskFillerSumTamperRejected()
    {
        VerifyTamperRejected(
            p => HyraxCommitment.GetBufferSizeBytes(p.WitnessCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.OuterMaskCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.InnerMaskCommitmentRowCount, p.Curve)
                + (3 * Scalar.SizeBytes),
            "inner σ_F");
    }


    [TestMethod]
    public void OuterRoundPolynomialTamperRejected()
    {
        VerifyTamperRejected(
            p => HyraxCommitment.GetBufferSizeBytes(p.WitnessCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.OuterMaskCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.InnerMaskCommitmentRowCount, p.Curve)
                + (4 * Scalar.SizeBytes),
            "outer round polynomial");
    }


    [TestMethod]
    public void ClaimAzTamperRejected()
    {
        VerifyTamperRejected(
            p => HyraxCommitment.GetBufferSizeBytes(p.WitnessCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.OuterMaskCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.InnerMaskCommitmentRowCount, p.Curve)
                + (4 * Scalar.SizeBytes)
                + (p.OuterRoundCount * 3 * Scalar.SizeBytes),
            "claim_Az");
    }


    [TestMethod]
    public void ClaimBzTamperRejected()
    {
        VerifyTamperRejected(p => OuterClaimsOffset(p) + Scalar.SizeBytes, "claim_Bz");
    }


    [TestMethod]
    public void ClaimCzTamperRejected()
    {
        VerifyTamperRejected(p => OuterClaimsOffset(p) + (2 * Scalar.SizeBytes), "claim_Cz");
    }


    [TestMethod]
    public void ErrorEvaluationTamperRejected()
    {
        //E(r_x) is the fourth scalar of the outer terminating section, after
        //the three claims.
        VerifyTamperRejected(p => OuterClaimsOffset(p) + (3 * Scalar.SizeBytes), "E(r_x)");
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


    [TestMethod]
    public void EvalWTamperRejected()
    {
        //After the outer rounds: the three claims plus E(r_x) (4 scalars),
        //then the inner rounds, then eval_W.
        VerifyTamperRejected(
            p => HyraxCommitment.GetBufferSizeBytes(p.WitnessCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.OuterMaskCommitmentRowCount, p.Curve)
                + HyraxCommitment.GetBufferSizeBytes(p.InnerMaskCommitmentRowCount, p.Curve)
                + (4 * Scalar.SizeBytes)
                + (p.OuterRoundCount * 3 * Scalar.SizeBytes)
                + (4 * Scalar.SizeBytes)
                + (p.InnerRoundCount * 2 * Scalar.SizeBytes),
            "eval_W");
    }


    [TestMethod]
    public void WrongInstanceDimensionsRejectedAtVerifierBoundary()
    {
        //A proof valid against the larger instance must NOT verify under a
        //verifier set up for the trivial instance. Dimension mismatch
        //surfaces as ArgumentException at the masked verifier's argument-
        //validation boundary (caller-bug path), matching the base
        //prover's behaviour. The exception is the correct rejection
        //signal in this case — the proof bytes themselves are not
        //malformed; the caller wired the wrong verifier.
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength: 4);
        using RawR1csInstance instance = BuildTwoMultiplyInstance();
        using RawR1csWitness witness = BuildTwoMultiplyWitness();
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = prover.Prove(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

        using MaskedSpartanVerifier wrongVerifier = BuildMaskedVerifier(hyraxVectorLength: 2);
        using RawR1csInstance wrongInstance = BuildOneMultiplyInstance();
        using FiatShamirTranscript verifierTranscript = FreshTranscript();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            _ = wrongVerifier.Verify(
                proof, wrongInstance, verifierTranscript,
                Add, Multiply, Subtract, Invert, Reduce,
                G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
                BaseMemoryPool.Shared);
        });
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
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength: 4);
        using RawR1csInstance proverInstance = BuildTwoMultiplyInstance();
        using RawR1csWitness witness = BuildTwoMultiplyWitness();
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof originalProof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

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

        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength: 4);
        using RawR1csInstance verifierInstance = BuildTwoMultiplyInstance();
        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            tamperedProof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsFalse(verified, $"Verifier must reject a proof with {tamperDescription} (offset {offset}).");
    }


    //The masking section ends after the three commitments and the four mask
    //scalars (σ_outer, σ_inner, and the two filler sums); the outer sumcheck
    //rounds start here. Computed from the proof's own dimensions so a layout
    //change moves every derived offset with it.
    private static int MaskingSectionEndOffset(MaskedSpartanProof proof)
    {
        return HyraxCommitment.GetBufferSizeBytes(proof.WitnessCommitmentRowCount, proof.Curve)
            + HyraxCommitment.GetBufferSizeBytes(proof.OuterMaskCommitmentRowCount, proof.Curve)
            + HyraxCommitment.GetBufferSizeBytes(proof.InnerMaskCommitmentRowCount, proof.Curve)
            + (MaskSumScalarCount * Scalar.SizeBytes);
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
            BaseMemoryPool.Shared);
    }
}