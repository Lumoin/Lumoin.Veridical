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


    [SuppressMessage("Reliability", "CA2000", Justification = "Test method composes ownership transfers through using declarations.")]
    private static void VerifyTamperRejected(MaskedProofOffsetSelector offsetSelector, string region)
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
        tamperedBytes[offset] ^= 0xFF;

        using MaskedSpartanProof tamperedProof = Rehydrate(tamperedBytes, originalProof);

        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength: 4);
        using RawR1csInstance verifierInstance = BuildTwoMultiplyInstance();
        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            tamperedProof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsFalse(verified, $"Verifier must reject a proof with a flipped byte in the {region} region (offset {offset}).");
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