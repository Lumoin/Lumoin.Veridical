using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Immutable;
using System.Text;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Commitment-intake validation gates for the blind BBS signer per
/// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Sections 4.1.2
/// (<c>deserialize_and_validate_commit</c>), 4.3.2 (CoreCommitVerify),
/// and 5.4.2 (<c>octets_to_commitment_with_proof</c>): an explicit
/// Identity_G1 commitment is rejected (only an ABSENT commitment yields
/// the identity default), an on-curve point outside the prime-order
/// subgroup is rejected by the subgroup delegate specifically, the
/// blind-generator arity must be <c>M + 1</c>, and the signer refuses
/// to sign over a commitment whose Schnorr proof fails. Scalar
/// canonicity and length-arithmetic intake live at
/// <see cref="BbsCommitmentWithProof.FromCanonical"/> and are gated by
/// <see cref="BbsCommitmentWithProofTests"/>.
/// </summary>
[TestClass]
internal sealed class BbsBlindCommitmentValidationTests
{
    //Pre-calculated wrong-subgroup probe shared with
    //BbsSubgroupValidationTests: the BLS12-381 G1 point with x = 0 is on
    //the curve but outside the r-order subgroup.
    private static readonly byte[] WrongSubgroupG1Compressed = Convert.FromHexString(
        "a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    private static readonly byte[] KeyMaterial = MakeBytes(64, 0x51);
    private static readonly byte[] KeyInfo = "blind-commitment-validation-key-info"u8.ToArray();
    private static readonly byte[] Header = "blind-commitment-validation-header"u8.ToArray();

    private static readonly BbsCiphersuite BlindSuite = BbsCiphersuite.Bls12Curve381Sha256Blind;


    [TestMethod]
    public void VerifyRejectsIdentityCommitmentPoint()
    {
        //Only an absent commitment yields the identity default; an explicit
        //identity encoding must be rejected before any Schnorr algebra.
        (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitTwoMessages();
        using(commitment)
        using(secretProverBlind)
        {
            using BbsCommitmentWithProof tampered = SpliceCommitmentPoint(
                commitment,
                WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381));

            Assert.IsFalse(VerifyCommitment(tampered),
                "An explicit Identity_G1 commitment point must be rejected.");
        }
    }


    [TestMethod]
    public void VerifyRejectsWrongSubgroupCommitmentPoint()
    {
        (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitTwoMessages();
        using(commitment)
        using(secretProverBlind)
        {
            using BbsCommitmentWithProof tampered = SpliceCommitmentPoint(commitment, WrongSubgroupG1Compressed);

            bool subgroupChecked = false;
            G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
            {
                subgroupChecked = true;

                return TestSetup.G1IsInPrimeOrderSubgroup(point, curve);
            };

            bool verified = tampered.Verify(
                TestSetup.Sha256.ExpandMessage,
                TestSetup.Sha256.HashToScalar,
                TestSetup.ScalarNegate,
                TestSetup.G1MultiScalarMultiply,
                TestSetup.Sha256.G1HashToCurve,
                TestSetup.G1IsOnCurve,
                recordingSubgroup,
                TestSetup.Pool);

            Assert.IsFalse(verified,
                "A commitment point outside the prime-order subgroup must be rejected even though it lies on the curve.");
            Assert.IsTrue(subgroupChecked,
                "Verification must consult the G1 subgroup delegate for the commitment point C.");
        }
    }


    [TestMethod]
    public void DeserializeAndValidateCommitRejectsBlindGeneratorArityMismatch()
    {
        //deserialize_and_validate_commit step 5: the blind generator vector
        //must destructure as (Q_2, J_1..J_M), i.e. hold exactly M + 1
        //points for the proof's M message responses.
        (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitTwoMessages();
        using(commitment)
        using(secretProverBlind)
        {
            string apiId = BlindSuite.Identifier;
            ImmutableArray<G1Point> oversizedGenerators = BbsAlgorithm.CreateGenerators(
                commitment.CommittedMessageCount + 2,
                BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                TestSetup.Sha256.ExpandMessage,
                TestSetup.Sha256.G1HashToCurve,
                TestSetup.Pool);
            try
            {
                G1Point? result = BbsBlindAlgorithm.DeserializeAndValidateCommit(
                    commitment,
                    oversizedGenerators.AsSpan(),
                    apiId,
                    TestSetup.Sha256.HashToScalar,
                    TestSetup.ScalarNegate,
                    TestSetup.G1MultiScalarMultiply,
                    TestSetup.G1IsOnCurve,
                    TestSetup.G1IsInPrimeOrderSubgroup,
                    TestSetup.Pool);

                Assert.IsNull(result,
                    "A blind generator vector whose length is not M + 1 must be rejected.");
            }
            finally
            {
                foreach(G1Point generator in oversizedGenerators)
                {
                    generator.Dispose();
                }
            }
        }
    }


    [TestMethod]
    public void BlindSignRefusesTamperedCommitmentProof()
    {
        using BbsKeyPair pair = MakeKeyPair();
        (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitTwoMessages();
        using(commitment)
        using(secretProverBlind)
        {
            //Tamper the Schnorr challenge: the commitment stays structurally
            //canonical, so refusal must come from the proof verification gate.
            byte[] tamperedBytes = commitment.AsReadOnlySpan().ToArray();
            tamperedBytes[^1] ^= 0x01;
            using BbsCommitmentWithProof tampered = BbsCommitmentWithProof.FromCanonical(tamperedBytes, BlindSuite, TestSetup.Pool);

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => _ = BlindSign(pair, tampered));

            Assert.AreEqual("commitmentWithProof", ex.ParamName);
        }
    }


    [TestMethod]
    public void BlindSignRefusesIdentityCommitmentPoint()
    {
        using BbsKeyPair pair = MakeKeyPair();
        (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitTwoMessages();
        using(commitment)
        using(secretProverBlind)
        {
            using BbsCommitmentWithProof tampered = SpliceCommitmentPoint(
                commitment,
                WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381));

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => _ = BlindSign(pair, tampered));

            Assert.AreEqual("commitmentWithProof", ex.ParamName);
        }
    }


    [TestMethod]
    public void BlindSignRefusesCommitmentFromTheOtherHashSuite()
    {
        //The commitment carries the interface-scoped ciphersuite; a SHA-256
        //key must refuse a commitment produced under the SHAKE-256 blind
        //interface. The guard routes through the base-suite mapping, so the
        //mismatch is detected even though neither value equals the key's
        //core ciphersuite.
        using BbsKeyPair pair = MakeKeyPair();
        (BbsCommitmentWithProof shakeCommitment, Scalar secretProverBlind) = BbsCommitmentWithProof.Commit(
            MakeMessages(2),
            BbsCiphersuite.Bls12Curve381Shake256Blind,
            TestSetup.Shake256.ExpandMessage,
            TestSetup.Shake256.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarMultiply,
            TestSetup.ScalarRandom,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Shake256.G1HashToCurve,
            TestSetup.Pool);
        using(shakeCommitment)
        using(secretProverBlind)
        {
            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => _ = BlindSign(pair, shakeCommitment));

            Assert.AreEqual("commitmentWithProof", ex.ParamName);
        }
    }


    private static BbsKeyPair MakeKeyPair() =>
        BbsCiphersuite.Bls12Curve381Sha256.Generate(
            KeyMaterial,
            KeyInfo,
            TestSetup.Sha256.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);


    private static (BbsCommitmentWithProof CommitmentWithProof, Scalar SecretProverBlind) CommitTwoMessages() =>
        BbsCommitmentWithProof.Commit(
            MakeMessages(2),
            BlindSuite,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarMultiply,
            TestSetup.ScalarRandom,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.Pool);


    private static BbsBlindSignature BlindSign(BbsKeyPair pair, BbsCommitmentWithProof commitmentWithProof) =>
        pair.SecretKey.BlindSign(
            pair.PublicKey,
            commitmentWithProof,
            new BbsHeader(Header),
            MakeMessages(1),
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarNegate,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.Pool);


    private static bool VerifyCommitment(BbsCommitmentWithProof commitmentWithProof) =>
        commitmentWithProof.Verify(
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.ScalarNegate,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.Pool);


    private static BbsCommitmentWithProof SpliceCommitmentPoint(BbsCommitmentWithProof source, ReadOnlySpan<byte> pointBytes)
    {
        byte[] splicedBytes = source.AsReadOnlySpan().ToArray();
        pointBytes.CopyTo(splicedBytes.AsSpan(BbsCommitmentWithProof.COffset, BbsCommitmentWithProof.CSizeBytes));

        return BbsCommitmentWithProof.FromCanonical(splicedBytes, BlindSuite, TestSetup.Pool);
    }


    private static BbsMessage[] MakeMessages(int count)
    {
        BbsMessage[] messages = new BbsMessage[count];
        for(int i = 0; i < count; i++)
        {
            messages[i] = new BbsMessage(Encoding.UTF8.GetBytes($"validation-message-{i}"));
        }

        return messages;
    }


    private static byte[] MakeBytes(int length, byte start)
    {
        byte[] result = new byte[length];
        for(int i = 0; i < length; i++)
        {
            result[i] = (byte)(start + i);
        }

        return result;
    }
}
