using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Linq;
using System.Text;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Self-consistency gates for the blind BBS issuance pipeline per
/// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c>: Commit → BlindSign →
/// VerifyBlindSign roundtrips across the (signer message count,
/// committed message count) matrix including both empty extremes,
/// rejection when the prover supplies the wrong blinding factor or a
/// wrong committed message, and interface separation from core BBS+.
/// </summary>
[TestClass]
internal sealed class BbsBlindSignVerifyTests
{
    private static readonly byte[] KeyMaterial = MakeBytes(64, 0x42);
    private static readonly byte[] KeyInfo = "blind-sign-verify-key-info"u8.ToArray();
    private static readonly byte[] Header = "blind-sign-verify-header"u8.ToArray();


    private sealed record SuiteWiring(
        BbsCiphersuite Ciphersuite,
        BbsCiphersuite BlindCiphersuite,
        ExpandMessageDelegate ExpandMessage,
        ScalarHashToScalarDelegate HashToScalar,
        G1HashToCurveDelegate G1HashToCurve);


    //Hash-delegate selection routes through the base hash suite shared by
    //the core and blind interface values.
    private static SuiteWiring CreateWiring(BbsCiphersuite blindCiphersuite)
    {
        BbsCiphersuite baseSuite = blindCiphersuite.BaseHashSuite;
        bool isSha256 = baseSuite == BbsCiphersuite.Bls12Curve381Sha256;

        return new SuiteWiring(
            baseSuite,
            blindCiphersuite,
            isSha256 ? TestSetup.Sha256.ExpandMessage : TestSetup.Shake256.ExpandMessage,
            isSha256 ? TestSetup.Sha256.HashToScalar : TestSetup.Shake256.HashToScalar,
            isSha256 ? TestSetup.Sha256.G1HashToCurve : TestSetup.Shake256.G1HashToCurve);
    }


    private static readonly SuiteWiring Sha256Wiring = CreateWiring(BbsCiphersuite.Bls12Curve381Sha256Blind);
    private static readonly SuiteWiring Shake256Wiring = CreateWiring(BbsCiphersuite.Bls12Curve381Shake256Blind);


    [TestMethod]
    public void RoundtripWithNoSignerMessagesAndOneCommittedMessageSucceeds()
    {
        RunRoundtrip(Sha256Wiring, signerMessageCount: 0, committedMessageCount: 1);
        RunRoundtrip(Shake256Wiring, signerMessageCount: 0, committedMessageCount: 1);
    }


    [TestMethod]
    public void RoundtripWithOneSignerMessageAndBlindOnlyCommitmentSucceeds()
    {
        //M = 0 with a commitment present: the prover commits only to its
        //blinding factor — the commitment is the 112-byte minimum shape.
        RunRoundtrip(Sha256Wiring, signerMessageCount: 1, committedMessageCount: 0);
        RunRoundtrip(Shake256Wiring, signerMessageCount: 1, committedMessageCount: 0);
    }


    [TestMethod]
    public void RoundtripWithSignerAndCommittedMessagesSucceeds()
    {
        RunRoundtrip(Sha256Wiring, signerMessageCount: 2, committedMessageCount: 3);
        RunRoundtrip(Shake256Wiring, signerMessageCount: 2, committedMessageCount: 3);
    }


    [TestMethod]
    public void RoundtripWithoutCommitmentOverPlainMessagesSucceeds()
    {
        //The spec's empty-commitment default: BlindSign degenerates to a
        //signature over the signer's own messages, still under the blind
        //interface (Q_2 participates in the domain with a zero scalar at
        //verification).
        RunRoundtrip(Sha256Wiring, signerMessageCount: 2, committedMessageCount: 0, useCommitment: false);
        RunRoundtrip(Shake256Wiring, signerMessageCount: 2, committedMessageCount: 0, useCommitment: false);
    }


    [TestMethod]
    public void VerifyBlindSignRejectsWrongSecretProverBlind()
    {
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] signerMessages = MakeMessages("issuer", 2);
        BbsMessage[] committedMessages = MakeMessages("committed", 3);

        (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = Commit(wiring, committedMessages);
        using(commitment)
        using(secretProverBlind)
        {
            using BbsBlindSignature signature = BlindSign(wiring, pair, commitment, signerMessages);
            using Scalar wrongBlind = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);

            Assert.IsTrue(VerifyBlindSign(wiring, pair.PublicKey, signature, signerMessages, committedMessages, secretProverBlind),
                "The genuine blinding factor must verify (guards the negative assertion below).");
            Assert.IsFalse(VerifyBlindSign(wiring, pair.PublicKey, signature, signerMessages, committedMessages, wrongBlind),
                "VerifyBlindSign must reject a blinding factor other than the one committed.");
        }
    }


    [TestMethod]
    public void VerifyBlindSignRejectsWrongCommittedMessage()
    {
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] signerMessages = MakeMessages("issuer", 2);
        BbsMessage[] committedMessages = MakeMessages("committed", 3);

        (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = Commit(wiring, committedMessages);
        using(commitment)
        using(secretProverBlind)
        {
            using BbsBlindSignature signature = BlindSign(wiring, pair, commitment, signerMessages);

            BbsMessage[] alteredCommittedMessages = (BbsMessage[])committedMessages.Clone();
            alteredCommittedMessages[1] = new BbsMessage("committed-altered"u8.ToArray());

            Assert.IsFalse(VerifyBlindSign(wiring, pair.PublicKey, signature, signerMessages, alteredCommittedMessages, secretProverBlind),
                "VerifyBlindSign must reject when a committed message differs from the one committed.");
        }
    }


    [TestMethod]
    public void CoreSignatureDoesNotVerifyUnderTheBlindInterface()
    {
        //Interface separation: the blind api_id changes every generator,
        //the domain, and the e derivation, so a core-interface signature
        //reinterpreted as a blind signature over the same bytes must fail.
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] messages = MakeMessages("separation", 2);

        using BbsSignature coreSignature = pair.SecretKey.Sign(
            pair.PublicKey,
            new BbsHeader(Header),
            messages,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.Pool);

        using BbsBlindSignature reinterpreted = BbsBlindSignature.FromCanonical(
            coreSignature.AsReadOnlySpan(),
            wiring.BlindCiphersuite,
            TestSetup.Pool);

        Assert.IsFalse(VerifyBlindSign(wiring, pair.PublicKey, reinterpreted, messages, [], secretProverBlind: null),
            "A core-interface signature must not verify under the blind interface.");
    }


    [TestMethod]
    public void BlindSignatureDoesNotVerifyUnderTheCoreInterface()
    {
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] messages = MakeMessages("separation", 2);

        using BbsBlindSignature blindSignature = BlindSign(wiring, pair, commitmentWithProof: null, messages);

        using BbsSignature reinterpreted = BbsSignature.FromCanonical(
            blindSignature.AsReadOnlySpan(),
            wiring.Ciphersuite,
            TestSetup.Pool);

        bool verified = pair.PublicKey.Verify(
            reinterpreted,
            new BbsHeader(Header),
            messages,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.G1Add,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.G2IsOnCurve,
            TestSetup.G2IsInPrimeOrderSubgroup,
            TestSetup.Pairing,
            TestSetup.Pool);

        Assert.IsFalse(verified, "A blind-interface signature must not verify under the core interface.");
    }


    private static void RunRoundtrip(SuiteWiring wiring, int signerMessageCount, int committedMessageCount, bool useCommitment = true)
    {
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] signerMessages = MakeMessages("issuer", signerMessageCount);
        BbsMessage[] committedMessages = MakeMessages("committed", committedMessageCount);

        BbsCommitmentWithProof? commitment = null;
        Scalar? secretProverBlind = null;
        try
        {
            if(useCommitment)
            {
                (commitment, secretProverBlind) = Commit(wiring, committedMessages);
            }

            using BbsBlindSignature signature = BlindSign(wiring, pair, commitment, signerMessages);

            Assert.IsTrue(VerifyBlindSign(wiring, pair.PublicKey, signature, signerMessages, committedMessages, secretProverBlind),
                $"Commit → BlindSign → VerifyBlindSign must roundtrip for L={signerMessageCount}, M={committedMessageCount}, commitment={useCommitment} under '{wiring.BlindCiphersuite.Identifier}'.");
        }
        finally
        {
            commitment?.Dispose();
            secretProverBlind?.Dispose();
        }
    }


    private static BbsKeyPair MakeKeyPair(SuiteWiring wiring) =>
        wiring.Ciphersuite.Generate(
            KeyMaterial,
            KeyInfo,
            wiring.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);


    private static (BbsCommitmentWithProof CommitmentWithProof, Scalar SecretProverBlind) Commit(
        SuiteWiring wiring,
        BbsMessage[] committedMessages) =>
        BbsCommitmentWithProof.Commit(
            committedMessages,
            wiring.BlindCiphersuite,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarMultiply,
            TestSetup.ScalarRandom,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.Pool);


    private static BbsBlindSignature BlindSign(
        SuiteWiring wiring,
        BbsKeyPair pair,
        BbsCommitmentWithProof? commitmentWithProof,
        BbsMessage[] signerMessages) =>
        pair.SecretKey.BlindSign(
            pair.PublicKey,
            commitmentWithProof,
            new BbsHeader(Header),
            signerMessages,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarNegate,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.Pool);


    private static bool VerifyBlindSign(
        SuiteWiring wiring,
        BbsPublicKey publicKey,
        BbsBlindSignature signature,
        BbsMessage[] signerMessages,
        BbsMessage[] committedMessages,
        Scalar? secretProverBlind)
    {
        BbsMessage[] fullMessages = signerMessages.Concat(committedMessages).ToArray();

        return signature.VerifyBlindSign(
            publicKey,
            new BbsHeader(Header),
            fullMessages,
            signerMessages.Length,
            secretProverBlind,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.G1Add,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.G2IsOnCurve,
            TestSetup.G2IsInPrimeOrderSubgroup,
            TestSetup.Pairing,
            TestSetup.Pool);
    }


    private static BbsMessage[] MakeMessages(string prefix, int count)
    {
        BbsMessage[] messages = new BbsMessage[count];
        for(int i = 0; i < count; i++)
        {
            messages[i] = new BbsMessage(Encoding.UTF8.GetBytes($"{prefix}-message-{i}"));
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
