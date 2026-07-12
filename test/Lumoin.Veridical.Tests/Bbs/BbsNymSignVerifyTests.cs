using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Self-consistency and rejection gates for the per-verifier-pseudonym
/// issuance pipeline per
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c>: CommitWithNym
/// → BlindSignWithNym → VerifyFinalizeWithNym roundtrips including a
/// multi-entry nym vector (the published vectors exercise only N = 1),
/// the entropy fold landing on exactly the last nym slot, the
/// Sybil-resistance length binding (a signer that certified a different
/// nym-vector length fails finalization), and interface separation from
/// the core and blind BBS+ Interfaces.
/// </summary>
[TestClass]
internal sealed class BbsNymSignVerifyTests
{
    private static readonly byte[] KeyMaterial = MakeBytes(64, 0x51);
    private static readonly byte[] KeyInfo = "nym-sign-verify-key-info"u8.ToArray();
    private static readonly byte[] Header = "nym-sign-verify-header"u8.ToArray();


    private sealed record SuiteWiring(
        BbsCiphersuite PseudonymCiphersuite,
        ExpandMessageDelegate ExpandMessage,
        ScalarHashToScalarDelegate HashToScalar,
        G1HashToCurveDelegate G1HashToCurve);


    //Hash-delegate selection routes through the base hash suite shared by
    //the core and pseudonym interface values.
    private static SuiteWiring CreateWiring(BbsCiphersuite pseudonymCiphersuite)
    {
        bool isSha256 = pseudonymCiphersuite.BaseHashSuite == BbsCiphersuite.Bls12Curve381Sha256;

        return new SuiteWiring(
            pseudonymCiphersuite,
            isSha256 ? TestSetup.Sha256.ExpandMessage : TestSetup.Shake256.ExpandMessage,
            isSha256 ? TestSetup.Sha256.HashToScalar : TestSetup.Shake256.HashToScalar,
            isSha256 ? TestSetup.Sha256.G1HashToCurve : TestSetup.Shake256.G1HashToCurve);
    }


    private static readonly SuiteWiring Sha256Wiring = CreateWiring(BbsCiphersuite.Bls12Curve381Sha256Pseudonym);
    private static readonly SuiteWiring Shake256Wiring = CreateWiring(BbsCiphersuite.Bls12Curve381Shake256Pseudonym);


    [TestMethod]
    public void RoundtripWithSingleNymAndMessagesSucceeds()
    {
        RunRoundtrip(Sha256Wiring, signerMessageCount: 2, committedMessageCount: 2, nymCount: 1);
        RunRoundtrip(Shake256Wiring, signerMessageCount: 2, committedMessageCount: 2, nymCount: 1);
    }


    [TestMethod]
    public void RoundtripWithTwoNymsAndNoCommittedMessagesSucceeds()
    {
        //N = 2 exercises the polynomial-commitment construction beyond the
        //published vectors, which all carry a single nym secret.
        RunRoundtrip(Sha256Wiring, signerMessageCount: 1, committedMessageCount: 0, nymCount: 2);
        RunRoundtrip(Shake256Wiring, signerMessageCount: 1, committedMessageCount: 0, nymCount: 2);
    }


    [TestMethod]
    public void VerifyFinalizeRejectsWrongCertifiedNymVectorLength()
    {
        //The Sybil-resistance binding: the signer certifies N inside
        //combined_header = header || I2OSP(N, 8). A signature issued for
        //N = 1 over a commitment actually carrying two nym scalars must
        //fail finalization against the true two-entry vector, because the
        //prover re-derives N = 2 from its prover_nyms and the domains
        //diverge.
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] signerMessages = MakeMessages("issuer", 2);
        Scalar[] proverNyms = MakeRandomScalars(2);
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        try
        {
            (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitWithNym(wiring, [], proverNyms);
            using(commitment)
            using(secretProverBlind)
            {
                using BbsBlindSignature correctSignature = BlindSignWithNym(wiring, pair, commitment, lengthNymVector: 2, signerNymEntropy, signerMessages);
                Scalar[]? finalized = VerifyFinalizeWithNym(wiring, pair.PublicKey, correctSignature, signerMessages, [], proverNyms, signerNymEntropy, secretProverBlind);
                Assert.IsNotNull(finalized, "The correctly certified length must finalize (guards the negative assertion below).");
                DisposeAll(finalized);

                using BbsBlindSignature underDeclaredSignature = BlindSignWithNym(wiring, pair, commitment, lengthNymVector: 1, signerNymEntropy, signerMessages);
                Scalar[]? rejected = VerifyFinalizeWithNym(wiring, pair.PublicKey, underDeclaredSignature, signerMessages, [], proverNyms, signerNymEntropy, secretProverBlind);
                Assert.IsNull(rejected, "A signature certifying a different nym-vector length than the prover holds must fail finalization.");
            }
        }
        finally
        {
            DisposeAll(proverNyms);
        }
    }


    [TestMethod]
    public void VerifyFinalizeRejectsWrongSignerNymEntropy()
    {
        //The last nym secret is prover_nyms[-1] + signer_nym_entropy: a
        //different entropy scalar shifts the finalized secret off the value
        //the signature actually covers.
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] signerMessages = MakeMessages("issuer", 1);
        Scalar[] proverNyms = MakeRandomScalars(1);
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        using Scalar wrongEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        try
        {
            (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitWithNym(wiring, [], proverNyms);
            using(commitment)
            using(secretProverBlind)
            {
                using BbsBlindSignature signature = BlindSignWithNym(wiring, pair, commitment, lengthNymVector: 1, signerNymEntropy, signerMessages);

                Scalar[]? rejected = VerifyFinalizeWithNym(wiring, pair.PublicKey, signature, signerMessages, [], proverNyms, wrongEntropy, secretProverBlind);
                Assert.IsNull(rejected, "VerifyFinalizeWithNym must reject an entropy scalar other than the one the signer folded into B.");
            }
        }
        finally
        {
            DisposeAll(proverNyms);
        }
    }


    [TestMethod]
    public void CoreSignatureDoesNotFinalizeUnderTheNymInterface()
    {
        //Interface separation: the pseudonym api_id changes every generator,
        //the domain (which additionally binds N), and the e derivation, so a
        //core-interface signature reinterpreted as a pseudonym-interface
        //blind signature over the same bytes must fail.
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] messages = MakeMessages("separation", 2);
        Scalar[] proverNyms = MakeRandomScalars(1);
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        try
        {
            (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitWithNym(wiring, [], proverNyms);
            using(commitment)
            using(secretProverBlind)
            {
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
                    wiring.PseudonymCiphersuite,
                    TestSetup.Pool);

                Scalar[]? rejected = VerifyFinalizeWithNym(wiring, pair.PublicKey, reinterpreted, messages, [], proverNyms, signerNymEntropy, secretProverBlind);
                Assert.IsNull(rejected, "A core-interface signature must not finalize under the pseudonym interface.");
            }
        }
        finally
        {
            DisposeAll(proverNyms);
        }
    }


    [TestMethod]
    public void NymSignatureDoesNotVerifyUnderTheCoreInterface()
    {
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] messages = MakeMessages("separation", 2);
        Scalar[] proverNyms = MakeRandomScalars(1);
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        try
        {
            (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitWithNym(wiring, [], proverNyms);
            using(commitment)
            using(secretProverBlind)
            {
                using BbsBlindSignature nymSignature = BlindSignWithNym(wiring, pair, commitment, lengthNymVector: 1, signerNymEntropy, messages);
                using BbsSignature reinterpreted = BbsSignature.FromCanonical(
                    nymSignature.AsReadOnlySpan(),
                    wiring.PseudonymCiphersuite.BaseHashSuite,
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

                Assert.IsFalse(verified, "A pseudonym-interface signature must not verify under the core interface.");
            }
        }
        finally
        {
            DisposeAll(proverNyms);
        }
    }


    [TestMethod]
    public void NymSignatureDoesNotVerifyUnderTheBlindInterface()
    {
        //The blind and pseudonym interfaces share the wire shape and the
        //blind machinery, but every DST differs and the pseudonym domain
        //binds N; a cross-reading must fail even with the correct blinding
        //factor supplied.
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] messages = MakeMessages("separation", 2);
        Scalar[] proverNyms = MakeRandomScalars(1);
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        try
        {
            (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitWithNym(wiring, [], proverNyms);
            using(commitment)
            using(secretProverBlind)
            {
                using BbsBlindSignature nymSignature = BlindSignWithNym(wiring, pair, commitment, lengthNymVector: 1, signerNymEntropy, messages);
                BbsCiphersuite blindCiphersuite = wiring.PseudonymCiphersuite.BaseHashSuite == BbsCiphersuite.Bls12Curve381Sha256
                    ? BbsCiphersuite.Bls12Curve381Sha256Blind
                    : BbsCiphersuite.Bls12Curve381Shake256Blind;
                using BbsBlindSignature reinterpreted = BbsBlindSignature.FromCanonical(
                    nymSignature.AsReadOnlySpan(),
                    blindCiphersuite,
                    TestSetup.Pool);

                bool verified = reinterpreted.VerifyBlindSign(
                    pair.PublicKey,
                    new BbsHeader(Header),
                    messages,
                    messages.Length,
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

                Assert.IsFalse(verified, "A pseudonym-interface signature must not verify under the blind interface.");
            }
        }
        finally
        {
            DisposeAll(proverNyms);
        }
    }


    [TestMethod]
    public void NymTaggedSignatureIsRefusedByVerifyBlindSignBeforeAnyCryptography()
    {
        //A genuine BlindSignWithNym output still carrying its pseudonym
        //Interface tag must be refused by VerifyBlindSign's interface gate —
        //before any generator derivation or pairing — because the blind and
        //pseudonym suites share the wire shape but no DST.
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] messages = MakeMessages("separation", 2);
        Scalar[] proverNyms = MakeRandomScalars(1);
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        try
        {
            (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitWithNym(wiring, [], proverNyms);
            using(commitment)
            using(secretProverBlind)
            {
                using BbsBlindSignature nymSignature = BlindSignWithNym(wiring, pair, commitment, lengthNymVector: 1, signerNymEntropy, messages);

                bool pairingInvoked = false;
                PairingDelegate recordingPairing = (p, q, result, curve) =>
                {
                    pairingInvoked = true;
                    TestSetup.Pairing(p, q, result, curve);
                };

                bool verified = nymSignature.VerifyBlindSign(
                    pair.PublicKey,
                    new BbsHeader(Header),
                    messages,
                    messages.Length,
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
                    recordingPairing,
                    TestSetup.Pool);

                Assert.IsFalse(verified, "A pseudonym-tagged signature must be refused by VerifyBlindSign.");
                Assert.IsFalse(pairingInvoked, "The refusal must come from the interface gate, before any pairing runs.");
            }
        }
        finally
        {
            DisposeAll(proverNyms);
        }
    }


    [TestMethod]
    public void BlindSignatureDoesNotFinalizeUnderTheNymInterface()
    {
        //The reverse crossing of NymSignatureDoesNotVerifyUnderTheBlindInterface:
        //a genuine blind-interface signature re-tagged as the pseudonym suite
        //passes the tag gate, so the rejection must come from the diverging
        //DSTs, the N-binding domain, and the e derivation.
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] messages = MakeMessages("separation", 2);
        BbsMessage[] committedMessages = MakeMessages("committed", 1);
        Scalar[] proverNyms = MakeRandomScalars(1);
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        try
        {
            (BbsCommitmentWithProof blindCommitment, Scalar secretProverBlind) = BbsCommitmentWithProof.Commit(
                committedMessages,
                BbsCiphersuite.Bls12Curve381Sha256Blind,
                wiring.ExpandMessage,
                wiring.HashToScalar,
                TestSetup.ScalarAdd,
                TestSetup.ScalarMultiply,
                TestSetup.ScalarRandom,
                TestSetup.G1MultiScalarMultiply,
                wiring.G1HashToCurve,
                TestSetup.Pool);
            using(blindCommitment)
            using(secretProverBlind)
            {
                using BbsBlindSignature blindSignature = pair.SecretKey.BlindSign(
                    pair.PublicKey,
                    blindCommitment,
                    new BbsHeader(Header),
                    messages,
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
                using BbsBlindSignature reinterpreted = BbsBlindSignature.FromCanonical(
                    blindSignature.AsReadOnlySpan(),
                    wiring.PseudonymCiphersuite,
                    TestSetup.Pool);

                Scalar[]? rejected = VerifyFinalizeWithNym(wiring, pair.PublicKey, reinterpreted, messages, committedMessages, proverNyms, signerNymEntropy, secretProverBlind);
                Assert.IsNull(rejected, "A blind-interface signature must not finalize under the pseudonym interface.");
            }
        }
        finally
        {
            DisposeAll(proverNyms);
        }
    }


    [TestMethod]
    public void BlindInterfaceCommitmentIsRefusedByBlindSignWithNym()
    {
        //A commitment produced under the blind interface carries a Schnorr
        //challenge bound to the blind api_id; the pseudonym-interface signer
        //must refuse it outright rather than sign over an unprovable opening.
        SuiteWiring wiring = Sha256Wiring;
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] committedMessages = MakeMessages("committed", 1);
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);

        (BbsCommitmentWithProof blindCommitment, Scalar secretProverBlind) = BbsCommitmentWithProof.Commit(
            committedMessages,
            BbsCiphersuite.Bls12Curve381Sha256Blind,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarMultiply,
            TestSetup.ScalarRandom,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.Pool);
        using(blindCommitment)
        using(secretProverBlind)
        {
            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BlindSignWithNym(wiring, pair, blindCommitment, lengthNymVector: 1, signerNymEntropy, []));
            Assert.Contains("pseudonym", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
    }


    private static void RunRoundtrip(SuiteWiring wiring, int signerMessageCount, int committedMessageCount, int nymCount)
    {
        using BbsKeyPair pair = MakeKeyPair(wiring);
        BbsMessage[] signerMessages = MakeMessages("issuer", signerMessageCount);
        BbsMessage[] committedMessages = MakeMessages("committed", committedMessageCount);
        Scalar[] proverNyms = MakeRandomScalars(nymCount);
        using Scalar signerNymEntropy = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        try
        {
            (BbsCommitmentWithProof commitment, Scalar secretProverBlind) = CommitWithNym(wiring, committedMessages, proverNyms);
            using(commitment)
            using(secretProverBlind)
            {
                using BbsBlindSignature signature = BlindSignWithNym(wiring, pair, commitment, nymCount, signerNymEntropy, signerMessages);
                Scalar[]? nymSecrets = VerifyFinalizeWithNym(wiring, pair.PublicKey, signature, signerMessages, committedMessages, proverNyms, signerNymEntropy, secretProverBlind);
                Assert.IsNotNull(nymSecrets,
                    $"CommitWithNym → BlindSignWithNym → VerifyFinalizeWithNym must roundtrip for L={signerMessageCount}, M={committedMessageCount}, N={nymCount} under '{wiring.PseudonymCiphersuite.Identifier}'.");
                try
                {
                    Assert.HasCount(nymCount, nymSecrets, "Finalization must return one nym secret per prover_nym.");

                    //The entropy fold lands on exactly the last slot: every
                    //earlier secret equals its prover_nym unchanged, and the
                    //last equals prover_nyms[-1] + signer_nym_entropy.
                    for(int i = 0; i < nymCount - 1; i++)
                    {
                        Assert.IsTrue(proverNyms[i].AsReadOnlySpan().SequenceEqual(nymSecrets[i].AsReadOnlySpan()),
                            $"nym_secrets[{i}] must equal prover_nyms[{i}] unchanged.");
                    }
                    using Scalar expectedLast = proverNyms[^1].Add(signerNymEntropy, TestSetup.ScalarAdd, TestSetup.Pool);
                    Assert.IsTrue(expectedLast.AsReadOnlySpan().SequenceEqual(nymSecrets[^1].AsReadOnlySpan()),
                        "nym_secrets[-1] must equal prover_nyms[-1] + signer_nym_entropy in the scalar field.");
                }
                finally
                {
                    DisposeAll(nymSecrets);
                }
            }
        }
        finally
        {
            DisposeAll(proverNyms);
        }
    }


    private static BbsKeyPair MakeKeyPair(SuiteWiring wiring) =>
        wiring.PseudonymCiphersuite.BaseHashSuite.Generate(
            KeyMaterial,
            KeyInfo,
            wiring.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);


    private static (BbsCommitmentWithProof CommitmentWithProof, Scalar SecretProverBlind) CommitWithNym(
        SuiteWiring wiring,
        BbsMessage[] committedMessages,
        Scalar[] proverNyms) =>
        BbsCommitmentWithProof.CommitWithNym(
            committedMessages,
            proverNyms,
            wiring.PseudonymCiphersuite,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarMultiply,
            TestSetup.ScalarRandom,
            TestSetup.G1MultiScalarMultiply,
            wiring.G1HashToCurve,
            TestSetup.Pool);


    private static BbsBlindSignature BlindSignWithNym(
        SuiteWiring wiring,
        BbsKeyPair pair,
        BbsCommitmentWithProof commitmentWithProof,
        int lengthNymVector,
        Scalar signerNymEntropy,
        BbsMessage[] signerMessages) =>
        pair.SecretKey.BlindSignWithNym(
            pair.PublicKey,
            commitmentWithProof,
            lengthNymVector,
            signerNymEntropy,
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


    private static Scalar[]? VerifyFinalizeWithNym(
        SuiteWiring wiring,
        BbsPublicKey publicKey,
        BbsBlindSignature signature,
        BbsMessage[] signerMessages,
        BbsMessage[] committedMessages,
        Scalar[] proverNyms,
        Scalar signerNymEntropy,
        Scalar secretProverBlind) =>
        signature.VerifyFinalizeWithNym(
            publicKey,
            new BbsHeader(Header),
            signerMessages,
            committedMessages,
            proverNyms,
            signerNymEntropy,
            secretProverBlind,
            wiring.ExpandMessage,
            wiring.HashToScalar,
            TestSetup.ScalarAdd,
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


    private static Scalar[] MakeRandomScalars(int count)
    {
        Scalar[] scalars = new Scalar[count];
        for(int i = 0; i < count; i++)
        {
            scalars[i] = Scalar.FromRandom(TestSetup.ScalarRandom, CurveParameterSet.Bls12Curve381, TestSetup.Pool);
        }

        return scalars;
    }


    private static void DisposeAll(Scalar[] scalars)
    {
        foreach(Scalar scalar in scalars)
        {
            scalar.Dispose();
        }
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
