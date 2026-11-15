using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using static Lumoin.Veridical.Tests.Secdsa.SecdsaTestSupport;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the signed transferable proof (Verheul Algorithms 22 to 24): the honest round trip, the phased response
/// against the all-software one, and a negative test for every check of the response and of the verification. The
/// signature schemes are keyed-hash stand-ins; the ECIES cipher is the platform's AES-GCM through the test crypto
/// seam, so the tests that run a response or an issue need a platform AES-GCM and are not available on browser-wasm.
/// </summary>
[TestClass]
internal sealed class TransferableProofTests
{
    [TestMethod]
    public void HonestRoundTripIsAcceptedAndReturnsTheSecretData()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp roundtrip");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);

        Assert.IsNotNull(prover);
        Assert.IsTrue(prover.SecretData.GetBytes().SequenceEqual("secret payload"u8));
        Assert.AreEqual(TransferableProofVerdict.Accept, fixture.Verify(issued.Challenge, prover.Response));
    }


    [TestMethod]
    public void IssueIsDeterministicForAGivenSeed()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp deterministic");
        using IssuedChallenge first = fixture.Issue();
        using IssuedChallenge second = fixture.Issue();

        Assert.IsTrue(first.Challenge.AsReadOnlySpan().SequenceEqual(second.Challenge.AsReadOnlySpan()));
        Assert.IsTrue(first.Ciphertext.AsReadOnlySpan().SequenceEqual(second.Ciphertext.AsReadOnlySpan()));
    }


    [TestMethod]
    public void EphemeralPublicKeyIsTheSumOfTheSeededProducts()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp sum");
        using IssuedChallenge issued = fixture.Issue();

        //The prover recomputes E from the recovered seed in step 9; an independent response succeeding shows that E is that sum.
        using ProverResponse? prover = fixture.Respond(issued);

        Assert.IsNotNull(prover);
    }


    [TestMethod]
    public void PhasedResponseWithASimulatedKeyHolderMatchesTheSoftwareResponse()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp phased");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? software = fixture.Respond(issued);
        Assert.IsNotNull(software);

        Assert.IsTrue(TransferableProofAlgorithm.TryPrepareResponse(
            issued.Challenge, fixture.Statement, fixture.Shipped, fixture.Challenger.Verify, G1ScalarMultiply, fixture.Pool, out G1Point? toKeyHolder));
        using(toKeyHolder)
        {
            //The key holder only agrees on d·E and returns Z_AB.
            using SharedSecret sharedSecret = EciesAlgorithm.AgreeSharedSecret(
                fixture.PrivateScalarKey, toKeyHolder!, G1ScalarMultiply, fixture.Pool);

            Assert.IsTrue(CompleteFrom(fixture, sharedSecret, issued, out TransferableResponse? phased, out AdditionalData? phasedData));
            using(phased)
            using(phasedData)
            {
                Assert.IsTrue(phased!.AsReadOnlySpan().SequenceEqual(software.Response.AsReadOnlySpan()));
                Assert.IsTrue(phasedData!.GetBytes().SequenceEqual(software.SecretData.GetBytes()));
            }
        }
    }


    [TestMethod]
    public void KeyHolderThatDecryptsEntirelyInsideProducesTheSameResponse()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp hsm");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? software = fixture.Respond(issued);
        Assert.IsNotNull(software);

        Assert.IsTrue(EciesAlgorithm.TryDecrypt(
            fixture.PrivateScalarKey, issued.Ciphertext, fixture.AuthenticatedData, TransferableFixture.Parameters, fixture.EciesKdf,
            TestPlatformCrypto.AesGcmDecrypt, G1ScalarMultiply, fixture.Pool, out EciesPlaintext? decrypted));
        using(decrypted)
        {
            Assert.IsTrue(FinishFrom(fixture, decrypted!, issued.Challenge, issued.Ciphertext, out TransferableResponse? finished, out AdditionalData? finishedData));
            using(finished)
            using(finishedData)
            {
                Assert.IsTrue(finished!.AsReadOnlySpan().SequenceEqual(software.Response.AsReadOnlySpan()));
            }
        }
    }


    [TestMethod]
    public void TamperedEphemeralPublicKeyIsRejectedByTheChallengeSignature()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp tamper e");
        using IssuedChallenge issued = fixture.Issue();
        Span<byte> ephemeral = stackalloc byte[PointSize];
        issued.Challenge.GetEphemeralPublicKeyBytes().CopyTo(ephemeral);
        ephemeral[^1] ^= 0x01;
        using TransferableChallenge tampered = fixture.Rebuild(
            issued.Challenge, ephemeral, issued.Challenge.GetSecondaryDigestBytes(),
            issued.Challenge.GetAdditionalAuthenticatedDataBytes(), issued.Challenge.GetSignatureBytes());

        Assert.IsFalse(Prepares(fixture, tampered));
    }


    [TestMethod]
    public void TamperedSecondaryHashIsRejectedByTheChallengeSignature()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp tamper h2");
        using IssuedChallenge issued = fixture.Issue();
        Span<byte> secondary = stackalloc byte[DigestSize];
        issued.Challenge.GetSecondaryDigestBytes().CopyTo(secondary);
        secondary[0] ^= 0x01;
        using TransferableChallenge tampered = fixture.Rebuild(
            issued.Challenge, issued.Challenge.GetEphemeralPublicKeyBytes(), secondary,
            issued.Challenge.GetAdditionalAuthenticatedDataBytes(), issued.Challenge.GetSignatureBytes());

        Assert.IsFalse(Prepares(fixture, tampered));
    }


    [TestMethod]
    public void TamperedAdditionalDataIsRejectedByTheProverAndTheVerifier()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp tamper aad");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);
        Span<byte> aad = stackalloc byte[issued.Challenge.GetAdditionalAuthenticatedDataBytes().Length];
        issued.Challenge.GetAdditionalAuthenticatedDataBytes().CopyTo(aad);
        aad[0] ^= 0x01;
        using TransferableChallenge tampered = fixture.Rebuild(
            issued.Challenge, issued.Challenge.GetEphemeralPublicKeyBytes(), issued.Challenge.GetSecondaryDigestBytes(),
            aad, issued.Challenge.GetSignatureBytes());

        Assert.IsFalse(Prepares(fixture, tampered));
        Assert.AreEqual(TransferableProofVerdict.RejectStatementMismatch, fixture.Verify(tampered, prover.Response));
    }


    [TestMethod]
    public void TamperedChallengeSignatureIsRejected()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp tamper sig");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);
        Span<byte> signature = stackalloc byte[issued.Challenge.GetSignatureBytes().Length];
        issued.Challenge.GetSignatureBytes().CopyTo(signature);
        signature[0] ^= 0x01;
        using TransferableChallenge tampered = fixture.Rebuild(
            issued.Challenge, issued.Challenge.GetEphemeralPublicKeyBytes(), issued.Challenge.GetSecondaryDigestBytes(),
            issued.Challenge.GetAdditionalAuthenticatedDataBytes(), signature);

        Assert.IsFalse(Prepares(fixture, tampered));
        Assert.AreEqual(TransferableProofVerdict.RejectChallengeSignature, fixture.Verify(tampered, prover.Response));
    }


    [TestMethod]
    public void TamperedChallengeSignatureReleasesNoResponseAndNoSecretDataFromAnyEntryPoint()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp unsigned challenge");
        using IssuedChallenge issued = fixture.Issue();
        Span<byte> signature = stackalloc byte[issued.Challenge.GetSignatureBytes().Length];
        issued.Challenge.GetSignatureBytes().CopyTo(signature);
        signature[0] ^= 0x01;
        using TransferableChallenge tampered = fixture.Rebuild(
            issued.Challenge, issued.Challenge.GetEphemeralPublicKeyBytes(), issued.Challenge.GetSecondaryDigestBytes(),
            issued.Challenge.GetAdditionalAuthenticatedDataBytes(), signature);
        using IssuedChallenge unsigned = new(tampered, issued.Ciphertext, ownsParts: false);

        //The software path.
        Assert.IsFalse(fixture.Responds(unsigned));

        //The phased path, with the correct shared secret from the key holder.
        using G1Point ephemeral = tampered.GetEphemeralPublicKey(fixture.Pool);
        using SharedSecret sharedSecret = EciesAlgorithm.AgreeSharedSecret(fixture.PrivateScalarKey, ephemeral, G1ScalarMultiply, fixture.Pool);
        Assert.IsFalse(CompleteFrom(fixture, sharedSecret, unsigned, out TransferableResponse? phased, out AdditionalData? phasedData));
        Assert.IsNull(phased);
        Assert.IsNull(phasedData);
        phased?.Dispose();
        phasedData?.Dispose();

        //The HSM-full-decrypt path, with the correct plaintext.
        Assert.IsTrue(EciesAlgorithm.TryDecrypt(
            fixture.PrivateScalarKey, issued.Ciphertext, fixture.AuthenticatedData, TransferableFixture.Parameters, fixture.EciesKdf,
            TestPlatformCrypto.AesGcmDecrypt, G1ScalarMultiply, fixture.Pool, out EciesPlaintext? decrypted));
        using(decrypted)
        {
            Assert.IsFalse(FinishFrom(fixture, decrypted!, tampered, issued.Ciphertext, out TransferableResponse? finished, out AdditionalData? finishedData));
            Assert.IsNull(finished);
            Assert.IsNull(finishedData);
            finished?.Dispose();
            finishedData?.Dispose();
        }
    }


    [TestMethod]
    public void ChallengeSignedByAnotherPartyIsRejected()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp other challenger");
        using MacSignature stranger = new(fixture.Pool, "stranger");
        using IssuedChallenge issued = fixture.Issue();

        Assert.IsFalse(fixture.Responds(issued, challengeVerify: stranger.Verify));
    }


    [TestMethod]
    public void TamperedCiphertextBodyAndTagReleaseNoResponse()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp tamper ct");
        using IssuedChallenge issued = fixture.Issue();
        Span<byte> body = stackalloc byte[issued.Ciphertext.GetEncryptedBytes().Length];
        Span<byte> tag = stackalloc byte[issued.Ciphertext.GetAuthenticationTagBytes().Length];
        issued.Ciphertext.GetEncryptedBytes().CopyTo(body);
        issued.Ciphertext.GetAuthenticationTagBytes().CopyTo(tag);
        body[0] ^= 0x01;
        using EciesCiphertext badBody = EciesCiphertext.FromParts(
            issued.Ciphertext.GetEphemeralPublicKeyBytes(), issued.Ciphertext.GetAuthenticationTagBytes(), body, TransferableFixture.Parameters, fixture.Pool);
        body[0] ^= 0x01;
        tag[0] ^= 0x01;
        using EciesCiphertext badTag = EciesCiphertext.FromParts(
            issued.Ciphertext.GetEphemeralPublicKeyBytes(), tag, body, TransferableFixture.Parameters, fixture.Pool);

        Assert.IsFalse(fixture.Responds(issued, ciphertext: badBody));
        Assert.IsFalse(fixture.Responds(issued, ciphertext: badTag));
    }


    [TestMethod]
    public void WrongPrivateKeyReleasesNoResponse()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp wrong key");
        using IssuedChallenge issued = fixture.Issue();
        Span<byte> other = stackalloc byte[ScalarSize];
        DeriveScalar("tp some other prover"u8, other);

        Assert.IsFalse(fixture.Responds(issued, privateKey: other));
    }


    [TestMethod]
    public void SeedDerivedKeysThatDoNotYieldTheEphemeralKeyAreRejectedAtStep9()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp step 9");
        using IssuedChallenge issued = fixture.Issue();

        //A challenge whose E is another point, with the genuine plaintext: the keys recomputed from the seed do not yield it.
        Span<byte> doubled = stackalloc byte[PointSize];
        Multiply(issued.Challenge.GetEphemeralPublicKeyBytes(), TwoScalar(stackalloc byte[ScalarSize]), doubled);
        using TransferableChallenge other = fixture.Rebuild(
            issued.Challenge, doubled, issued.Challenge.GetSecondaryDigestBytes(),
            issued.Challenge.GetAdditionalAuthenticatedDataBytes(), issued.Challenge.GetSignatureBytes());

        Assert.IsTrue(EciesAlgorithm.TryDecrypt(
            fixture.PrivateScalarKey, issued.Ciphertext, fixture.AuthenticatedData, TransferableFixture.Parameters, fixture.EciesKdf,
            TestPlatformCrypto.AesGcmDecrypt, G1ScalarMultiply, fixture.Pool, out EciesPlaintext? decrypted));
        using(decrypted)
        {
            Assert.IsFalse(FinishFrom(fixture, decrypted!, other, issued.Ciphertext, out TransferableResponse? response, out AdditionalData? data, AcceptAnySignature));
            Assert.IsNull(response);
            Assert.IsNull(data);
            response?.Dispose();
            data?.Dispose();
        }
    }


    [TestMethod]
    public void WrongSecondaryHashIsRejectedAtStep13()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp step 13");
        using IssuedChallenge issued = fixture.Issue();
        Span<byte> secondary = stackalloc byte[DigestSize];
        issued.Challenge.GetSecondaryDigestBytes().CopyTo(secondary);
        secondary[0] ^= 0x01;
        using TransferableChallenge other = fixture.Rebuild(
            issued.Challenge, issued.Challenge.GetEphemeralPublicKeyBytes(), secondary,
            issued.Challenge.GetAdditionalAuthenticatedDataBytes(), issued.Challenge.GetSignatureBytes());

        Assert.IsTrue(EciesAlgorithm.TryDecrypt(
            fixture.PrivateScalarKey, issued.Ciphertext, fixture.AuthenticatedData, TransferableFixture.Parameters, fixture.EciesKdf,
            TestPlatformCrypto.AesGcmDecrypt, G1ScalarMultiply, fixture.Pool, out EciesPlaintext? decrypted));
        using(decrypted)
        {
            Assert.IsFalse(FinishFrom(fixture, decrypted!, other, issued.Ciphertext, out TransferableResponse? response, out AdditionalData? data, AcceptAnySignature));
            Assert.IsNull(response);
            Assert.IsNull(data);
            response?.Dispose();
            data?.Dispose();
        }
    }


    [TestMethod]
    public void ChallengerWhoEncryptsUnderDEBecauseOneGeneratorIsAMultipleOfAnotherIsCaughtAtStep11()
    {
        //G1 = c·G0 and D1 ≠ d·G1. The challenger knows d·G1 = c·D0, so it can encrypt under the key from d·E and the
        //decryption of step 7 succeeds; only the repeated decryption of step 11 under the key from the sum of ei·Di fails.
        using TransferableFixture fixture = TransferableFixture.Create("tp step 11", consistent: false);
        using IssuedChallenge honest = fixture.Issue();

        //Honest issuance on the false statement encrypts under the key from the sum of ei·Di, so the prover cannot decrypt at all.
        Assert.IsFalse(fixture.Responds(honest));

        //The forged ciphertext: same E, plaintext Seed || ASD, key derived from d·E.
        using SharedSecret forgedSecret = EciesAlgorithm.AgreeSharedSecret(
            fixture.PrivateScalarKey, honest.Challenge.GetEphemeralPublicKey(fixture.Pool), G1ScalarMultiply, fixture.Pool);
        using EciesPlaintext payload = PayloadOf(fixture);
        using EciesCiphertext forged = EciesAlgorithm.Seal(
            honest.Challenge.GetEphemeralPublicKeyBytes(), forgedSecret, payload, fixture.AuthenticatedData, TransferableFixture.Parameters,
            fixture.EciesKdf, TestPlatformCrypto.AesGcmEncrypt, fixture.Pool, null);

        //Step 7 succeeds under the forged ciphertext.
        Assert.IsTrue(EciesAlgorithm.TryCompleteDecryption(
            forgedSecret, forged, fixture.AuthenticatedData, TransferableFixture.Parameters, fixture.EciesKdf,
            TestPlatformCrypto.AesGcmDecrypt, fixture.Pool, out EciesPlaintext? step7));
        step7!.Dispose();

        //The whole response is refused.
        Assert.IsFalse(fixture.Responds(honest, ciphertext: forged));
    }


    [TestMethod]
    public void SameForgeryOnAConsistentStatementIsAcceptedSoStep11IsTheOnlyDifference()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp step 11 control");
        using IssuedChallenge honest = fixture.Issue();
        using SharedSecret secret = EciesAlgorithm.AgreeSharedSecret(
            fixture.PrivateScalarKey, honest.Challenge.GetEphemeralPublicKey(fixture.Pool), G1ScalarMultiply, fixture.Pool);
        using EciesPlaintext payload = PayloadOf(fixture);
        using EciesCiphertext viaDe = EciesAlgorithm.Seal(
            honest.Challenge.GetEphemeralPublicKeyBytes(), secret, payload, fixture.AuthenticatedData, TransferableFixture.Parameters,
            fixture.EciesKdf, TestPlatformCrypto.AesGcmEncrypt, fixture.Pool, null);
        using ProverResponse? prover = fixture.Respond(honest, ciphertext: viaDe);

        Assert.IsNotNull(prover);
    }


    [TestMethod]
    public void TamperedResponseSignatureIsRejected()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp tamper sigp");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);
        Span<byte> signature = stackalloc byte[prover.Response.GetSignatureBytes().Length];
        prover.Response.GetSignatureBytes().CopyTo(signature);
        signature[0] ^= 0x01;
        using TransferableResponse tampered = fixture.Rebuild(prover.Response, prover.Response.GetPrimaryDigestBytes(), signature);

        Assert.AreEqual(TransferableProofVerdict.RejectResponseSignature, fixture.Verify(issued.Challenge, tampered));
    }


    [TestMethod]
    public void TamperedPrimaryHashInTheResponseIsRejectedBySignatureOrDigest()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp tamper h1");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);
        Span<byte> primary = stackalloc byte[DigestSize];
        prover.Response.GetPrimaryDigestBytes().CopyTo(primary);
        primary[0] ^= 0x01;
        using TransferableResponse tampered = fixture.Rebuild(prover.Response, primary, prover.Response.GetSignatureBytes());

        Assert.AreEqual(TransferableProofVerdict.RejectResponseSignature, fixture.Verify(issued.Challenge, tampered));
    }


    [TestMethod]
    public void ValidlySignedResponseWithAPrimaryHashThatDoesNotHashToH2IsRejectedAtStep6()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp step 6");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);

        //A prover that signs a different H1: the signature verifies but H(H1) is not H2.
        Span<byte> primary = stackalloc byte[DigestSize];
        prover.Response.GetPrimaryDigestBytes().CopyTo(primary);
        primary[0] ^= 0x01;
        using ProofDigest changed = ProofDigest.FromCanonical(primary, ProofDigestKind.Primary, fixture.Pool);
        using G1Point ephemeral = issued.Challenge.GetEphemeralPublicKey(fixture.Pool);
        using ProofDigest secondary = issued.Challenge.GetSecondaryDigest(fixture.Pool);
        using LayoutWriter scope = new(fixture.Pool);
        fixture.Shipped.EncodeResponseScope(ephemeral, fixture.Statement, secondary, changed, scope);
        Span<byte> signature = stackalloc byte[DigestSize];
        fixture.Prover.Sign(scope.WrittenBytes, signature);
        using TransferableResponse forged = fixture.Rebuild(prover.Response, primary, signature);

        Assert.AreEqual(TransferableProofVerdict.RejectDigest, fixture.Verify(issued.Challenge, forged));
    }


    [TestMethod]
    public void WrongVerificationKeysAreRejected()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp wrong verify keys");
        using MacSignature stranger = new(fixture.Pool, "stranger");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);

        Assert.AreEqual(TransferableProofVerdict.RejectChallengeSignature, fixture.Verify(issued.Challenge, prover.Response, challengeVerify: stranger.Verify));
        Assert.AreEqual(TransferableProofVerdict.RejectResponseSignature, fixture.Verify(issued.Challenge, prover.Response, responseVerify: stranger.Verify));
    }


    [TestMethod]
    public void ChangedPublicKeyInTheStatementIsRejectedByTheChallengeSignature()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp statement");
        using TransferableFixture other = TransferableFixture.Create("tp statement other");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);
        using AdditionalData sameData = AdditionalData.FromCanonical(
            fixture.AuthenticatedData.GetBytes(), AdditionalDataRole.Authenticated, fixture.Pool);
        ProofStatement changed = new(fixture.Generators, other.PublicKeys, sameData);

        Assert.AreEqual(TransferableProofVerdict.RejectChallengeSignature, fixture.Verify(issued.Challenge, prover.Response, statement: changed));
    }


    [TestMethod]
    public void ChallengeAndResponseUnderDifferentProfilesAreRejected()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp profile mismatch");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);
        using TransferableResponse retagged = fixture.Rebuild(
            prover.Response, prover.Response.GetPrimaryDigestBytes(), prover.Response.GetSignatureBytes(), TestLayoutProfile.ProfileId);

        Assert.AreEqual(TransferableProofVerdict.RejectProfileMismatch, fixture.Verify(issued.Challenge, retagged));
    }


    [TestMethod]
    public void ValueSignedUnderOneProfileIsRejectedUnderTheOther()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp two profiles");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);

        //Verified under the other profile, the recorded profile identifier does not match.
        Assert.AreEqual(TransferableProofVerdict.RejectProfileMismatch, fixture.Verify(issued.Challenge, prover.Response, TestLayoutProfile.Profile));

        //Retagged to claim the other profile, the signature no longer matches the other profile's bytes.
        using TransferableChallenge claimed = fixture.Rebuild(
            issued.Challenge, issued.Challenge.GetEphemeralPublicKeyBytes(), issued.Challenge.GetSecondaryDigestBytes(),
            issued.Challenge.GetAdditionalAuthenticatedDataBytes(), issued.Challenge.GetSignatureBytes(), TestLayoutProfile.ProfileId);
        using TransferableResponse claimedResponse = fixture.Rebuild(
            prover.Response, prover.Response.GetPrimaryDigestBytes(), prover.Response.GetSignatureBytes(), TestLayoutProfile.ProfileId);

        Assert.AreEqual(TransferableProofVerdict.RejectChallengeSignature, fixture.Verify(claimed, claimedResponse, TestLayoutProfile.Profile));
    }


    [TestMethod]
    public void WholeProtocolRunsUnderTheSecondProfileWithoutChangingAnyAlgorithm()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp second profile");
        using IssuedChallenge issued = fixture.Issue(TestLayoutProfile.Profile);
        using ProverResponse? prover = fixture.Respond(issued, TestLayoutProfile.Profile);

        Assert.IsNotNull(prover);
        Assert.AreEqual(TestLayoutProfile.ProfileId, issued.Challenge.Profile);
        Assert.AreEqual(TestLayoutProfile.ProfileId, prover.Response.Profile);
        Assert.AreEqual(TransferableProofVerdict.Accept, fixture.Verify(issued.Challenge, prover.Response, TestLayoutProfile.Profile));
        Assert.IsTrue(prover.SecretData.GetBytes().SequenceEqual("secret payload"u8));
    }


    [TestMethod]
    public void ProfilesProduceDifferentChallengesForTheSameSeedAndStatement()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp profiles differ");
        using IssuedChallenge shipped = fixture.Issue();
        using IssuedChallenge test = fixture.Issue(TestLayoutProfile.Profile);

        //The derived keys differ because the derivation input differs, so E differs too.
        Assert.IsFalse(shipped.Challenge.GetEphemeralPublicKeyBytes().SequenceEqual(test.Challenge.GetEphemeralPublicKeyBytes()));
    }


    [TestMethod]
    public void IssueRejectsASecretDataRoleMismatchAndAnUnusableSignatureLength()
    {
        using TransferableFixture fixture = TransferableFixture.Create("tp issue guards");

        Assert.ThrowsExactly<ArgumentException>(() => IssueWith(fixture, fixture.AuthenticatedData, fixture.Challenger.Sign));
        Assert.ThrowsExactly<InvalidOperationException>(() => IssueWith(fixture, fixture.SecretData, ReportsZeroLength));
        Assert.ThrowsExactly<InvalidOperationException>(() => IssueWith(fixture, fixture.SecretData, ReportsTooLong));
    }


    [TestMethod]
    public void SeededKeyReductionStaysInRangeAndIsTheModularReductionPlusOne()
    {
        //x = 0 reduces to 1; x = q - 1 reduces to 1; x = q - 2 reduces to q - 1.
        Span<byte> wide = stackalloc byte[P256SeededKeyReduction.WideSizeBytes];
        Span<byte> key = stackalloc byte[ScalarSize];
        Span<byte> expected = stackalloc byte[ScalarSize];

        P256SeededKeyReduction.Reduce(wide, key);
        expected.Clear();
        expected[^1] = 1;
        Assert.IsTrue(key.SequenceEqual(expected), "Zero must reduce to 1.");

        P256ScalarValidation.OrderBytes.CopyTo(wide[(wide.Length - ScalarSize)..]);
        wide[^1]--;
        P256SeededKeyReduction.Reduce(wide, key);
        Assert.IsTrue(key.SequenceEqual(expected), "q - 1 must reduce to 1.");

        wide[^1]--;
        P256SeededKeyReduction.Reduce(wide, key);
        P256ScalarValidation.OrderBytes.CopyTo(expected);
        expected[^1]--;
        Assert.IsTrue(key.SequenceEqual(expected), "q - 2 must reduce to q - 1.");
    }


    [TestMethod]
    public void SeededKeyReductionMatchesBigIntegerArithmetic()
    {
        DeterministicEntropy entropy = new("tp reduction");
        Span<byte> wide = stackalloc byte[P256SeededKeyReduction.WideSizeBytes];
        Span<byte> key = stackalloc byte[ScalarSize];
        for(int round = 0; round < 25; round++)
        {
            entropy.Fill(wide);
            P256SeededKeyReduction.Reduce(wide, key);

            System.Numerics.BigInteger order = new(P256ScalarValidation.OrderBytes, isUnsigned: true, isBigEndian: true);
            System.Numerics.BigInteger value = new(wide, isUnsigned: true, isBigEndian: true);
            System.Numerics.BigInteger expected = 1 + (value % (order - 1));
            System.Numerics.BigInteger actual = new(key, isUnsigned: true, isBigEndian: true);

            Assert.AreEqual(expected, actual);
        }
    }


    private static void IssueWith(TransferableFixture fixture, AdditionalData secretData, StructureSignDelegate sign)
    {
        TransferableChallenge challenge = TransferableProofAlgorithm.Issue(
            fixture.Statement, secretData, fixture.Seed, fixture.Shipped, TransferableFixture.Parameters, TransferableFixture.SeedKeyDerivation,
            fixture.EciesKdf, TestPlatformCrypto.AesGcmEncrypt, sign, Hash, G1ScalarMultiply, G1Add, fixture.Pool, out EciesCiphertext ciphertext);
        challenge.Dispose();
        ciphertext.Dispose();
    }


    private static int ReportsZeroLength(ReadOnlySpan<byte> structure, Span<byte> signature)
    {
        return 0;
    }


    private static int ReportsTooLong(ReadOnlySpan<byte> structure, Span<byte> signature)
    {
        return TransferableProofAlgorithm.MaxSignatureSizeBytes + 1;
    }


    private static Span<byte> TwoScalar(Span<byte> scalar)
    {
        scalar.Clear();
        scalar[^1] = 2;

        return scalar;
    }


    private static EciesPlaintext PayloadOf(TransferableFixture fixture)
    {
        using LayoutWriter payload = new(fixture.Pool);
        fixture.Shipped.EncodeSeedPayload(fixture.Seed, fixture.SecretData, payload);

        return EciesPlaintext.FromCanonical(payload.WrittenBytes, fixture.Pool);
    }


    //Accepts every signature, so a test of a later step is not decided by the signature check of step 4.
    private static bool AcceptAnySignature(ReadOnlySpan<byte> structure, ReadOnlySpan<byte> signature)
    {
        return true;
    }


    private static bool Prepares(TransferableFixture fixture, TransferableChallenge challenge)
    {
        bool prepared = TransferableProofAlgorithm.TryPrepareResponse(
            challenge, fixture.Statement, fixture.Shipped, fixture.Challenger.Verify, G1ScalarMultiply, fixture.Pool, out G1Point? point);
        point?.Dispose();

        return prepared;
    }


    private static bool CompleteFrom(
        TransferableFixture fixture,
        SharedSecret sharedSecret,
        IssuedChallenge issued,
        out TransferableResponse? response,
        out AdditionalData? secretData)
    {
        return TransferableProofAlgorithm.TryCompleteResponse(
            sharedSecret, issued.Challenge, issued.Ciphertext, fixture.Statement, fixture.Shipped, TransferableFixture.Parameters,
            fixture.Challenger.Verify, TransferableFixture.SeedKeyDerivation, fixture.EciesKdf, TestPlatformCrypto.AesGcmDecrypt, fixture.Prover.Sign,
            Hash, G1ScalarMultiply, G1Add, fixture.Pool, out response, out secretData);
    }


    private static bool FinishFrom(
        TransferableFixture fixture,
        EciesPlaintext decrypted,
        TransferableChallenge challenge,
        EciesCiphertext ciphertext,
        out TransferableResponse? response,
        out AdditionalData? secretData,
        StructureVerifyDelegate? challengeVerify = null)
    {
        return TransferableProofAlgorithm.TryFinishResponse(
            decrypted, challenge, ciphertext, fixture.Statement, fixture.Shipped, TransferableFixture.Parameters,
            challengeVerify ?? fixture.Challenger.Verify, TransferableFixture.SeedKeyDerivation, fixture.EciesKdf, TestPlatformCrypto.AesGcmDecrypt, fixture.Prover.Sign,
            Hash, G1ScalarMultiply, G1Add, fixture.Pool, out response, out secretData);
    }

}
