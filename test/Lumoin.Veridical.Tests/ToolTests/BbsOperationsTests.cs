using Lumoin.Veridical.Cli;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// In-process tests of <see cref="BbsOperations"/>, the shared implementation behind the <c>bbs-*</c>
/// subcommands and their MCP tools: key generation, sign then verify, proof generation with selective
/// disclosure then proof verification, and the rejections for tampered or malformed input.
/// </summary>
[TestClass]
internal sealed class BbsOperationsTests
{
    private const string Header = "bbs-tool-header";

    private const string PresentationHeader = "bbs-tool-presentation";

    private const string KeyInfo = "bbs-tool-key-info";

    private const int ExpectedSecretKeyHexLength = 64;

    private const int ExpectedPublicKeyHexLength = 192;

    private const int ExpectedSignatureHexLength = 160;


    private static IReadOnlyList<string> Messages { get; } = ["alpha", "beta", "gamma", "delta"];

    private static IReadOnlyList<string> DisclosedMessages { get; } = ["0=alpha", "2=gamma"];

    private static string[] Suites { get; } = [BbsPlatformComposition.Sha256Name, BbsPlatformComposition.Shake256Name];


    [TestMethod]
    public void GenerateKeyProducesAKeyPairOfTheDocumentedSizesAndDrawsFreshMaterial()
    {
        (string secret, string publicKey) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, null, KeyInfo);
        (string otherSecret, _) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, null, KeyInfo);

        Assert.AreEqual(ExpectedSecretKeyHexLength, secret.Length);
        Assert.AreEqual(ExpectedPublicKeyHexLength, publicKey.Length);
        Assert.AreNotEqual(secret, otherSecret, "Two draws from the operating system must give different keys.");
    }


    [TestMethod]
    public void GenerateKeyFromTheSameKeyMaterialIsDeterministic()
    {
        string material = new('a', 2 * BbsOperations.KeyMaterialBytes);

        (string firstSecret, string firstPublic) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, material, KeyInfo);
        (string secondSecret, string secondPublic) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, material, KeyInfo);

        Assert.AreEqual(firstSecret, secondSecret);
        Assert.AreEqual(firstPublic, secondPublic);
    }


    [TestMethod]
    public void GenerateKeyRejectsShortKeyMaterialAndAnUnknownCiphersuite()
    {
        Assert.ThrowsExactly<ArgumentException>(() => BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, "aabb", KeyInfo));
        Assert.ThrowsExactly<ArgumentException>(() => BbsOperations.GenerateKey("md5", null, KeyInfo));
    }


    [TestMethod]
    public void SignThenVerifyRoundTripsForBothCiphersuites()
    {
        foreach(string suite in Suites)
        {
            (string secret, string publicKey) = BbsOperations.GenerateKey(suite, null, KeyInfo);

            string signature = BbsOperations.Sign(suite, secret, publicKey, Header, Messages, hexMessages: false);
            VerificationResult result = BbsOperations.Verify(suite, publicKey, signature, Header, Messages, hexMessages: false);

            Assert.AreEqual(ExpectedSignatureHexLength, signature.Length);
            Assert.AreEqual(VerificationStatus.Valid, result.Status, result.Message);
        }
    }


    [TestMethod]
    public void VerifyRejectsAChangedMessageHeaderOrCiphersuite()
    {
        (string secret, string publicKey) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, null, KeyInfo);
        string signature = BbsOperations.Sign(BbsPlatformComposition.Sha256Name, secret, publicKey, Header, Messages, hexMessages: false);

        Assert.AreEqual(
            VerificationStatus.Rejected,
            BbsOperations.Verify(BbsPlatformComposition.Sha256Name, publicKey, signature, Header, ["alpha", "beta", "gamma", "changed"], hexMessages: false).Status);
        Assert.AreEqual(
            VerificationStatus.Rejected,
            BbsOperations.Verify(BbsPlatformComposition.Sha256Name, publicKey, signature, "another-header", Messages, hexMessages: false).Status);
        Assert.AreNotEqual(
            VerificationStatus.Valid,
            BbsOperations.Verify(BbsPlatformComposition.Shake256Name, publicKey, signature, Header, Messages, hexMessages: false).Status);
    }


    [TestMethod]
    public void VerifyAnswersMalformedForUnparseableInputs()
    {
        (_, string publicKey) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, null, KeyInfo);

        Assert.AreEqual(
            VerificationStatus.Malformed,
            BbsOperations.Verify(BbsPlatformComposition.Sha256Name, publicKey, "zz", Header, Messages, hexMessages: false).Status);
        Assert.AreEqual(
            VerificationStatus.Malformed,
            BbsOperations.Verify(BbsPlatformComposition.Sha256Name, "00", new string('1', ExpectedSignatureHexLength), Header, Messages, hexMessages: false).Status);
    }


    [TestMethod]
    public void HexMessagesSignTheSameBytesAsTheirTextForm()
    {
        (string secret, string publicKey) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, null, KeyInfo);
        string signature = BbsOperations.Sign(BbsPlatformComposition.Sha256Name, secret, publicKey, Header, ["alpha", "beta"], hexMessages: false);

        //"alpha" and "beta" as UTF-8 hex.
        VerificationResult result = BbsOperations.Verify(BbsPlatformComposition.Sha256Name, publicKey, signature, Header, ["616c706861", "62657461"], hexMessages: true);

        Assert.AreEqual(VerificationStatus.Valid, result.Status, result.Message);
    }


    [TestMethod]
    public void ProofWithSelectiveDisclosureRoundTripsAndRejectsTampering()
    {
        (string secret, string publicKey) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, null, KeyInfo);
        string signature = BbsOperations.Sign(BbsPlatformComposition.Sha256Name, secret, publicKey, Header, Messages, hexMessages: false);

        string proof = BbsOperations.GenerateProof(BbsPlatformComposition.Sha256Name, publicKey, signature, Header, PresentationHeader, Messages, hexMessages: false, disclosed: "0,2");
        VerificationResult valid = BbsOperations.VerifyProof(BbsPlatformComposition.Sha256Name, publicKey, proof, Header, PresentationHeader, DisclosedMessages, hexMessages: false);
        VerificationResult wrongMessage = BbsOperations.VerifyProof(BbsPlatformComposition.Sha256Name, publicKey, proof, Header, PresentationHeader, ["0=alpha", "2=changed"], hexMessages: false);
        VerificationResult wrongPresentation = BbsOperations.VerifyProof(BbsPlatformComposition.Sha256Name, publicKey, proof, Header, "another-presentation", DisclosedMessages, hexMessages: false);

        Assert.AreEqual(VerificationStatus.Valid, valid.Status, valid.Message);
        Assert.Contains("2 undisclosed", valid.Message, StringComparison.Ordinal);
        Assert.AreEqual(VerificationStatus.Rejected, wrongMessage.Status);
        Assert.AreEqual(VerificationStatus.Rejected, wrongPresentation.Status);
    }


    [TestMethod]
    public void ProofDisclosingNothingVerifiesAndTwoProofsDiffer()
    {
        (string secret, string publicKey) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, null, KeyInfo);
        string signature = BbsOperations.Sign(BbsPlatformComposition.Sha256Name, secret, publicKey, Header, Messages, hexMessages: false);

        string first = BbsOperations.GenerateProof(BbsPlatformComposition.Sha256Name, publicKey, signature, Header, PresentationHeader, Messages, hexMessages: false, disclosed: string.Empty);
        string second = BbsOperations.GenerateProof(BbsPlatformComposition.Sha256Name, publicKey, signature, Header, PresentationHeader, Messages, hexMessages: false, disclosed: string.Empty);

        Assert.AreNotEqual(first, second, "Proofs draw fresh randomness, so two proofs of one signature differ.");
        Assert.AreEqual(VerificationStatus.Valid, BbsOperations.VerifyProof(BbsPlatformComposition.Sha256Name, publicKey, first, Header, PresentationHeader, [], hexMessages: false).Status);
    }


    [TestMethod]
    public void GenerateProofRejectsInvalidDisclosedIndices()
    {
        (string secret, string publicKey) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, null, KeyInfo);
        string signature = BbsOperations.Sign(BbsPlatformComposition.Sha256Name, secret, publicKey, Header, Messages, hexMessages: false);

        Assert.ThrowsExactly<ArgumentException>(() => BbsOperations.GenerateProof(BbsPlatformComposition.Sha256Name, publicKey, signature, Header, PresentationHeader, Messages, false, "2,0"));
        Assert.ThrowsExactly<ArgumentException>(() => BbsOperations.GenerateProof(BbsPlatformComposition.Sha256Name, publicKey, signature, Header, PresentationHeader, Messages, false, "9"));
        Assert.ThrowsExactly<ArgumentException>(() => BbsOperations.GenerateProof(BbsPlatformComposition.Sha256Name, publicKey, signature, Header, PresentationHeader, Messages, false, "x"));
    }


    [TestMethod]
    public void VerifyProofAnswersMalformedForABadDisclosedEntryAndAShortProof()
    {
        (_, string publicKey) = BbsOperations.GenerateKey(BbsPlatformComposition.Sha256Name, null, KeyInfo);

        Assert.AreEqual(
            VerificationStatus.Malformed,
            BbsOperations.VerifyProof(BbsPlatformComposition.Sha256Name, publicKey, "00", Header, PresentationHeader, ["no-separator"], hexMessages: false).Status);
        Assert.AreEqual(
            VerificationStatus.Malformed,
            BbsOperations.VerifyProof(BbsPlatformComposition.Sha256Name, publicKey, "00", Header, PresentationHeader, ["0=alpha"], hexMessages: false).Status);
    }
}
