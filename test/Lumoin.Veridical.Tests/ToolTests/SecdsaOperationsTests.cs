using Lumoin.Veridical.Cli;
using System;
using System.Globalization;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// In-process tests of <see cref="SecdsaOperations"/>, the shared implementation behind the <c>secdsa-*</c>
/// subcommands and their MCP tools. Each primitive is round-tripped through the operations alone: points are
/// built as <c>(a*b)*G</c> with <see cref="SecdsaOperations.DerivePublicKey"/>, so the tests need no group
/// arithmetic of their own.
/// </summary>
[TestClass]
internal sealed class SecdsaOperationsTests
{
    private const int ScalarHexLength = 64;

    private const int SignatureHexLength = 128;

    private const int MacHexLength = 64;

    //SHA-256 of "abc", a fixed 32-byte message hash.
    private const string MessageHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private const string AnotherMessageHash = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    private const ulong PinKey = 7;

    private const ulong HardwareKey = 11;

    private const ulong DlWitness = 13;

    private const ulong SecondBaseScalar = 17;

    private const ulong WalletShare = 2;

    private const ulong WscaShare = 3;

    private const ulong BaseKey = 5;

    private const ulong ComposedPrivateKey = WalletShare * WscaShare * BaseKey;

    private const ulong VerifierEphemeralKey = 19;

    private const string Challenge = "6368616c6c656e6765";

    private const string Salt = "73616c74";

    private const string SharedInfo = "696e666f";

    private const string Message = "6d657373616765";


    [TestMethod]
    public void SplitSignThenVerifyRoundTripsUnderTheDerivedPublicKey()
    {
        string publicKey = SecdsaOperations.DerivePublicKey(Scalar(PinKey), Scalar(HardwareKey));
        string signature = SecdsaOperations.SplitSign(Scalar(PinKey), Scalar(HardwareKey), MessageHash);

        VerificationResult valid = SecdsaOperations.Verify(publicKey, MessageHash, signature);
        VerificationResult wrongHash = SecdsaOperations.Verify(publicKey, AnotherMessageHash, signature);

        Assert.AreEqual(SignatureHexLength, signature.Length);
        Assert.AreEqual(VerificationStatus.Valid, valid.Status, valid.Message);
        Assert.AreEqual(VerificationStatus.Rejected, wrongHash.Status);
    }


    [TestMethod]
    public void SplitSignIsDeterministicUnderTheRfc6979NonceSource()
    {
        string first = SecdsaOperations.SplitSign(Scalar(PinKey), Scalar(HardwareKey), MessageHash);
        string second = SecdsaOperations.SplitSign(Scalar(PinKey), Scalar(HardwareKey), MessageHash);

        Assert.AreEqual(first, second);
    }


    [TestMethod]
    public void SplitSignRejectsAZeroOrMalformedKeyScalar()
    {
        Assert.ThrowsExactly<ArgumentException>(() => SecdsaOperations.SplitSign(Scalar(0), Scalar(HardwareKey), MessageHash));
        Assert.ThrowsExactly<ArgumentException>(() => SecdsaOperations.SplitSign("zz", Scalar(HardwareKey), MessageHash));
        Assert.ThrowsExactly<ArgumentException>(() => SecdsaOperations.SplitSign(Scalar(PinKey), Scalar(HardwareKey), "00"));
    }


    [TestMethod]
    public void VerifyAnswersMalformedForAWrongLengthSignature()
    {
        string publicKey = SecdsaOperations.DerivePublicKey(Scalar(PinKey), Scalar(HardwareKey));

        VerificationResult result = SecdsaOperations.Verify(publicKey, MessageHash, "00ff");

        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
    }


    [TestMethod]
    public void RecoveredNoncePointVerifiesTheSignatureAndATamperedSDoesNot()
    {
        string publicKey = SecdsaOperations.DerivePublicKey(Scalar(PinKey), Scalar(HardwareKey));
        string signature = SecdsaOperations.SplitSign(Scalar(PinKey), Scalar(HardwareKey), MessageHash);
        string s = signature[ScalarHexLength..];

        string noncePoint = SecdsaOperations.RecoverNoncePoint(publicKey, MessageHash, signature);
        VerificationResult valid = SecdsaOperations.VerifyFull(publicKey, MessageHash, noncePoint, s);
        VerificationResult tampered = SecdsaOperations.VerifyFull(publicKey, MessageHash, noncePoint, Scalar(PinKey));

        Assert.AreEqual(VerificationStatus.Valid, valid.Status, valid.Message);
        Assert.AreEqual(VerificationStatus.Rejected, tampered.Status);
    }


    [TestMethod]
    public void DlEqualityProofOverTwoPairsRoundTripsAndRejectsAWrongChallengeOrProof()
    {
        (string generators, string publicKeys) = DlStatement();

        string proof = SecdsaOperations.DlEqualityProve(Scalar(DlWitness), generators, publicKeys, Challenge);
        VerificationResult valid = SecdsaOperations.DlEqualityVerify(generators, publicKeys, Challenge, proof);
        VerificationResult wrongChallenge = SecdsaOperations.DlEqualityVerify(generators, publicKeys, string.Empty, proof);
        VerificationResult tampered = SecdsaOperations.DlEqualityVerify(generators, publicKeys, Challenge, FlipLastDigit(proof));

        Assert.AreEqual(SignatureHexLength, proof.Length);
        Assert.AreEqual(VerificationStatus.Valid, valid.Status, valid.Message);
        Assert.AreEqual(VerificationStatus.Rejected, wrongChallenge.Status);
        Assert.AreNotEqual(VerificationStatus.Valid, tampered.Status);
    }


    [TestMethod]
    public void DlEqualityVerifyAnswersMalformedForAWrongLengthProofAndRejectsUnequalLogarithms()
    {
        (string generators, string publicKeys) = DlStatement();
        string mismatched = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(DlWitness + 1))
            + SecdsaOperations.DerivePublicKey(Scalar(DlWitness), Scalar(SecondBaseScalar));
        string proof = SecdsaOperations.DlEqualityProve(Scalar(DlWitness), generators, publicKeys, Challenge);

        Assert.AreEqual(VerificationStatus.Malformed, SecdsaOperations.DlEqualityVerify(generators, publicKeys, Challenge, "00").Status);
        Assert.AreNotEqual(VerificationStatus.Valid, SecdsaOperations.DlEqualityVerify(generators, mismatched, Challenge, proof).Status);
    }


    [TestMethod]
    public void BlindingRelationRoundTripsAndRejectsAProofForOtherPoints()
    {
        string g = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(1));
        string gDoublePrime = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(SecondBaseScalar));
        string yPrime = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(DlWitness));
        string yDoublePrime = SecdsaOperations.DerivePublicKey(Scalar(DlWitness), Scalar(SecondBaseScalar));

        string proof = SecdsaOperations.BlindingRelationProve(g, gDoublePrime, yPrime, yDoublePrime, Scalar(SecondBaseScalar));
        VerificationResult valid = SecdsaOperations.BlindingRelationVerify(g, gDoublePrime, yPrime, yDoublePrime, proof);
        VerificationResult swapped = SecdsaOperations.BlindingRelationVerify(g, gDoublePrime, yDoublePrime, yPrime, proof);

        Assert.AreEqual(VerificationStatus.Valid, valid.Status, valid.Message);
        Assert.AreNotEqual(VerificationStatus.Valid, swapped.Status);
    }


    [TestMethod]
    public void ControlRelationRoundTripsAndIsBoundToTheRecordContext()
    {
        string h = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(1));
        string w = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(SecondBaseScalar));
        string hPrime = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(DlWitness));
        string wPrime = SecdsaOperations.DerivePublicKey(Scalar(DlWitness), Scalar(SecondBaseScalar));

        string proof = SecdsaOperations.ControlRelationProve(h, w, hPrime, wPrime, Scalar(DlWitness), Challenge);
        VerificationResult valid = SecdsaOperations.ControlRelationVerify(h, w, hPrime, wPrime, Challenge, proof);
        VerificationResult otherContext = SecdsaOperations.ControlRelationVerify(h, w, hPrime, wPrime, Message, proof);

        Assert.AreEqual(VerificationStatus.Valid, valid.Status, valid.Message);
        Assert.AreEqual(VerificationStatus.Rejected, otherContext.Status);
    }


    [TestMethod]
    public void EcdhMacSignThenVerifyRoundTripsAndRejectsAChangedMessage()
    {
        string proverPublicKey = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(PinKey));
        string verifierPublicKey = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(VerifierEphemeralKey));

        string mac = SecdsaOperations.EcdhMacSign(Scalar(PinKey), verifierPublicKey, Salt, SharedInfo, Message);
        VerificationResult valid = SecdsaOperations.EcdhMacVerify(proverPublicKey, Scalar(VerifierEphemeralKey), Salt, SharedInfo, Message, mac);
        VerificationResult changed = SecdsaOperations.EcdhMacVerify(proverPublicKey, Scalar(VerifierEphemeralKey), Salt, SharedInfo, Challenge, mac);

        Assert.AreEqual(MacHexLength, mac.Length);
        Assert.AreEqual(VerificationStatus.Valid, valid.Status, valid.Message);
        Assert.AreEqual(VerificationStatus.Rejected, changed.Status);
    }


    [TestMethod]
    public void EcdhMacKeyDerivationAgreesFromBothSides()
    {
        string proverPublicKey = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(PinKey));
        string verifierPublicKey = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(VerifierEphemeralKey));

        string proverSide = SecdsaOperations.EcdhMacDeriveKey(Scalar(PinKey), verifierPublicKey, Salt, SharedInfo);
        string verifierSide = SecdsaOperations.EcdhMacDeriveKey(Scalar(VerifierEphemeralKey), proverPublicKey, Salt, SharedInfo);

        Assert.AreEqual(proverSide, verifierSide);
        Assert.AreEqual(MacHexLength, proverSide.Length);
    }


    [TestMethod]
    public void EcdhMacSplitSignAgreesWithSignUnderTheComposedKey()
    {
        string verifierPublicKey = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(VerifierEphemeralKey));

        string split = SecdsaOperations.EcdhMacSplitSign(Scalar(WalletShare), Scalar(WscaShare), Scalar(BaseKey), verifierPublicKey, Salt, SharedInfo, Message);
        string direct = SecdsaOperations.EcdhMacSign(Scalar(ComposedPrivateKey), verifierPublicKey, Salt, SharedInfo, Message);

        Assert.AreEqual(direct, split);
    }


    [TestMethod]
    public void EcdhMacVerifyAnswersMalformedForAnInvalidVerifierKey()
    {
        string proverPublicKey = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(PinKey));

        VerificationResult result = SecdsaOperations.EcdhMacVerify(proverPublicKey, "zz", Salt, SharedInfo, Message, new string('0', MacHexLength));

        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
    }


    private static (string Generators, string PublicKeys) DlStatement()
    {
        //D1 = d*G and D2 = d*(e*G), the pairs (G, D1) and (e*G, D2) sharing the logarithm d.
        string generators = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(1))
            + SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(SecondBaseScalar));
        string publicKeys = SecdsaOperations.DerivePublicKey(Scalar(1), Scalar(DlWitness))
            + SecdsaOperations.DerivePublicKey(Scalar(DlWitness), Scalar(SecondBaseScalar));

        return (generators, publicKeys);
    }


    private static string Scalar(ulong value) => value.ToString("x64", CultureInfo.InvariantCulture);


    private static string FlipLastDigit(string hex)
    {
        char last = hex[^1];

        return string.Concat(hex.AsSpan(0, hex.Length - 1), last == '0' ? "1" : "0");
    }
}
