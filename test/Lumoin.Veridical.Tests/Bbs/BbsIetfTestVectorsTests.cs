using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Bbs.IetfVectors;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Sha256;
using Lumoin.Veridical.Tests.Bbs.IetfVectors.Shake256;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Byte-equality tests against the IETF Appendix A test vectors
/// for both BBS+ ciphersuites (KeyGen + Sign + Verify +
/// GenerateProof + VerifyProof subsets).
/// </summary>
/// <remarks>
/// <para>
/// Load-bearing correctness gate: any divergence here means the
/// implementation differs from any other conformant implementation
/// of the spec.
/// </para>
/// <para>
/// Vectors live as typed C# constants under <c>IetfVectors/</c>.
/// SHA-256 ships 1 KeyGen + 10 signatures + 5 proofs; SHAKE-256
/// ships 1 KeyGen + 3 signatures + 3 proofs. Per-primitive
/// auxiliary coverage lives under <c>Primitives/</c>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class BbsIetfTestVectorsTests
{
    public static IEnumerable<object[]> Sha256KeyGenVectorsData =>
        Sha256KeyGenVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Shake256KeyGenVectorsData =>
        Shake256KeyGenVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Sha256SignatureVectorsData =>
        Sha256SignatureVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Shake256SignatureVectorsData =>
        Shake256SignatureVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Sha256ProofVectorsData =>
        Sha256ProofVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Shake256ProofVectorsData =>
        Shake256ProofVectors.All.Select(v => new object[] { v });


    [TestMethod]
    [DynamicData(nameof(Sha256KeyGenVectorsData))]
    public void KeyGenVector_Bls12Curve381Sha256(BbsKeyGenVector vector) =>
        RunKeyGenVector(
            vector,
            BbsCiphersuite.Bls12Curve381Sha256,
            TestSetup.Sha256.HashToScalar);


    [TestMethod]
    [DynamicData(nameof(Shake256KeyGenVectorsData))]
    public void KeyGenVector_Bls12Curve381Shake256(BbsKeyGenVector vector) =>
        RunKeyGenVector(
            vector,
            BbsCiphersuite.Bls12Curve381Shake256,
            TestSetup.Shake256.HashToScalar);


    [TestMethod]
    [DynamicData(nameof(Sha256SignatureVectorsData))]
    public void SignatureVector_Bls12Curve381Sha256(BbsSignatureVector vector) =>
        RunSignatureVector(
            vector,
            BbsCiphersuite.Bls12Curve381Sha256,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.Sha256.G1HashToCurve);


    [TestMethod]
    [DynamicData(nameof(Shake256SignatureVectorsData))]
    public void SignatureVector_Bls12Curve381Shake256(BbsSignatureVector vector) =>
        RunSignatureVector(
            vector,
            BbsCiphersuite.Bls12Curve381Shake256,
            TestSetup.Shake256.ExpandMessage,
            TestSetup.Shake256.HashToScalar,
            TestSetup.Shake256.G1HashToCurve);


    [TestMethod]
    [DynamicData(nameof(Sha256ProofVectorsData))]
    public void ProofVector_Bls12Curve381Sha256(BbsProofVector vector) =>
        RunProofVector(
            vector,
            BbsCiphersuite.Bls12Curve381Sha256,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.Sha256.G1HashToCurve);


    [TestMethod]
    [DynamicData(nameof(Shake256ProofVectorsData))]
    public void ProofVector_Bls12Curve381Shake256(BbsProofVector vector) =>
        RunProofVector(
            vector,
            BbsCiphersuite.Bls12Curve381Shake256,
            TestSetup.Shake256.ExpandMessage,
            TestSetup.Shake256.HashToScalar,
            TestSetup.Shake256.G1HashToCurve);


    private static void RunKeyGenVector(
        BbsKeyGenVector vector,
        BbsCiphersuite ciphersuite,
        ScalarHashToScalarDelegate hashToScalar)
    {
        byte[] keyMaterial = Convert.FromHexString(vector.KeyMaterial);
        byte[] keyInfo = vector.KeyInfo.Length == 0
            ? Array.Empty<byte>()
            : Convert.FromHexString(vector.KeyInfo);
        byte[] expectedSk = Convert.FromHexString(vector.ExpectedSecretKey);
        byte[] expectedPk = Convert.FromHexString(vector.ExpectedPublicKey);

        using BbsKeyPair pair = ciphersuite.Generate(
            keyMaterial,
            keyInfo,
            hashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);

        Assert.IsTrue(pair.SecretKey.AsReadOnlySpan().SequenceEqual(expectedSk),
            $"KeyGen SK mismatch ('{vector.Id}', §{vector.DraftSection}).\n  expected: {vector.ExpectedSecretKey}\n  got:      {Convert.ToHexStringLower(pair.SecretKey.AsReadOnlySpan())}");
        Assert.IsTrue(pair.PublicKey.AsReadOnlySpan().SequenceEqual(expectedPk),
            $"KeyGen PK mismatch ('{vector.Id}', §{vector.DraftSection}).\n  expected: {vector.ExpectedPublicKey}\n  got:      {Convert.ToHexStringLower(pair.PublicKey.AsReadOnlySpan())}");
    }


    private static void RunSignatureVector(
        BbsSignatureVector vector,
        BbsCiphersuite ciphersuite,
        ExpandMessageDelegate expandMessage,
        ScalarHashToScalarDelegate hashToScalar,
        G1HashToCurveDelegate g1HashToCurve)
    {
        byte[] skBytes = Convert.FromHexString(vector.SignerSecretKey);
        byte[] pkBytes = Convert.FromHexString(vector.SignerPublicKey);
        byte[] header = vector.Header.Length == 0
            ? Array.Empty<byte>()
            : Convert.FromHexString(vector.Header);
        BbsMessage[] messages = vector.Messages
            .Select(m => new BbsMessage(m.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(m)))
            .ToArray();
        byte[] expectedSignature = Convert.FromHexString(vector.Signature);

        using BbsSecretKey sk = BbsSecretKey.FromCanonical(skBytes, ciphersuite, TestSetup.Pool);
        using BbsPublicKey pk = BbsPublicKey.FromCanonical(pkBytes, ciphersuite, TestSetup.Pool);

        if(vector.ExpectedValid)
        {
            using BbsSignature actualSignature = sk.Sign(
                pk,
                new BbsHeader(header),
                messages,
                expandMessage,
                hashToScalar,
                TestSetup.ScalarAdd,
                TestSetup.ScalarInvert,
                TestSetup.G1Add,
                TestSetup.G1ScalarMultiply,
                TestSetup.G1MultiScalarMultiply,
                g1HashToCurve,
                TestSetup.Pool);

            Assert.IsTrue(actualSignature.AsReadOnlySpan().SequenceEqual(expectedSignature),
                $"Sign byte-equality failed for '{vector.Id}' (§{vector.DraftSection}).\n  expected: {vector.Signature}\n  got:      {Convert.ToHexStringLower(actualSignature.AsReadOnlySpan())}");
        }

        using BbsSignature signatureToVerify = BbsSignature.FromCanonical(expectedSignature, ciphersuite, TestSetup.Pool);
        bool verifyResult = pk.Verify(
            signatureToVerify,
            new BbsHeader(header),
            messages,
            expandMessage,
            hashToScalar,
            TestSetup.G1Add,
            TestSetup.G1MultiScalarMultiply,
            g1HashToCurve,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pairing,
            TestSetup.Pool);

        Assert.AreEqual(vector.ExpectedValid, verifyResult,
            $"Verify result mismatch for '{vector.Id}' (§{vector.DraftSection}). Expected {vector.ExpectedValid}, got {verifyResult}. Reason in vector: '{vector.InvalidReason ?? "(none)"}'.");
    }


    private static void RunProofVector(
        BbsProofVector vector,
        BbsCiphersuite ciphersuite,
        ExpandMessageDelegate expandMessage,
        ScalarHashToScalarDelegate hashToScalar,
        G1HashToCurveDelegate g1HashToCurve)
    {
        byte[] pkBytes = Convert.FromHexString(vector.SignerPublicKey);
        byte[] signatureBytes = Convert.FromHexString(vector.Signature);
        byte[] header = vector.Header.Length == 0
            ? Array.Empty<byte>()
            : Convert.FromHexString(vector.Header);
        byte[] presentationHeader = vector.PresentationHeader.Length == 0
            ? Array.Empty<byte>()
            : Convert.FromHexString(vector.PresentationHeader);
        BbsMessage[] messages = vector.Messages
            .Select(m => new BbsMessage(m.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(m)))
            .ToArray();
        int[] disclosedIndices = vector.DisclosedIndexes.ToArray();
        byte[] seed = Convert.FromHexString(vector.Seed);
        byte[] expectedProof = Convert.FromHexString(vector.Proof);

        using BbsPublicKey pk = BbsPublicKey.FromCanonical(pkBytes, ciphersuite, TestSetup.Pool);
        using BbsSignature signature = BbsSignature.FromCanonical(signatureBytes, ciphersuite, TestSetup.Pool);

        if(vector.ExpectedValid)
        {
            int undisclosedCount = messages.Length - disclosedIndices.Length;
            int randomScalarCount = 5 + undisclosedCount;
            ScalarRandomDelegate deterministicRng = BbsDeterministicScalars.FromSeed(
                seed,
                ciphersuite,
                randomScalarCount,
                expandMessage,
                TestSetup.ScalarReduce);

            using BbsProof actualProof = signature.GenerateProof(
                pk,
                new BbsHeader(header),
                new BbsPresentationHeader(presentationHeader),
                messages,
                disclosedIndices,
                expandMessage,
                hashToScalar,
                TestSetup.ScalarAdd,
                TestSetup.ScalarSubtract,
                TestSetup.ScalarMultiply,
                TestSetup.ScalarNegate,
                TestSetup.ScalarInvert,
                deterministicRng,
                TestSetup.G1Add,
                TestSetup.G1ScalarMultiply,
                TestSetup.G1MultiScalarMultiply,
                g1HashToCurve,
                TestSetup.Pool);

            Assert.IsTrue(actualProof.AsReadOnlySpan().SequenceEqual(expectedProof),
                $"GenerateProof byte-equality failed for '{vector.Id}' (§{vector.DraftSection}).\n  expected: {vector.Proof}\n  got:      {Convert.ToHexStringLower(actualProof.AsReadOnlySpan())}");
        }

        BbsMessage[] disclosedMessages = disclosedIndices.Select(i => messages[i]).ToArray();
        using BbsProof proofToVerify = BbsProof.FromCanonical(expectedProof, ciphersuite, TestSetup.Pool);
        bool verifyResult = pk.VerifyProof(
            proofToVerify,
            new BbsHeader(header),
            new BbsPresentationHeader(presentationHeader),
            disclosedMessages,
            disclosedIndices,
            expandMessage,
            hashToScalar,
            TestSetup.G1Add,
            TestSetup.G1MultiScalarMultiply,
            g1HashToCurve,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pairing,
            TestSetup.Pool);

        Assert.AreEqual(vector.ExpectedValid, verifyResult,
            $"VerifyProof result mismatch for '{vector.Id}' (§{vector.DraftSection}). Expected {vector.ExpectedValid}, got {verifyResult}. Reason in vector: '{vector.InvalidReason ?? "(none)"}'.");
    }
}