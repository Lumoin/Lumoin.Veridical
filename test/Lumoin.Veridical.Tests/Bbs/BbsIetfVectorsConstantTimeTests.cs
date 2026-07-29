using Lumoin.Veridical.Backends.Managed;
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
/// Byte-equality tests that drive the IETF Appendix A vectors through the
/// <em>constant-time</em> ladders at the two long-term-secret seams: key generation
/// (<c>PK = SK·BP2</c> through <see cref="Bls12Curve381ConstantTimeG2Backend"/>) and
/// signing (<c>A = B·(1/(SK+e))</c> through
/// <see cref="Bls12Curve381ConstantTimeG1Backend"/>). The main
/// <see cref="BbsIetfTestVectorsTests"/> sweep runs the reference wiring; this suite
/// pins that swapping in the constant-time ladders reproduces the published bytes
/// exactly, which is the drop-in-replacement contract the production composition
/// roots rely on.
/// </summary>
[TestClass]
internal sealed class BbsIetfVectorsConstantTimeTests
{
    private static G1ScalarMultiplyDelegate ConstantTimeG1ScalarMultiply { get; } = Bls12Curve381ConstantTimeG1Backend.GetScalarMultiply();
    private static G2ScalarMultiplyDelegate ConstantTimeG2ScalarMultiply { get; } = Bls12Curve381ConstantTimeG2Backend.GetScalarMultiply();

    public static IEnumerable<object[]> Sha256KeyGenVectorsData =>
        Sha256KeyGenVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Shake256KeyGenVectorsData =>
        Shake256KeyGenVectors.All.Select(v => new object[] { v });

    public static IEnumerable<object[]> Sha256SignatureVectorsData =>
        Sha256SignatureVectors.All.Where(v => v.ExpectedValid).Select(v => new object[] { v });

    public static IEnumerable<object[]> Shake256SignatureVectorsData =>
        Shake256SignatureVectors.All.Where(v => v.ExpectedValid).Select(v => new object[] { v });


    [TestMethod]
    [DynamicData(nameof(Sha256KeyGenVectorsData))]
    public void KeyGenVectorThroughConstantTimeG2LadderSha256(BbsKeyGenVector vector) =>
        RunKeyGenVector(vector, BbsCiphersuite.Bls12Curve381Sha256, TestSetup.Sha256.HashToScalar);


    [TestMethod]
    [DynamicData(nameof(Shake256KeyGenVectorsData))]
    public void KeyGenVectorThroughConstantTimeG2LadderShake256(BbsKeyGenVector vector) =>
        RunKeyGenVector(vector, BbsCiphersuite.Bls12Curve381Shake256, TestSetup.Shake256.HashToScalar);


    [TestMethod]
    [DynamicData(nameof(Sha256SignatureVectorsData))]
    public void SignatureVectorThroughConstantTimeG1LadderSha256(BbsSignatureVector vector) =>
        RunSignatureVector(
            vector,
            BbsCiphersuite.Bls12Curve381Sha256,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.Sha256.G1HashToCurve);


    [TestMethod]
    [DynamicData(nameof(Shake256SignatureVectorsData))]
    public void SignatureVectorThroughConstantTimeG1LadderShake256(BbsSignatureVector vector) =>
        RunSignatureVector(
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
            ConstantTimeG2ScalarMultiply,
            TestSetup.Pool);

        Assert.IsTrue(pair.SecretKey.AsReadOnlySpan().SequenceEqual(expectedSk),
            $"KeyGen SK mismatch through the constant-time G2 ladder ('{vector.Id}', §{vector.DraftSection}).");
        Assert.IsTrue(pair.PublicKey.AsReadOnlySpan().SequenceEqual(expectedPk),
            $"KeyGen PK mismatch through the constant-time G2 ladder ('{vector.Id}', §{vector.DraftSection}).\n  expected: {vector.ExpectedPublicKey}\n  got:      {Convert.ToHexStringLower(pair.PublicKey.AsReadOnlySpan())}");
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

        using BbsSignature actualSignature = sk.Sign(
            pk,
            new BbsHeader(header),
            messages,
            expandMessage,
            hashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            ConstantTimeG1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            g1HashToCurve,
            TestSetup.Pool);

        Assert.IsTrue(actualSignature.AsReadOnlySpan().SequenceEqual(expectedSignature),
            $"Sign byte-equality through the constant-time G1 ladder failed for '{vector.Id}' (§{vector.DraftSection}).\n  expected: {vector.Signature}\n  got:      {Convert.ToHexStringLower(actualSignature.AsReadOnlySpan())}");
    }
}
