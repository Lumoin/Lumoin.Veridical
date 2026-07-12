using Lumoin.Veridical.Bbs;
using System;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Cross-ciphersuite invariants for BBS+. The two ciphersuites
/// (BLS12-381-SHA-256 and BLS12-381-SHAKE-256) MUST NOT be
/// interoperable: a key produced under one must not produce
/// matching keys under the other; a signature produced under one
/// must not verify under the other; same for proofs.
/// </summary>
[TestClass]
internal sealed class BbsCiphersuiteSeparationTests
{
    private static readonly byte[] KeyMaterial = MakeBytes(64, 0xA0);
    private static readonly byte[] KeyInfo = "ciphersuite-separation-key-info"u8.ToArray();
    private static readonly byte[] Header = "ciphersuite-separation-header"u8.ToArray();


    [TestMethod]
    public void SameKeyMaterialProducesDifferentKeysAcrossCiphersuites()
    {
        //KeyGen routes the same (keyMaterial, keyInfo) through the
        //ciphersuite-specific hash_to_scalar (different DST and
        //different expand_message variant) before computing PK = SK * BP2,
        //so SK and PK must both differ between ciphersuites.
        using BbsKeyPair sha = BbsCiphersuite.Bls12Curve381Sha256.Generate(
            KeyMaterial, KeyInfo,
            TestSetup.Sha256.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);
        using BbsKeyPair shake = BbsCiphersuite.Bls12Curve381Shake256.Generate(
            KeyMaterial, KeyInfo,
            TestSetup.Shake256.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);

        Assert.IsFalse(
            sha.SecretKey.AsReadOnlySpan().SequenceEqual(shake.SecretKey.AsReadOnlySpan()),
            "KeyGen under SHA-256 and SHAKE-256 must produce different secret keys for identical (keyMaterial, keyInfo).");
        Assert.IsFalse(
            sha.PublicKey.AsReadOnlySpan().SequenceEqual(shake.PublicKey.AsReadOnlySpan()),
            "KeyGen under SHA-256 and SHAKE-256 must produce different public keys for identical (keyMaterial, keyInfo).");
        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Sha256, sha.SecretKey.Ciphersuite);
        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Shake256, shake.SecretKey.Ciphersuite);
    }


    [TestMethod]
    public void SignatureFromOneCiphersuiteDoesNotVerifyUnderTheOther()
    {
        //A SHA-256 key signs a message; the verifier wires SHAKE-256
        //delegates against the same byte signature: must return false
        //because the verifier reconstructs different message scalars,
        //different domain, and different generators.
        BbsMessage[] messages = [new BbsMessage("cross-cs payload"u8.ToArray())];

        using BbsKeyPair shaPair = BbsCiphersuite.Bls12Curve381Sha256.Generate(
            KeyMaterial, KeyInfo,
            TestSetup.Sha256.HashToScalar, TestSetup.G2ScalarMultiply, TestSetup.Pool);

        using BbsSignature shaSignature = shaPair.SecretKey.Sign(
            shaPair.PublicKey,
            new BbsHeader(Header),
            messages,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.Pool);

        //Reinterpret the same signature bytes as a SHAKE-256 signature
        //and try to verify under a SHAKE-256 key.
        using BbsPublicKey shakePk = BbsPublicKey.FromCanonical(
            shaPair.PublicKey.AsReadOnlySpan(),
            BbsCiphersuite.Bls12Curve381Shake256,
            TestSetup.Pool);
        using BbsSignature shakeSignature = BbsSignature.FromCanonical(
            shaSignature.AsReadOnlySpan(),
            BbsCiphersuite.Bls12Curve381Shake256,
            TestSetup.Pool);

        bool shakeVerifyResult = shakePk.Verify(
            shakeSignature,
            new BbsHeader(Header),
            messages,
            TestSetup.Shake256.ExpandMessage,
            TestSetup.Shake256.HashToScalar,
            TestSetup.G1Add,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Shake256.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.G2IsOnCurve,
            TestSetup.G2IsInPrimeOrderSubgroup,
            TestSetup.Pairing,
            TestSetup.Pool);

        Assert.IsFalse(shakeVerifyResult,
            "A signature produced under SHA-256 must not verify under SHAKE-256.");
    }


    [TestMethod]
    public void CiphersuiteMismatchBetweenKeyAndSignatureReturnsFalse()
    {
        //The leaf types carry their ciphersuite as a Tag entry; Verify
        //fails fast (returns false) when publicKey.Ciphersuite differs
        //from signature.Ciphersuite. This test confirms the
        //fail-fast path triggers without proceeding into pairing math.
        BbsMessage[] messages = [new BbsMessage("mismatch payload"u8.ToArray())];

        using BbsKeyPair shaPair = BbsCiphersuite.Bls12Curve381Sha256.Generate(
            KeyMaterial, KeyInfo,
            TestSetup.Sha256.HashToScalar, TestSetup.G2ScalarMultiply, TestSetup.Pool);

        using BbsSignature shaSignature = shaPair.SecretKey.Sign(
            shaPair.PublicKey,
            new BbsHeader(Header),
            messages,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.Pool);

        //Same bytes, different ciphersuite tag on PK vs signature.
        using BbsPublicKey shakeTaggedPk = BbsPublicKey.FromCanonical(
            shaPair.PublicKey.AsReadOnlySpan(),
            BbsCiphersuite.Bls12Curve381Shake256,
            TestSetup.Pool);

        //Verify supplies SHA-256 delegates (matching the signature), but
        //the public key carries the SHAKE-256 ciphersuite tag. Verify
        //must reject on ciphersuite mismatch before reaching pairing.
        bool result = shakeTaggedPk.Verify(
            shaSignature,
            new BbsHeader(Header),
            messages,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.G1Add,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.G1IsOnCurve,
            TestSetup.G1IsInPrimeOrderSubgroup,
            TestSetup.G2Add,
            TestSetup.G2ScalarMultiply,
            TestSetup.G2IsOnCurve,
            TestSetup.G2IsInPrimeOrderSubgroup,
            TestSetup.Pairing,
            TestSetup.Pool);

        Assert.IsFalse(result,
            "Verify must reject when publicKey.Ciphersuite differs from signature.Ciphersuite.");
    }


    [TestMethod]
    public void SignThrowsOnCiphersuiteMismatchBetweenSecretAndPublicKey()
    {
        //Sign requires the secret key and public key to share a
        //ciphersuite; it throws ArgumentException rather than producing
        //a signature with an ambiguous ciphersuite tag.
        using BbsKeyPair shaPair = BbsCiphersuite.Bls12Curve381Sha256.Generate(
            KeyMaterial, KeyInfo,
            TestSetup.Sha256.HashToScalar, TestSetup.G2ScalarMultiply, TestSetup.Pool);

        //Reinterpret the SHA-256 PK bytes under the SHAKE-256 tag.
        using BbsPublicKey shakeTaggedPk = BbsPublicKey.FromCanonical(
            shaPair.PublicKey.AsReadOnlySpan(),
            BbsCiphersuite.Bls12Curve381Shake256,
            TestSetup.Pool);

        BbsMessage[] messages = [new BbsMessage("mismatch"u8.ToArray())];

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() => shaPair.SecretKey.Sign(
            shakeTaggedPk,
            new BbsHeader(Header),
            messages,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.Pool));

        Assert.AreEqual("publicKey", ex.ParamName);
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