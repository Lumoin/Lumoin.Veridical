using Lumoin.Veridical.Bbs;
using System;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Negative Verify tests: tampered messages, wrong public key,
/// bit-flipped signature components — Verify must return false (not
/// throw).
/// </summary>
[TestClass]
internal sealed class BbsFailureTests
{
    private static readonly byte[] Header = "test-header"u8.ToArray();
    private static readonly BbsMessage[] Messages = [new BbsMessage("first"u8.ToArray()), new BbsMessage("second"u8.ToArray())];


    [TestMethod]
    public void VerifyWithWrongPublicKeyReturnsFalse()
    {
        using BbsKeyPair pair1 = MakeKeyPair(0x10);
        using BbsKeyPair pair2 = MakeKeyPair(0x20);
        using BbsSignature signature = SignWith(pair1);

        bool result = pair2.PublicKey.Verify(
            signature,
            new BbsHeader(Header),
            Messages,
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

        Assert.IsFalse(result, "Verify under a different public key must return false.");
    }


    [TestMethod]
    public void VerifyWithTamperedMessageReturnsFalse()
    {
        using BbsKeyPair pair = MakeKeyPair(0x10);
        using BbsSignature signature = SignWith(pair);

        //Flip one byte in the second message.
        byte[] tamperedSecondBytes = "second"u8.ToArray();
        tamperedSecondBytes[0] ^= 0x01;
        BbsMessage[] tamperedMessages = [Messages[0], new BbsMessage(tamperedSecondBytes)];

        bool result = pair.PublicKey.Verify(
            signature,
            new BbsHeader(Header),
            tamperedMessages,
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

        Assert.IsFalse(result, "Verify with tampered message must return false.");
    }


    [TestMethod]
    public void VerifyWithBitFlippedAReturnsFalse()
    {
        using BbsKeyPair pair = MakeKeyPair(0x10);
        using BbsSignature signature = SignWith(pair);

        //Flip a low-order bit of the A component (byte 47, low bit) to
        //produce an alternate on-curve point with overwhelming
        //probability — or an off-curve / wrong-subgroup point, which
        //the decoder catches and Verify reports as false.
        byte[] tampered = signature.AsReadOnlySpan().ToArray();
        tampered[BbsSignature.AOffset + BbsSignature.ASizeBytes - 1] ^= 0x01;
        using BbsSignature tamperedSig = BbsSignature.FromCanonical(tampered, BbsCiphersuite.Bls12Curve381Sha256, TestSetup.Pool);

        bool result = pair.PublicKey.Verify(
            tamperedSig,
            new BbsHeader(Header),
            Messages,
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

        Assert.IsFalse(result, "Verify with bit-flipped A component must return false (decode failure or pairing mismatch).");
    }


    [TestMethod]
    public void VerifyWithBitFlippedEReturnsFalse()
    {
        using BbsKeyPair pair = MakeKeyPair(0x10);
        using BbsSignature signature = SignWith(pair);

        //Flip a low-order bit of the e component.
        byte[] tampered = signature.AsReadOnlySpan().ToArray();
        tampered[BbsSignature.EOffset + BbsSignature.ESizeBytes - 1] ^= 0x01;
        using BbsSignature tamperedSig = BbsSignature.FromCanonical(tampered, BbsCiphersuite.Bls12Curve381Sha256, TestSetup.Pool);

        bool result = pair.PublicKey.Verify(
            tamperedSig,
            new BbsHeader(Header),
            Messages,
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

        Assert.IsFalse(result, "Verify with bit-flipped e component must return false.");
    }


    private static BbsKeyPair MakeKeyPair(byte seedStart)
    {
        byte[] keyMaterial = new byte[64];
        for(int i = 0; i < keyMaterial.Length; i++)
        {
            keyMaterial[i] = (byte)(seedStart + i);
        }

        return BbsCiphersuite.Bls12Curve381Sha256.Generate(
            keyMaterial,
            "test-key-info"u8.ToArray(),
            TestSetup.Sha256.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);
    }


    private static BbsSignature SignWith(BbsKeyPair pair)
    {
        return pair.SecretKey.Sign(
            pair.PublicKey,
            new BbsHeader(Header),
            Messages,
            TestSetup.Sha256.ExpandMessage,
            TestSetup.Sha256.HashToScalar,
            TestSetup.ScalarAdd,
            TestSetup.ScalarInvert,
            TestSetup.G1Add,
            TestSetup.G1ScalarMultiply,
            TestSetup.G1MultiScalarMultiply,
            TestSetup.Sha256.G1HashToCurve,
            TestSetup.Pool);
    }
}