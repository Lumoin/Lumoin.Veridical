using CsCheck;
using Lumoin.Veridical.Bbs;
using System;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Sign + Verify roundtrip property tests.
/// </summary>
[TestClass]
internal sealed class BbsSignatureTests
{
    private static readonly byte[] KeyMaterial = MakeBytes(64, 0x10);
    private static readonly byte[] KeyInfo = "test-key-info"u8.ToArray();
    private static readonly byte[] Header = "test-header-bytes"u8.ToArray();


    [TestMethod]
    public void SignVerifyRoundtripSingleMessage()
    {
        Gen.Byte.Array[1, 64]
            .Sample(messageBytes =>
            {
                using BbsKeyPair pair = MakeKeyPair();
                BbsMessage[] messages = [new BbsMessage(messageBytes)];
                using BbsSignature signature = pair.SecretKey.Sign(
                    pair.PublicKey,
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
                return pair.PublicKey.Verify(
                    signature,
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
            }, iter: 2);
    }


    [TestMethod]
    [DataRow(2)]
    [DataRow(5)]
    public void SignVerifyRoundtripMultipleMessages(int messageCount)
    {
        using BbsKeyPair pair = MakeKeyPair();
        BbsMessage[] messages = new BbsMessage[messageCount];
        for(int i = 0; i < messageCount; i++)
        {
            messages[i] = new BbsMessage(MakeBytes(16 + i, (byte)(0x20 + i)));
        }

        using BbsSignature signature = pair.SecretKey.Sign(
            pair.PublicKey,
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

        bool ok = pair.PublicKey.Verify(
            signature,
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
        Assert.IsTrue(ok, $"Sign+Verify roundtrip with {messageCount} messages must succeed.");
    }


    [TestMethod]
    public void SignProducesDeterministicSignature()
    {
        //BBS+ Sign is deterministic per Section 3.6.1: the same
        //(SK, header, messages) always produces the same (A, e). This
        //property is load-bearing for IETF Appendix A byte-equality.
        using BbsKeyPair pair = MakeKeyPair();
        BbsMessage[] messages = [new BbsMessage("message-bytes"u8.ToArray())];

        using BbsSignature first = pair.SecretKey.Sign(
            pair.PublicKey,
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
        using BbsSignature second = pair.SecretKey.Sign(
            pair.PublicKey,
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

        Assert.IsTrue(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "BBS+ Sign must be deterministic: two signs with identical inputs must produce identical bytes.");
    }


    internal static BbsKeyPair MakeKeyPair()
    {
        return BbsCiphersuite.Bls12Curve381Sha256.Generate(
            KeyMaterial,
            KeyInfo,
            TestSetup.Sha256.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);
    }


    internal static byte[] MakeBytes(int length, byte start)
    {
        byte[] result = new byte[length];
        for(int i = 0; i < length; i++)
        {
            result[i] = (byte)(start + i);
        }

        return result;
    }
}