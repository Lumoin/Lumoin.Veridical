using CsCheck;
using Lumoin.Veridical.Bbs;
using System;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Property tests for BBS+ KeyGen.
/// </summary>
[TestClass]
internal sealed class BbsKeyGenerationTests
{
    [TestMethod]
    public void GenerateProducesPublicKeyWithMatchingCiphersuite()
    {
        byte[] keyMaterial = new byte[64];
        for(int i = 0; i < keyMaterial.Length; i++)
        {
            keyMaterial[i] = (byte)(0x10 + i);
        }
        byte[] keyInfo = "test-key-info"u8.ToArray();

        using BbsKeyPair pair = BbsCiphersuite.Bls12Curve381Sha256.Generate(
            keyMaterial,
            keyInfo,
            TestSetup.Sha256.HashToScalar,
            TestSetup.G2ScalarMultiply,
            TestSetup.Pool);

        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Sha256, pair.SecretKey.Ciphersuite);
        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Sha256, pair.PublicKey.Ciphersuite);
    }


    [TestMethod]
    public void GenerateIsDeterministicGivenInputs()
    {
        Gen.Byte.Array[64]
            .Sample(keyMaterial =>
            {
                using BbsKeyPair a = BbsCiphersuite.Bls12Curve381Sha256.Generate(
                    keyMaterial,
                    ReadOnlySpan<byte>.Empty,
                    TestSetup.Sha256.HashToScalar,
                    TestSetup.G2ScalarMultiply,
                    TestSetup.Pool);
                using BbsKeyPair b = BbsCiphersuite.Bls12Curve381Sha256.Generate(
                    keyMaterial,
                    ReadOnlySpan<byte>.Empty,
                    TestSetup.Sha256.HashToScalar,
                    TestSetup.G2ScalarMultiply,
                    TestSetup.Pool);
                return a.SecretKey.AsReadOnlySpan().SequenceEqual(b.SecretKey.AsReadOnlySpan())
                    && a.PublicKey.AsReadOnlySpan().SequenceEqual(b.PublicKey.AsReadOnlySpan());
            }, iter: 10);
    }
}