using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates the P-256 ECDSA reference against the platform's P-256 ECDSA
/// (through the platform cryptography seam) as an
/// independent oracle, in both directions: a signature the platform produces must
/// verify here, and a signature produced here must verify on the platform. Round-trip
/// and rejection cases pin the in-range checks and the tamper response. This
/// is the cleartext spec the in-circuit proof is gated against.
/// </summary>
[TestClass]
internal sealed class P256EcdsaReferenceTests
{
    /// <summary>The byte width of one P-256 scalar or coordinate.</summary>
    private const int ScalarSize = 32;

    /// <summary>The byte width of a SEC1-compressed P-256 public key: a one-byte parity tag plus the x-coordinate.</summary>
    private const int CompressedSize = 33;

    /// <summary>The curve parameter set selecting the P-256 instantiation throughout this class.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.P256;

    /// <summary>A fixed valid nonce in [1, n−1] (well below n); ECDSA security forbids nonce reuse across distinct messages with the same key in production, but a fixed nonce is fine for gating the arithmetic against the oracle.</summary>
    private const string NonceHex = "1234567890abcdeffedcba9876543210112233445566778899aabbccddeeff00";

    /// <summary>The fixed message these gates sign and verify.</summary>
    private static ReadOnlySpan<byte> Message => "The age threshold predicate over an mdoc credential."u8;


    /// <summary>Verifies that a signature .NET produces over P-256 verifies in the reference, and that flipping one bit of r makes the reference reject it.</summary>
    [TestMethod]
    public void VerifiesADotNetProducedSignature()
    {
        PlatformP256Key key = TestPlatformCrypto.GenerateP256Key();

        Span<byte> signature = stackalloc byte[PlatformP256Key.SignatureSize];
        TestPlatformCrypto.SignP256(key, Message, signature);

        Span<byte> publicKey = stackalloc byte[CompressedSize];
        key.ExportCompressedPublicKey(publicKey);

        Span<byte> digest = stackalloc byte[ScalarSize];
        SHA256.HashData(Message, digest);

        bool valid = P256EcdsaReference.Verify(publicKey, digest, signature[..ScalarSize], signature[ScalarSize..]);
        Assert.IsTrue(valid, "A signature .NET produced over P-256 must verify in the reference.");

        //Flip one bit of r: the recovered R.x can no longer match.
        Span<byte> tampered = stackalloc byte[2 * ScalarSize];
        signature.CopyTo(tampered);
        tampered[0] ^= 0x01;
        bool tamperedValid = P256EcdsaReference.Verify(publicKey, digest, tampered[..ScalarSize], tampered[ScalarSize..]);
        Assert.IsFalse(tamperedValid, "A tampered signature must not verify.");
    }


    /// <summary>Verifies that a deterministic signature the reference produces over P-256 verifies in .NET.</summary>
    [TestMethod]
    public void ReferenceSignatureVerifiesInDotNet()
    {
        PlatformP256Key key = TestPlatformCrypto.GenerateP256Key();

        Span<byte> privateKey = stackalloc byte[ScalarSize];
        key.PrivateKey.CopyTo(privateKey);

        Span<byte> digest = stackalloc byte[ScalarSize];
        SHA256.HashData(Message, digest);

        Span<byte> nonce = stackalloc byte[ScalarSize];
        Convert.FromHexString(NonceHex).CopyTo(nonce);

        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s = stackalloc byte[ScalarSize];
        P256EcdsaReference.Sign(privateKey, digest, nonce, r, s);

        Span<byte> signature = stackalloc byte[2 * ScalarSize];
        r.CopyTo(signature[..ScalarSize]);
        s.CopyTo(signature[ScalarSize..]);

        bool valid = TestPlatformCrypto.VerifyP256(key.PublicX, key.PublicY, Message, signature);
        Assert.IsTrue(valid, "A signature the reference produced must verify in .NET.");
    }


    /// <summary>Verifies that the reference signs a message and then verifies its own signature over the same key and digest.</summary>
    [TestMethod]
    public void SignAndVerifyRoundTrip()
    {
        PlatformP256Key key = TestPlatformCrypto.GenerateP256Key();

        Span<byte> privateKey = stackalloc byte[ScalarSize];
        key.PrivateKey.CopyTo(privateKey);
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        key.ExportCompressedPublicKey(publicKey);

        Span<byte> digest = stackalloc byte[ScalarSize];
        SHA256.HashData(Message, digest);
        Span<byte> nonce = stackalloc byte[ScalarSize];
        Convert.FromHexString(NonceHex).CopyTo(nonce);

        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s = stackalloc byte[ScalarSize];
        P256EcdsaReference.Sign(privateKey, digest, nonce, r, s);

        Assert.IsTrue(P256EcdsaReference.Verify(publicKey, digest, r, s), "The reference must verify its own signature.");
    }


    /// <summary>Verifies that the reference rejects signature components outside [1, n-1]: r = 0, s = 0, and r = n (the curve order).</summary>
    [TestMethod]
    public void RejectsOutOfRangeComponents()
    {
        PlatformP256Key key = TestPlatformCrypto.GenerateP256Key();
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        key.ExportCompressedPublicKey(publicKey);
        Span<byte> digest = stackalloc byte[ScalarSize];
        SHA256.HashData(Message, digest);

        Span<byte> zero = stackalloc byte[ScalarSize];
        Span<byte> one = stackalloc byte[ScalarSize];
        one[^1] = 1;

        Assert.IsFalse(P256EcdsaReference.Verify(publicKey, digest, zero, one), "r = 0 must reject.");
        Assert.IsFalse(P256EcdsaReference.Verify(publicKey, digest, one, zero), "s = 0 must reject.");

        //r = n (the order) is out of [1, n−1] and must reject.
        Span<byte> order = stackalloc byte[ScalarSize];
        WellKnownCurves.GetScalarFieldOrder(Curve).TryWriteBytes(order, out _, isUnsigned: true, isBigEndian: true);
        Assert.IsFalse(P256EcdsaReference.Verify(publicKey, digest, order, one), "r = n must reject.");
    }
}
