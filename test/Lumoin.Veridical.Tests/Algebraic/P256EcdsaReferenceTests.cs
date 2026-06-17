using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates the P-256 ECDSA reference against .NET's built-in P-256
/// (<see cref="ECDsa"/> over <see cref="ECCurve.NamedCurves.nistP256"/>) as an
/// independent oracle, in both directions: a signature .NET produces must
/// verify here, and a signature produced here must verify in .NET. Round-trip
/// and rejection cases pin the in-range checks and the tamper response. This
/// is the cleartext spec the in-circuit proof (LF.5) is gated against.
/// </summary>
[TestClass]
internal sealed class P256EcdsaReferenceTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;
    private static readonly CurveParameterSet Curve = CurveParameterSet.P256;

    //A fixed valid nonce in [1, n−1] (well below n); ECDSA security forbids
    //nonce reuse across distinct messages with the same key in production, but
    //a fixed nonce is fine for gating the arithmetic against the oracle.
    private const string NonceHex = "1234567890abcdeffedcba9876543210112233445566778899aabbccddeeff00";

    private static ReadOnlySpan<byte> Message => "The age threshold predicate over an mdoc credential."u8;


    [TestMethod]
    public void VerifiesADotNetProducedSignature()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        Span<byte> signature = stackalloc byte[2 * ScalarSize];
        int written = ecdsa.SignData(Message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.AreEqual(signature.Length, written, "P-256 IEEE-P1363 signatures are r‖s, 64 bytes.");

        Span<byte> publicKey = stackalloc byte[CompressedSize];
        ExportPublicKeyCompressed(ecdsa, publicKey);

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


    [TestMethod]
    public void ReferenceSignatureVerifiesInDotNet()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        Span<byte> privateKey = stackalloc byte[ScalarSize];
        LeftPad(parameters.D, privateKey);

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

        bool valid = ecdsa.VerifyData(Message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.IsTrue(valid, "A signature the reference produced must verify in .NET.");
    }


    [TestMethod]
    public void SignAndVerifyRoundTrip()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        Span<byte> privateKey = stackalloc byte[ScalarSize];
        LeftPad(parameters.D, privateKey);
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        ExportPublicKeyCompressed(ecdsa, publicKey);

        Span<byte> digest = stackalloc byte[ScalarSize];
        SHA256.HashData(Message, digest);
        Span<byte> nonce = stackalloc byte[ScalarSize];
        Convert.FromHexString(NonceHex).CopyTo(nonce);

        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s = stackalloc byte[ScalarSize];
        P256EcdsaReference.Sign(privateKey, digest, nonce, r, s);

        Assert.IsTrue(P256EcdsaReference.Verify(publicKey, digest, r, s), "The reference must verify its own signature.");
    }


    [TestMethod]
    public void RejectsOutOfRangeComponents()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        ExportPublicKeyCompressed(ecdsa, publicKey);
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


    private static void ExportPublicKeyCompressed(ECDsa ecdsa, Span<byte> destination)
    {
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        Span<byte> x = stackalloc byte[ScalarSize];
        Span<byte> y = stackalloc byte[ScalarSize];
        LeftPad(parameters.Q.X, x);
        LeftPad(parameters.Q.Y, y);

        //SEC1 compressed: 0x02 if y is even, 0x03 if odd, then x big-endian.
        destination[0] = (byte)(0x02 | (y[^1] & 0x01));
        x.CopyTo(destination[1..]);
    }


    private static void LeftPad(byte[]? source, Span<byte> destination)
    {
        destination.Clear();
        ArgumentNullException.ThrowIfNull(source);
        source.CopyTo(destination[(destination.Length - source.Length)..]);
    }
}
