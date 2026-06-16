using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Cryptography;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for <see cref="SecdsaAlgorithm"/>, Verheul's Split-ECDSA Algorithm 2 over NIST P-256. The split
/// signature must be an ORDINARY ECDSA signature under the composite key <c>Y = (P·u)·G</c>, so it is gated
/// against two independent verifiers — the platform <see cref="ECDsa"/> and the in-repo
/// <see cref="P256EcdsaReference"/> — and, with a matched explicit nonce, pinned byte-for-byte to a direct
/// ECDSA sign under <c>d = P·u</c>. The mod-<c>n</c> scalar and group arithmetic is wired from the BigInteger
/// references (the open production-backend decision is resolved as reuse-by-injection); a production constant-
/// time mod-<c>n</c> backend would re-run these same gates unchanged.
/// </summary>
[TestClass]
internal sealed class SecdsaSplitSignTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;

    private static ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerScalarReference.GetMultiply();
    private static ScalarAddDelegate ScalarAdd { get; } = P256BigIntegerScalarReference.GetAdd();
    private static ScalarInvertDelegate ScalarInvert { get; } = P256BigIntegerScalarReference.GetInvert();
    private static ScalarReduceDelegate ScalarReduce { get; } = P256BigIntegerScalarReference.GetReduce();
    private static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();
    private static G1AddDelegate G1Add { get; } = P256BigIntegerG1Reference.GetAdd();

    private static SecdsaNonceSource Rfc6979NonceSource { get; } = Rfc6979SecdsaNonceSource.Create(Sha256Hmac.Compute);

    private static BigInteger Order { get; } = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);


    [TestMethod]
    public void SplitSignatureIsAcceptedByDotNetEcdsa()
    {
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("the split signature verifies under the standard ECDSA verifier");

        (byte[] r, byte[] s) = SplitSign(pinKey, hardwareKey, messageHash);
        byte[] publicKey = DerivePublicKey(pinKey, hardwareKey);

        Assert.IsTrue(VerifyWithDotNet(publicKey, messageHash, r, s), "The platform ECDSA verifier must accept the split signature under Y = (P*u)*G.");
    }


    [TestMethod]
    public void SplitSignatureIsAcceptedByReferenceEcdsa()
    {
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("the split signature verifies under the reference ECDSA verifier");

        (byte[] r, byte[] s) = SplitSign(pinKey, hardwareKey, messageHash);
        byte[] publicKey = DerivePublicKey(pinKey, hardwareKey);

        Assert.IsTrue(P256EcdsaReference.Verify(publicKey, messageHash, r, s), "The reference ECDSA verifier must accept the split signature under Y = (P*u)*G.");
    }


    [TestMethod]
    public void SplitSignatureIsAcceptedBySecdsaVerify()
    {
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("the split signature verifies under SECDSA's own verifier");

        (byte[] r, byte[] s) = SplitSign(pinKey, hardwareKey, messageHash);
        byte[] publicKey = DerivePublicKey(pinKey, hardwareKey);

        Assert.IsTrue(
            SecdsaAlgorithm.Verify(publicKey, messageHash, r, s, ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add),
            "SECDSA.Verify must accept its own split signature under Y = (P*u)*G.");
    }


    [TestMethod]
    public void SplitSignWithMatchedNonceIsByteIdenticalToDirectSignUnderCompositeKey()
    {
        //The algebraic core: s = P*k^-1(P^-1*e + r*u) = k^-1(e + r*(P*u)). With the SAME explicit k, the split
        //signature equals a direct ECDSA sign under d = P*u byte-for-byte (r matches because both derive it
        //from k*G; s matches by the identity).
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("matched-nonce equivalence to a direct composite-key signature");
        byte[] fixedNonce = DeriveScalar("secdsa-fixed-nonce");

        SecdsaNonceSource fixedNonceSource = (_, _, _, nonce) => fixedNonce.CopyTo(nonce);

        Span<byte> splitR = stackalloc byte[ScalarSize];
        Span<byte> splitS = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(
            pinKey, hardwareKey, messageHash, fixedNonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply,
            splitR, splitS);

        //Direct ECDSA sign under d = P*u with the same k, via the independent reference.
        Span<byte> compositeKey = stackalloc byte[ScalarSize];
        ScalarMultiply(pinKey, hardwareKey, compositeKey, CurveParameterSet.P256);
        Span<byte> directR = stackalloc byte[ScalarSize];
        Span<byte> directS = stackalloc byte[ScalarSize];
        P256EcdsaReference.Sign(compositeKey, messageHash, fixedNonce, directR, directS);

        Assert.IsTrue(splitR.SequenceEqual(directR), "The split-sign r must byte-match a direct sign under d = P*u with the same nonce.");
        Assert.IsTrue(splitS.SequenceEqual(directS), "The split-sign s must byte-match a direct sign under d = P*u with the same nonce.");
    }


    [TestMethod]
    public void DerivedPublicKeyEqualsPinScalarTimesHardwarePublicKey()
    {
        //Y = (P*u)*G must equal P*(u*G): the split public key is the PIN-scalar multiple of the hardware
        //public key U = u*G, computed here in a different operation order than DeriveSplitPublicKey uses.
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");

        byte[] derived = DerivePublicKey(pinKey, hardwareKey);

        Span<byte> generator = stackalloc byte[CompressedSize];
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.P256).CopyTo(generator);
        Span<byte> hardwarePublicKey = stackalloc byte[CompressedSize];
        G1ScalarMultiply(generator, hardwareKey, hardwarePublicKey, CurveParameterSet.P256);
        Span<byte> composedPublicKey = stackalloc byte[CompressedSize];
        G1ScalarMultiply(hardwarePublicKey, pinKey, composedPublicKey, CurveParameterSet.P256);

        Assert.IsTrue(derived.AsSpan().SequenceEqual(composedPublicKey), "DeriveSplitPublicKey must equal P*(u*G).");
    }


    [TestMethod]
    public void ProductionRfc6979NonceSourceIsDeterministicAndVerifies()
    {
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("RFC 6979 makes split signing deterministic");

        (byte[] firstR, byte[] firstS) = SplitSign(pinKey, hardwareKey, messageHash);
        (byte[] secondR, byte[] secondS) = SplitSign(pinKey, hardwareKey, messageHash);

        Assert.IsTrue(firstR.AsSpan().SequenceEqual(secondR), "RFC 6979 split signing must be deterministic in r.");
        Assert.IsTrue(firstS.AsSpan().SequenceEqual(secondS), "RFC 6979 split signing must be deterministic in s.");

        byte[] publicKey = DerivePublicKey(pinKey, hardwareKey);
        Assert.IsTrue(VerifyWithDotNet(publicKey, messageHash, firstR, firstS), "The deterministic split signature must verify under the platform ECDSA verifier.");
    }


    [TestMethod]
    public void SplitSignNonceDiffersFromADirectRfc6979SignUnderCompositeKey()
    {
        //SECDSA derives k via RFC 6979 over (u, e'); a direct signer under d = P*u derives k over (d, e). The
        //two nonces — and therefore the two (still both valid) signatures — differ. This documents that the
        //byte-identity gate above holds only for a MATCHED explicit nonce, not for the production RFC 6979 path.
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("split-sign and direct-sign pick different RFC 6979 nonces");

        (byte[] splitR, byte[] splitS) = SplitSign(pinKey, hardwareKey, messageHash);

        //Direct RFC 6979 sign under d = P*u over the unblinded e.
        Span<byte> compositeKey = stackalloc byte[ScalarSize];
        ScalarMultiply(pinKey, hardwareKey, compositeKey, CurveParameterSet.P256);
        Span<byte> directNonce = stackalloc byte[ScalarSize];
        Rfc6979DeterministicNonce.GenerateNonce(CurveParameterSet.P256, compositeKey, messageHash, Sha256Hmac.Compute, directNonce);
        Span<byte> directR = stackalloc byte[ScalarSize];
        Span<byte> directS = stackalloc byte[ScalarSize];
        P256EcdsaReference.Sign(compositeKey, messageHash, directNonce, directR, directS);

        bool identical = splitR.AsSpan().SequenceEqual(directR) && splitS.AsSpan().SequenceEqual(directS);
        Assert.IsFalse(identical, "Production split-sign (RFC 6979 over (u, e')) must differ from a direct RFC 6979 sign under d = P*u (different nonce).");

        //Both are nonetheless valid signatures under the same key.
        byte[] publicKey = DerivePublicKey(pinKey, hardwareKey);
        byte[] directRArray = directR.ToArray();
        byte[] directSArray = directS.ToArray();
        Assert.IsTrue(VerifyWithDotNet(publicKey, messageHash, splitR, splitS), "The split signature must verify.");
        Assert.IsTrue(VerifyWithDotNet(publicKey, messageHash, directRArray, directSArray), "The direct signature must verify.");
    }


    [TestMethod]
    public void TamperedSignatureIsRejectedByAllVerifiers()
    {
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("a flipped signature bit must be rejected");

        (byte[] r, byte[] s) = SplitSign(pinKey, hardwareKey, messageHash);
        byte[] publicKey = DerivePublicKey(pinKey, hardwareKey);

        //Flip the lowest bit of s.
        s[^1] ^= 0x01;

        Assert.IsFalse(VerifyWithDotNet(publicKey, messageHash, r, s), "The platform verifier must reject a tampered signature.");
        Assert.IsFalse(P256EcdsaReference.Verify(publicKey, messageHash, r, s), "The reference verifier must reject a tampered signature.");
        Assert.IsFalse(
            SecdsaAlgorithm.Verify(publicKey, messageHash, r, s, ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add),
            "SECDSA.Verify must reject a tampered signature.");
    }


    [TestMethod]
    public void VerifyRejectsOutOfRangeComponentsWithoutThrowing()
    {
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("out-of-range r or s is rejected, not thrown");
        byte[] publicKey = DerivePublicKey(pinKey, hardwareKey);

        byte[] zero = new byte[ScalarSize];
        byte[] orderBytes = OrderBytes();
        (byte[] r, byte[] s) = SplitSign(pinKey, hardwareKey, messageHash);

        Assert.IsFalse(Verify(publicKey, messageHash, zero, s), "r = 0 must be rejected.");
        Assert.IsFalse(Verify(publicKey, messageHash, r, zero), "s = 0 must be rejected.");
        Assert.IsFalse(Verify(publicKey, messageHash, orderBytes, s), "r = n must be rejected.");
        Assert.IsFalse(Verify(publicKey, messageHash, r, orderBytes), "s = n must be rejected.");
    }


    [TestMethod]
    public void SplitSignRejectsZeroOrOutOfRangeKeys()
    {
        byte[] valid = DeriveScalar("secdsa-pin-key");
        byte[] messageHash = MessageHash("zero or out-of-range keys are rejected");
        byte[] zero = new byte[ScalarSize];
        byte[] orderBytes = OrderBytes();

        Assert.ThrowsExactly<ArgumentException>(() => SplitSignThrowing(zero, valid, messageHash), "P = 0 must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(() => SplitSignThrowing(valid, zero, messageHash), "u = 0 must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(() => SplitSignThrowing(orderBytes, valid, messageHash), "P = n must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(() => SplitSignThrowing(valid, orderBytes, messageHash), "u = n must be rejected.");
    }


    [TestMethod]
    public void PooledSplitSignatureIsClearedOnDispose()
    {
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("a pooled signature buffer is zeroed on return");

        using var pool = new BaseMemoryPool();

        byte[] signatureBytes;
        using(SecdsaSignature signature = SecdsaAlgorithm.SplitSign(
            pinKey, hardwareKey, messageHash, Rfc6979NonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply, pool))
        {
            signatureBytes = signature.AsReadOnlySpan().ToArray();
            Assert.IsTrue(signatureBytes.AsSpan(0, ScalarSize).SequenceEqual(SplitSign(pinKey, hardwareKey, messageHash).Item1), "The pooled signature r must match the span overload.");
        }

        //After disposal the slot is returned cleared; the next same-size rent must observe zeroed bytes.
        using System.Buffers.IMemoryOwner<byte> rerented = pool.Rent(SecdsaSignature.SizeBytes);
        int firstNonZero = rerented.Memory.Span[..SecdsaSignature.SizeBytes].IndexOfAnyExcept((byte)0);
        Assert.AreEqual(-1, firstNonZero, "The returned signature buffer must be cleared.");
    }


    [TestMethod]
    public void SplitSignViaSoftwareRawSignerSeamEqualsTheInlinePath()
    {
        //The raw-sign delegate seam (the TPM-pluggable split) must produce exactly the same signature as the
        //inline (P, u, nonceSource) path when driven by the software raw signer — they are the same raw sign.
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("the software raw-sign seam matches the inline split sign");

        (byte[] inlineR, byte[] inlineS) = SplitSign(pinKey, hardwareKey, messageHash);

        SecdsaRawEcdsaSign rawSign = SecdsaSoftwareRawSigner.Create(
            hardwareKey, Rfc6979NonceSource, ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply);
        byte[] seamR = new byte[ScalarSize];
        byte[] seamS = new byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(pinKey, messageHash, rawSign, ScalarMultiply, ScalarInvert, ScalarReduce, seamR, seamS);

        Assert.IsTrue(inlineR.AsSpan().SequenceEqual(seamR), "Seam r must equal the inline path r.");
        Assert.IsTrue(inlineS.AsSpan().SequenceEqual(seamS), "Seam s must equal the inline path s.");
    }


    [TestMethod]
    public void SplitSignViaHardwareLikeRawSignerVerifies()
    {
        //Simulate a TPM: the raw signer holds u and does its OWN ECDSA (the reference signer, a different
        //implementation than the package's Sign); SecdsaAlgorithm only sees the delegate, never u. The masked
        //result must still be a valid standard ECDSA signature under Y = (P*u)*G.
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("a hardware-held raw signer drives the split sign");

        SecdsaRawEcdsaSign hardwareLike = (blindedHash, r, s0) =>
        {
            Span<byte> nonce = stackalloc byte[ScalarSize];
            Rfc6979DeterministicNonce.GenerateNonce(CurveParameterSet.P256, hardwareKey, blindedHash, Sha256Hmac.Compute, nonce);
            P256EcdsaReference.Sign(hardwareKey, blindedHash, nonce, r, s0);
        };

        byte[] r = new byte[ScalarSize];
        byte[] s = new byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(pinKey, messageHash, hardwareLike, ScalarMultiply, ScalarInvert, ScalarReduce, r, s);

        byte[] publicKey = DerivePublicKey(pinKey, hardwareKey);
        Assert.IsTrue(VerifyWithDotNet(publicKey, messageHash, r, s), "The hardware-seam split signature must verify under the platform ECDSA verifier.");
        Assert.IsTrue(P256EcdsaReference.Verify(publicKey, messageHash, r, s), "...and under the reference verifier.");
    }


    [TestMethod]
    public void FullFormatRecoversTheNoncePointAndVerifies()
    {
        //ToFullFormat must recover the exact nonce point the signer formed. Signing with an EXPLICIT k makes
        //R = k*G known independently: RecoverNoncePoint from (r, s) must return that R, R.x mod n must equal r,
        //VerifyFull(R, s) must accept, and a tampered s must be rejected.
        byte[] pinKey = DeriveScalar("secdsa-pin-key");
        byte[] hardwareKey = DeriveScalar("secdsa-hardware-key");
        byte[] messageHash = MessageHash("full-format recovers the nonce point R = k*G");
        byte[] fixedNonce = DeriveScalar("secdsa-fixed-nonce");

        SecdsaNonceSource fixedNonceSource = (_, _, _, nonce) => fixedNonce.CopyTo(nonce);

        byte[] r = new byte[ScalarSize];
        byte[] s = new byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(
            pinKey, hardwareKey, messageHash, fixedNonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply,
            r, s);

        byte[] publicKey = DerivePublicKey(pinKey, hardwareKey);

        //R = k*G formed directly from the signing nonce — the independent expectation. Masking changes s, not r,
        //so the full point is k*G regardless of the PIN mask.
        Span<byte> generator = stackalloc byte[CompressedSize];
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.P256).CopyTo(generator);
        byte[] expectedNoncePoint = new byte[CompressedSize];
        G1ScalarMultiply(generator, fixedNonce, expectedNoncePoint, CurveParameterSet.P256);

        byte[] recovered = new byte[CompressedSize];
        bool recoveredOk = SecdsaAlgorithm.RecoverNoncePoint(
            publicKey, messageHash, r, s,
            ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add,
            recovered);

        Assert.IsTrue(recoveredOk, "RecoverNoncePoint must recover a finite R from a valid signature.");
        Assert.IsTrue(recovered.AsSpan().SequenceEqual(expectedNoncePoint), "Recovered R must equal k*G formed from the signing nonce.");

        byte[] rFromPoint = new byte[ScalarSize];
        ScalarReduce(recovered.AsSpan(1), rFromPoint, CurveParameterSet.P256);
        Assert.IsTrue(rFromPoint.AsSpan().SequenceEqual(r), "R.x mod n must equal the signature r.");

        Assert.IsTrue(
            SecdsaAlgorithm.VerifyFull(publicKey, messageHash, recovered, s, ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add),
            "VerifyFull must accept the full-format (R, s) signature.");

        byte[] tamperedS = (byte[])s.Clone();
        tamperedS[^1] ^= 0x01;
        Assert.IsFalse(
            SecdsaAlgorithm.VerifyFull(publicKey, messageHash, recovered, tamperedS, ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add),
            "VerifyFull must reject a tampered s.");
    }


    private static (byte[] R, byte[] S) SplitSign(byte[] pinKey, byte[] hardwareKey, byte[] messageHash)
    {
        byte[] r = new byte[ScalarSize];
        byte[] s = new byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(
            pinKey, hardwareKey, messageHash, Rfc6979NonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply,
            r, s);

        return (r, s);
    }


    private static void SplitSignThrowing(byte[] pinKey, byte[] hardwareKey, byte[] messageHash)
    {
        byte[] r = new byte[ScalarSize];
        byte[] s = new byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(
            pinKey, hardwareKey, messageHash, Rfc6979NonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply,
            r, s);
    }


    private static bool Verify(byte[] publicKey, byte[] messageHash, byte[] r, byte[] s) =>
        SecdsaAlgorithm.Verify(publicKey, messageHash, r, s, ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add);


    private static byte[] DerivePublicKey(byte[] pinKey, byte[] hardwareKey)
    {
        byte[] publicKey = new byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(pinKey, hardwareKey, ScalarMultiply, G1ScalarMultiply, publicKey);

        return publicKey;
    }


    //A deterministic, in-range scalar in [1, n-1]: SHA-256 of the label reduced modulo n.
    private static byte[] DeriveScalar(string label)
    {
        Span<byte> digest = stackalloc byte[ScalarSize];
        Sha256.HashData(Encoding.ASCII.GetBytes(label), digest);
        byte[] scalar = new byte[ScalarSize];
        ScalarReduce(digest, scalar, CurveParameterSet.P256);

        return scalar;
    }


    private static byte[] MessageHash(string message)
    {
        byte[] hash = new byte[ScalarSize];
        Sha256.HashData(Encoding.ASCII.GetBytes(message), hash);

        return hash;
    }


    private static byte[] OrderBytes()
    {
        byte[] big = Order.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] order = new byte[ScalarSize];
        big.CopyTo(order.AsSpan(ScalarSize - big.Length));

        return order;
    }


    //Independent oracle: import Y from the compressed point and verify the IEEE-P1363 r||s signature with the
    //platform ECDSA. Decompression reuses the reference group code so a parity slip cannot masquerade as a
    //signing bug.
    private static bool VerifyWithDotNet(byte[] publicKeyCompressed, byte[] messageHash, byte[] r, byte[] s)
    {
        P256BigIntegerG1Reference.AffinePoint point = P256BigIntegerG1Reference.Decode(publicKeyCompressed);

        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = To32(point.X),
                Y = To32(point.Y)
            }
        };

        using ECDsa ecdsa = ECDsa.Create(parameters);

        byte[] signature = new byte[2 * ScalarSize];
        r.CopyTo(signature, 0);
        s.CopyTo(signature, ScalarSize);

        return ecdsa.VerifyHash(messageHash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }


    private static byte[] To32(BigInteger value)
    {
        byte[] big = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] result = new byte[ScalarSize];
        big.CopyTo(result.AsSpan(ScalarSize - big.Length));

        return result;
    }
}
