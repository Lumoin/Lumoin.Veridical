using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Cryptography;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the phased ECDH-MAC of <see cref="EcdhMacAlgorithm"/> (Algorithms 16 and 17) and the phased
/// three-party split of Algorithm 12, with a simulated external key holder between the phases. Each phased path
/// must be byte-identical to the all-software path, the completions must reject a wrong shared secret, and the
/// preparation must reject an infinity, off-curve, or wrongly sized peer point. The key-derivation seam is
/// exercised with both HKDF (Algorithms 16 and 17) and the X9.63 SHA-256 derivation a PKCS#11 HSM applies with
/// <c>CKD_SHA256_KDF</c> (Algorithm 12), and the two are shown to give different keys.
/// </summary>
[TestClass]
internal sealed class EcdhMacPhasesTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;
    private const int MacSize = 32;
    private const int CounterSize = 4;

    private const string ProverKeyHex = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";
    private const string VerifierKeyHex = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    private const string WalletShareHex = "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80912";
    private const string WscaShareHex = "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a23";
    private const string BaseKeyHex = "4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b34";
    private const string OrderHex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    private const string ZeroScalarHex = "0000000000000000000000000000000000000000000000000000000000000000";
    private const string InfinityPointHex = "000000000000000000000000000000000000000000000000000000000000000000";
    private const string OffCurvePointHex = "020000000000000000000000000000000000000000000000000000000000000001";
    private const string ShortPointHex = "0200";
    private const string SaltHex = "73657373696f6e2d7472616e736372697074";
    private const string SharedInfoHex = "454d61634b6579";
    private const string MessageHex = "6465766963652d62696e64696e67206d657373616765";

    private static byte[] ProverKey { get; } = Convert.FromHexString(ProverKeyHex);
    private static byte[] VerifierKey { get; } = Convert.FromHexString(VerifierKeyHex);
    private static byte[] WalletShare { get; } = Convert.FromHexString(WalletShareHex);
    private static byte[] WscaShare { get; } = Convert.FromHexString(WscaShareHex);
    private static byte[] BaseKey { get; } = Convert.FromHexString(BaseKeyHex);
    private static byte[] Order { get; } = Convert.FromHexString(OrderHex);
    private static byte[] ZeroScalar { get; } = Convert.FromHexString(ZeroScalarHex);
    private static byte[] InfinityPoint { get; } = Convert.FromHexString(InfinityPointHex);
    private static byte[] OffCurvePoint { get; } = Convert.FromHexString(OffCurvePointHex);
    private static byte[] ShortPoint { get; } = Convert.FromHexString(ShortPointHex);
    private static byte[] Salt { get; } = Convert.FromHexString(SaltHex);
    private static byte[] SharedInfo { get; } = Convert.FromHexString(SharedInfoHex);
    private static byte[] Message { get; } = Convert.FromHexString(MessageHex);
    private static byte[] NoBytes { get; } = [];

    private static ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerScalarReference.GetMultiply();
    private static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();
    private static EcdhMacKeyDerivationDelegate Hkdf { get; } = Sha256Hkdf.DeriveKey;
    private static EcdhMacKeyDerivationDelegate X963 { get; } = DeriveX963Sha256;
    private static HmacSha256Delegate Hmac { get; } = Sha256Hmac.Compute;


    [TestMethod]
    public void PhasedSignWithSimulatedKeyHolderIsByteIdenticalToAllSoftwareSign()
    {
        AssertPhasedSignMatchesAllSoftwareSign(NoBytes, NoBytes);
        AssertPhasedSignMatchesAllSoftwareSign(Salt, SharedInfo);
    }


    [TestMethod]
    public void KeyHolderDerivedKeyPathNeedsOnlyHmacAndConstantTimeVerification()
    {
        Span<byte> verifierPublicKey = stackalloc byte[CompressedSize];
        PublicPoint(VerifierKey, verifierPublicKey);

        //The key holder derives K itself (ECDH plus the KDF) and returns only K.
        Span<byte> sharedSecret = stackalloc byte[ScalarSize];
        KeyHolderEcdh(ProverKey, verifierPublicKey, sharedSecret);
        Span<byte> macKey = stackalloc byte[EcdhMacAlgorithm.MacKeySizeBytes];
        Hkdf(Salt, sharedSecret, SharedInfo, macKey);

        //Signing under K is the injected HMAC alone.
        Span<byte> mac = stackalloc byte[MacSize];
        Hmac(macKey, Message, mac);

        Span<byte> softwareMac = stackalloc byte[MacSize];
        EcdhMacAlgorithm.Sign(ProverKey, verifierPublicKey, Salt, SharedInfo, Message, Hkdf, Hmac, G1ScalarMultiply, softwareMac);
        Assert.IsTrue(mac.SequenceEqual(softwareMac), "HMAC under the key holder's K must byte-match the all-software MAC.");

        Assert.IsTrue(EcdhMacAlgorithm.VerifyMac(macKey, Message, mac, Hmac), "VerifyMac must accept the MAC under K.");

        Span<byte> tampered = stackalloc byte[MacSize];
        mac.CopyTo(tampered);
        tampered[^1] ^= 0x01;
        Assert.IsFalse(EcdhMacAlgorithm.VerifyMac(macKey, Message, tampered, Hmac), "VerifyMac must reject a tampered MAC.");
        Assert.IsFalse(EcdhMacAlgorithm.VerifyMac(macKey, Message, mac[..(MacSize - 1)], Hmac), "VerifyMac must reject a short MAC without throwing.");
        Assert.IsFalse(EcdhMacAlgorithm.VerifyMac(macKey, SharedInfo, mac, Hmac), "VerifyMac must reject a different message.");
    }


    [TestMethod]
    public void CompleteVerifyAcceptsTheSignedMacAndRejectsAWrongSharedSecret()
    {
        Span<byte> proverPublicKey = stackalloc byte[CompressedSize];
        PublicPoint(ProverKey, proverPublicKey);
        Span<byte> verifierPublicKey = stackalloc byte[CompressedSize];
        PublicPoint(VerifierKey, verifierPublicKey);

        Span<byte> mac = stackalloc byte[MacSize];
        EcdhMacAlgorithm.Sign(ProverKey, verifierPublicKey, Salt, SharedInfo, Message, Hkdf, Hmac, G1ScalarMultiply, mac);

        //The verifier's key holder returns Z_AB = x(e * D) for the prover's public point D.
        Span<byte> verifierSharedSecret = stackalloc byte[ScalarSize];
        KeyHolderEcdh(VerifierKey, proverPublicKey, verifierSharedSecret);
        Assert.IsTrue(
            EcdhMacAlgorithm.CompleteVerify(Salt, verifierSharedSecret, SharedInfo, Message, mac, Hkdf, Hmac),
            "CompleteVerify must accept the MAC under the verifier-side shared secret.");

        Span<byte> wrongSecret = stackalloc byte[ScalarSize];
        verifierSharedSecret.CopyTo(wrongSecret);
        wrongSecret[0] ^= 0x01;
        Assert.IsFalse(
            EcdhMacAlgorithm.CompleteVerify(Salt, wrongSecret, SharedInfo, Message, mac, Hkdf, Hmac),
            "CompleteVerify must reject a wrong Z_AB.");

        Assert.IsFalse(
            EcdhMacAlgorithm.CompleteVerify(Salt, verifierSharedSecret, SharedInfo, Message, mac[..(MacSize - 1)], Hkdf, Hmac),
            "CompleteVerify must reject a short MAC without throwing.");
        Assert.IsFalse(
            EcdhMacAlgorithm.CompleteVerify(Salt, verifierSharedSecret, SharedInfo, SharedInfo, mac, Hkdf, Hmac),
            "CompleteVerify must reject a different message.");

        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.CompleteVerify(Salt, Salt, SharedInfo, Message, Message, Hkdf, Hmac),
            "A shared secret that is not 32 bytes is a caller error.");
    }


    [TestMethod]
    public void PrepareKeyAgreementRejectsInfinityOffCurveAndWronglySizedPoints()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => PrepareInto(InfinityPoint),
            "The encoded point at infinity must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(
            () => PrepareInto(ShortPoint),
            "A wrongly sized point must be rejected.");
        Assert.ThrowsExactly<InvalidOperationException>(
            () => PrepareInto(OffCurvePoint),
            "An off-curve point must be rejected through the backend's decode contract.");
    }


    [TestMethod]
    public void ThreePartyPhasesAreByteIdenticalToAllSoftwareSplitSign()
    {
        Span<byte> verifierPublicKey = stackalloc byte[CompressedSize];
        PublicPoint(VerifierKey, verifierPublicKey);

        //Wallet: validate E (step 1) and compute E' = zU * E (step 2).
        Span<byte> walletInput = stackalloc byte[CompressedSize];
        EcdhMacAlgorithm.PrepareKeyAgreement(verifierPublicKey, G1ScalarMultiply, walletInput);
        Span<byte> walletBlinded = stackalloc byte[CompressedSize];
        EcdhMacAlgorithm.ApplyKeyShare(WalletShare, walletInput, G1ScalarMultiply, walletBlinded);

        //WSCA: E'' = zW * E' (step 4), after validating what it received.
        Span<byte> wscaInput = stackalloc byte[CompressedSize];
        EcdhMacAlgorithm.PrepareKeyAgreement(walletBlinded, G1ScalarMultiply, wscaInput);
        Span<byte> wscaBlinded = stackalloc byte[CompressedSize];
        EcdhMacAlgorithm.ApplyKeyShare(WscaShare, wscaInput, G1ScalarMultiply, wscaBlinded);

        //HSM: S_AB = bU * E'' and Z_AB (steps 6 and 7); the wallet completes with the MAC.
        Span<byte> sharedSecret = stackalloc byte[ScalarSize];
        KeyHolderEcdh(BaseKey, wscaBlinded, sharedSecret);
        Span<byte> phasedMac = stackalloc byte[MacSize];
        EcdhMacAlgorithm.CompleteSign(Salt, sharedSecret, SharedInfo, Message, Hkdf, Hmac, phasedMac);

        Span<byte> softwareMac = stackalloc byte[MacSize];
        EcdhMacAlgorithm.SplitSign(
            WalletShare, WscaShare, BaseKey, verifierPublicKey, Salt, SharedInfo, Message,
            Hkdf, Hmac, G1ScalarMultiply, softwareMac);

        Assert.IsTrue(phasedMac.SequenceEqual(softwareMac), "The three-party phases must byte-match the all-software split sign.");
    }


    [TestMethod]
    public void X963DerivationAtTheHsmVerifiesOnlyWhenTheVerifierBindsTheSameDerivation()
    {
        //Algorithm 12 lets the HSM derive K (step 8) with CKM_ECDH1_DERIVE and CKD_SHA256_KDF, an X9.63 KDF.
        //Algorithms 16 and 17 derive K with HKDF. Same Z_AB, different K: a MAC made under the HSM's K verifies
        //only where the verifier binds the same derivation.
        Span<byte> verifierPublicKey = stackalloc byte[CompressedSize];
        PublicPoint(VerifierKey, verifierPublicKey);
        Span<byte> walletBlinded = stackalloc byte[CompressedSize];
        EcdhMacAlgorithm.ApplyKeyShare(WalletShare, verifierPublicKey, G1ScalarMultiply, walletBlinded);
        Span<byte> wscaBlinded = stackalloc byte[CompressedSize];
        EcdhMacAlgorithm.ApplyKeyShare(WscaShare, walletBlinded, G1ScalarMultiply, wscaBlinded);

        Span<byte> sharedSecret = stackalloc byte[ScalarSize];
        KeyHolderEcdh(BaseKey, wscaBlinded, sharedSecret);
        Span<byte> hsmKey = stackalloc byte[EcdhMacAlgorithm.MacKeySizeBytes];
        X963(NoBytes, sharedSecret, SharedInfo, hsmKey);
        Span<byte> hkdfKey = stackalloc byte[EcdhMacAlgorithm.MacKeySizeBytes];
        Hkdf(NoBytes, sharedSecret, SharedInfo, hkdfKey);
        Assert.IsFalse(hsmKey.SequenceEqual(hkdfKey), "X9.63 and HKDF must derive different keys from the same Z_AB.");

        //The wallet receives K from the HSM (step 10) and computes the MAC (step 11).
        Span<byte> mac = stackalloc byte[MacSize];
        Hmac(hsmKey, Message, mac);

        Span<byte> composedKey = stackalloc byte[ScalarSize];
        ScalarMultiply(WalletShare, WscaShare, composedKey, CurveParameterSet.P256);
        Span<byte> composedKeyFinal = stackalloc byte[ScalarSize];
        ScalarMultiply(composedKey, BaseKey, composedKeyFinal, CurveParameterSet.P256);
        Span<byte> composedPublicKey = stackalloc byte[CompressedSize];
        PublicPoint(composedKeyFinal, composedPublicKey);

        Assert.IsTrue(
            EcdhMacAlgorithm.Verify(composedPublicKey, VerifierKey, NoBytes, SharedInfo, Message, mac, X963, Hmac, G1ScalarMultiply),
            "A verifier binding the X9.63 derivation must accept the MAC under the HSM-derived key.");
        Assert.IsFalse(
            EcdhMacAlgorithm.Verify(composedPublicKey, VerifierKey, NoBytes, SharedInfo, Message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "A verifier binding HKDF must reject a MAC made under the X9.63-derived key.");
    }


    [TestMethod]
    public void X963DerivationMatchesAnIndependentSha256Computation()
    {
        //K = SHA-256(Z || counter || SharedInfo) for one 32-byte block, computed with the platform hash.
        Span<byte> sharedSecret = stackalloc byte[ScalarSize];
        KeyHolderEcdh(ProverKey, PublicPointOf(VerifierKey), sharedSecret);

        Span<byte> input = stackalloc byte[ScalarSize + CounterSize + SharedInfo.Length];
        sharedSecret.CopyTo(input);
        input[ScalarSize + CounterSize - 1] = 0x01;
        SharedInfo.CopyTo(input[(ScalarSize + CounterSize)..]);
        Span<byte> expected = stackalloc byte[ScalarSize];
        SHA256.HashData(input, expected);

        Span<byte> derived = stackalloc byte[ScalarSize];
        X963(NoBytes, sharedSecret, SharedInfo, derived);

        Assert.IsTrue(derived.SequenceEqual(expected), "The X9.63 test derivation must equal SHA-256(Z || 00000001 || SharedInfo).");
    }


    [TestMethod]
    public void ApplyKeyShareRejectsInvalidSharesAndPoints()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => ApplyInto(ZeroScalar, PublicPointOf(VerifierKey)),
            "A zero key share must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(
            () => ApplyInto(Order, PublicPointOf(VerifierKey)),
            "A key share equal to n must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(
            () => ApplyInto(WalletShare, InfinityPoint),
            "The point at infinity must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(
            () => ApplyInto(WalletShare, ShortPoint),
            "A wrongly sized point must be rejected.");
        Assert.ThrowsExactly<InvalidOperationException>(
            () => ApplyInto(WalletShare, OffCurvePoint),
            "An off-curve point must be rejected through the backend's decode contract.");
    }


    private static void AssertPhasedSignMatchesAllSoftwareSign(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> sharedInfo)
    {
        Span<byte> verifierPublicKey = stackalloc byte[CompressedSize];
        PublicPoint(VerifierKey, verifierPublicKey);

        Span<byte> keyHolderInput = stackalloc byte[CompressedSize];
        EcdhMacAlgorithm.PrepareKeyAgreement(verifierPublicKey, G1ScalarMultiply, keyHolderInput);
        Assert.IsTrue(keyHolderInput.SequenceEqual(verifierPublicKey), "Prepare must return the validated canonical encoding of E.");

        //The key holder performs the raw ECDH and returns Z_AB; the private scalar never enters the library.
        Span<byte> sharedSecret = stackalloc byte[ScalarSize];
        KeyHolderEcdh(ProverKey, keyHolderInput, sharedSecret);

        Span<byte> phasedMac = stackalloc byte[MacSize];
        EcdhMacAlgorithm.CompleteSign(salt, sharedSecret, sharedInfo, Message, Hkdf, Hmac, phasedMac);

        Span<byte> softwareMac = stackalloc byte[MacSize];
        EcdhMacAlgorithm.Sign(ProverKey, verifierPublicKey, salt, sharedInfo, Message, Hkdf, Hmac, G1ScalarMultiply, softwareMac);

        Assert.IsTrue(phasedMac.SequenceEqual(softwareMac), $"The phased MAC must byte-match the all-software MAC (salt {salt.Length}B, shared info {sharedInfo.Length}B).");
    }


    //The simulated external key holder: raw ECDH returning the 32-byte x-coordinate Z_AB.
    private static void KeyHolderEcdh(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPoint, Span<byte> sharedSecret)
    {
        Span<byte> sharedPoint = stackalloc byte[CompressedSize];
        try
        {
            G1ScalarMultiply(peerPoint, privateKey, sharedPoint, CurveParameterSet.P256);
            sharedPoint[1..].CopyTo(sharedSecret);
        }
        finally
        {
            sharedPoint.Clear();
        }
    }


    //The ANSI X9.63 KDF over SHA-256 for a single 32-byte output block: SHA-256(Z || counter(1) || SharedInfo),
    //the derivation CKD_SHA256_KDF denotes. The salt does not take part.
    private static void DeriveX963Sha256(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> sharedInfo, Span<byte> macKey)
    {
        Span<byte> input = stackalloc byte[sharedSecret.Length + CounterSize + sharedInfo.Length];
        Span<byte> block = stackalloc byte[ScalarSize];
        try
        {
            sharedSecret.CopyTo(input);
            input[sharedSecret.Length + CounterSize - 1] = 0x01;
            sharedInfo.CopyTo(input[(sharedSecret.Length + CounterSize)..]);
            SHA256.HashData(input, block);
            block[..macKey.Length].CopyTo(macKey);
        }
        finally
        {
            input.Clear();
            block.Clear();
        }
    }


    private static void PublicPoint(ReadOnlySpan<byte> privateKey, Span<byte> publicPoint)
    {
        Span<byte> generator = stackalloc byte[CompressedSize];
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.P256).CopyTo(generator);
        G1ScalarMultiply(generator, privateKey, publicPoint, CurveParameterSet.P256);
    }


    private static byte[] PublicPointOf(byte[] privateKey)
    {
        byte[] publicPoint = Convert.FromHexString(InfinityPointHex);
        PublicPoint(privateKey, publicPoint);

        return publicPoint;
    }


    private static void PrepareInto(byte[] point)
    {
        Span<byte> output = stackalloc byte[CompressedSize];
        EcdhMacAlgorithm.PrepareKeyAgreement(point, G1ScalarMultiply, output);
    }


    private static void ApplyInto(byte[] share, byte[] point)
    {
        Span<byte> output = stackalloc byte[CompressedSize];
        EcdhMacAlgorithm.ApplyKeyShare(share, point, G1ScalarMultiply, output);
    }
}
