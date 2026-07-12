using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Cryptography;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for <see cref="EcdhMacAlgorithm"/>, Verheul's ECDH-MAC device-binding primitive (Algorithms 16/17) and
/// its three-party Split-ECDH-MAC composition (Algorithm 12). The split MAC must agree byte-for-byte with a
/// direct MAC under the composed key (the associativity gate), a signed MAC must verify via Diffie-Hellman
/// symmetry, and — since no published ISO test vectors exist for this primitive — the full derivation is pinned
/// against an independent oracle built from the platform <see cref="ECDiffieHellman"/> plus
/// <see cref="HKDF"/>/<see cref="HMACSHA256"/>. The group arithmetic is wired from the BigInteger references,
/// mirroring <c>SecdsaSplitSignTests</c>.
/// </summary>
[TestClass]
internal sealed class EcdhMacAlgorithmTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;
    private const int MacSize = 32;

    private static ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerScalarReference.GetMultiply();
    private static ScalarReduceDelegate ScalarReduce { get; } = P256BigIntegerScalarReference.GetReduce();
    private static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();
    private static HkdfSha256Delegate Hkdf { get; } = Sha256Hkdf.DeriveKey;
    private static HmacSha256Delegate Hmac { get; } = Sha256Hmac.Compute;

    private static BigInteger Order { get; } = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);


    //Deterministic (walletShareLabel, wscaShareLabel, baseKeyLabel, verifierEphemeralLabel) tuples for the
    //split-vs-direct agreement gate; no unseeded randomness anywhere in this file.
    private static readonly (string WalletShareLabel, string WscaShareLabel, string BaseKeyLabel, string VerifierEphemeralLabel)[] SplitVsDirectKeyTuples =
    [
        ("ecdhmac-split-wallet-share-1", "ecdhmac-split-wsca-share-1", "ecdhmac-split-base-key-1", "ecdhmac-split-verifier-ephemeral-1"),
        ("ecdhmac-split-wallet-share-2", "ecdhmac-split-wsca-share-2", "ecdhmac-split-base-key-2", "ecdhmac-split-verifier-ephemeral-2"),
        ("ecdhmac-split-wallet-share-3", "ecdhmac-split-wsca-share-3", "ecdhmac-split-base-key-3", "ecdhmac-split-verifier-ephemeral-3"),
    ];

    //(salt, sharedInfo) combinations covering the paper's plain form (both empty) and the ISO 18013-5 EMacKey
    //shape (both non-empty).
    private static readonly (byte[] Salt, byte[] SharedInfo)[] ContextCombinations =
    [
        ([], []),
        (Encoding.ASCII.GetBytes("session-transcript-hash"), Encoding.ASCII.GetBytes("EMacKey")),
    ];


    [TestMethod]
    public void SplitSignAgreesWithDirectSignUnderTheComposedKeyAcrossTuplesAndContexts()
    {
        foreach((string walletLabel, string wscaLabel, string baseLabel, string ephemeralLabel) in SplitVsDirectKeyTuples)
        {
            byte[] walletKeyShare = DeriveScalar(walletLabel);
            byte[] wscaKeyShare = DeriveScalar(wscaLabel);
            byte[] baseKey = DeriveScalar(baseLabel);
            byte[] verifierEphemeralPublicKey = DerivePublicPoint(DeriveScalar(ephemeralLabel));
            byte[] composedPrivateKey = ComposePrivateKey(walletKeyShare, wscaKeyShare, baseKey);
            byte[] message = Encoding.ASCII.GetBytes($"split-vs-direct agreement for {walletLabel}/{wscaLabel}/{baseLabel}");

            foreach((byte[] salt, byte[] sharedInfo) in ContextCombinations)
            {
                byte[] splitMac = new byte[MacSize];
                EcdhMacAlgorithm.SplitSign(
                    walletKeyShare, wscaKeyShare, baseKey, verifierEphemeralPublicKey,
                    salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, splitMac);

                byte[] directMac = new byte[MacSize];
                EcdhMacAlgorithm.Sign(
                    composedPrivateKey, verifierEphemeralPublicKey,
                    salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, directMac);

                Assert.IsTrue(
                    splitMac.AsSpan().SequenceEqual(directMac),
                    $"SplitSign must byte-match a direct Sign under the composed key p = zU*zW*bU mod n for {walletLabel}/{wscaLabel}/{baseLabel} (salt {salt.Length}B, sharedInfo {sharedInfo.Length}B).");
            }
        }
    }


    [TestMethod]
    public void VerifyAcceptsSignUnderDiffieHellmanSymmetry()
    {
        byte[] proverPrivateKey = DeriveScalar("ecdhmac-roundtrip-prover-private-key");
        byte[] proverPublicKey = DerivePublicPoint(proverPrivateKey);
        byte[] verifierEphemeralPrivateKey = DeriveScalar("ecdhmac-roundtrip-verifier-ephemeral-private-key");
        byte[] verifierEphemeralPublicKey = DerivePublicPoint(verifierEphemeralPrivateKey);
        byte[] message = Encoding.ASCII.GetBytes("device-binding message authenticated prover to verifier");
        byte[] salt = Encoding.ASCII.GetBytes("session-transcript-hash");
        byte[] sharedInfo = Encoding.ASCII.GetBytes("EMacKey");

        byte[] mac = new byte[MacSize];
        EcdhMacAlgorithm.Sign(proverPrivateKey, verifierEphemeralPublicKey, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac);

        bool accepted = EcdhMacAlgorithm.Verify(
            proverPublicKey, verifierEphemeralPrivateKey, salt, sharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply);

        Assert.IsTrue(accepted, "Verify must accept a MAC produced by Sign, via Diffie-Hellman symmetry e*D = d*E.");
    }


    [TestMethod]
    public void SplitSignOutputVerifiesUnderTheComposedPublicKey()
    {
        byte[] walletKeyShare = DeriveScalar("ecdhmac-split-verify-wallet-share");
        byte[] wscaKeyShare = DeriveScalar("ecdhmac-split-verify-wsca-share");
        byte[] baseKey = DeriveScalar("ecdhmac-split-verify-base-key");
        byte[] verifierEphemeralPrivateKey = DeriveScalar("ecdhmac-split-verify-verifier-ephemeral");
        byte[] verifierEphemeralPublicKey = DerivePublicPoint(verifierEphemeralPrivateKey);
        byte[] message = Encoding.ASCII.GetBytes("the split MAC verifies under the composed public key P = p*G");
        byte[] salt = [];
        byte[] sharedInfo = Encoding.ASCII.GetBytes("split-context");

        byte[] mac = new byte[MacSize];
        EcdhMacAlgorithm.SplitSign(
            walletKeyShare, wscaKeyShare, baseKey, verifierEphemeralPublicKey,
            salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac);

        byte[] composedPrivateKey = ComposePrivateKey(walletKeyShare, wscaKeyShare, baseKey);
        byte[] composedPublicKey = DerivePublicPoint(composedPrivateKey);

        bool accepted = EcdhMacAlgorithm.Verify(
            composedPublicKey, verifierEphemeralPrivateKey, salt, sharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply);

        Assert.IsTrue(accepted, "SplitSign output must verify under the composed public key P = (zU*zW*bU mod n)*G.");
    }


    [TestMethod]
    public void SignMatchesThePlatformEcdhHkdfAndHmacPipeline()
    {
        byte[] proverPrivateKey = DeriveScalar("ecdhmac-platform-oracle-prover-private-key");
        byte[] proverPublicKey = DerivePublicPoint(proverPrivateKey);
        byte[] verifierEphemeralPrivateKey = DeriveScalar("ecdhmac-platform-oracle-verifier-ephemeral-private-key");
        byte[] verifierEphemeralPublicKey = DerivePublicPoint(verifierEphemeralPrivateKey);
        byte[] message = Encoding.ASCII.GetBytes("the platform ECDH + HKDF + HMAC pipeline is an independent oracle");
        byte[] salt = Encoding.ASCII.GetBytes("session-transcript-hash");
        byte[] sharedInfo = Encoding.ASCII.GetBytes("EMacKey");

        using ECDiffieHellman proverEcdh = CreatePlatformEcdhKey(proverPrivateKey, proverPublicKey);
        using ECDiffieHellman verifierEcdh = CreatePlatformEcdhKey(verifierEphemeralPrivateKey, verifierEphemeralPublicKey);

        byte[] sharedSecret = proverEcdh.DeriveRawSecretAgreement(verifierEcdh.PublicKey);
        byte[] macKeyBytes = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, MacSize, salt, sharedInfo);
        byte[] expectedMac = HMACSHA256.HashData(macKeyBytes, message);

        byte[] actualMac = new byte[MacSize];
        EcdhMacAlgorithm.Sign(proverPrivateKey, verifierEphemeralPublicKey, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, actualMac);

        Assert.IsTrue(
            actualMac.AsSpan().SequenceEqual(expectedMac),
            "Sign must match the independent platform ECDH + HKDF + HMAC pipeline byte-for-byte.");
    }


    [TestMethod]
    public void DeriveMacKeySupportsVariableLengthsAndMatchesThePlatformHkdf()
    {
        byte[] privateKey = DeriveScalar("ecdhmac-mac-key-length-private-key");
        byte[] publicKey = DerivePublicPoint(privateKey);
        byte[] peerPrivateKey = DeriveScalar("ecdhmac-mac-key-length-peer-private-key");
        byte[] peerPublicKey = DerivePublicPoint(peerPrivateKey);
        byte[] salt = Encoding.ASCII.GetBytes("ecdhmac-mac-key-length-salt");
        byte[] sharedInfo = Encoding.ASCII.GetBytes("ecdhmac-mac-key-length-info");

        using ECDiffieHellman proverEcdh = CreatePlatformEcdhKey(privateKey, publicKey);
        using ECDiffieHellman peerEcdh = CreatePlatformEcdhKey(peerPrivateKey, peerPublicKey);
        byte[] sharedSecret = proverEcdh.DeriveRawSecretAgreement(peerEcdh.PublicKey);

        ReadOnlySpan<int> macKeyLengths = [16, MacSize];
        foreach(int length in macKeyLengths)
        {
            byte[] expected = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, length, salt, sharedInfo);

            byte[] actual = new byte[length];
            EcdhMacAlgorithm.DeriveMacKey(privateKey, peerPublicKey, salt, sharedInfo, Hkdf, G1ScalarMultiply, actual);

            Assert.IsTrue(
                actual.AsSpan().SequenceEqual(expected),
                $"DeriveMacKey with L = {length} must match the platform HKDF over the platform ECDH shared secret.");
        }

        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.DeriveMacKey(privateKey, peerPublicKey, salt, sharedInfo, Hkdf, G1ScalarMultiply, Array.Empty<byte>()),
            "An empty MAC key destination (L = 0) must be rejected.");
    }


    [TestMethod]
    public void VerifyRejectsTamperedMessageContextMacAndProverKey()
    {
        byte[] proverPrivateKey = DeriveScalar("ecdhmac-tamper-prover-private-key");
        byte[] proverPublicKey = DerivePublicPoint(proverPrivateKey);
        byte[] verifierEphemeralPrivateKey = DeriveScalar("ecdhmac-tamper-verifier-ephemeral-private-key");
        byte[] verifierEphemeralPublicKey = DerivePublicPoint(verifierEphemeralPrivateKey);
        byte[] message = Encoding.ASCII.GetBytes("the original authenticated message");
        byte[] salt = Encoding.ASCII.GetBytes("original-salt");
        byte[] sharedInfo = Encoding.ASCII.GetBytes("original-shared-info");

        byte[] mac = new byte[MacSize];
        EcdhMacAlgorithm.Sign(proverPrivateKey, verifierEphemeralPublicKey, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac);

        Assert.IsTrue(
            EcdhMacAlgorithm.Verify(proverPublicKey, verifierEphemeralPrivateKey, salt, sharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "The untampered MAC must verify.");

        byte[] tamperedMessage = (byte[])message.Clone();
        tamperedMessage[^1] ^= 0x01;
        Assert.IsFalse(
            EcdhMacAlgorithm.Verify(proverPublicKey, verifierEphemeralPrivateKey, salt, sharedInfo, tamperedMessage, mac, Hkdf, Hmac, G1ScalarMultiply),
            "A flipped message byte must be rejected.");

        byte[] differentSharedInfo = Encoding.ASCII.GetBytes("different-shared-info");
        Assert.IsFalse(
            EcdhMacAlgorithm.Verify(proverPublicKey, verifierEphemeralPrivateKey, salt, differentSharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "A different sharedInfo must be rejected.");

        byte[] differentSalt = Encoding.ASCII.GetBytes("different-salt");
        Assert.IsFalse(
            EcdhMacAlgorithm.Verify(proverPublicKey, verifierEphemeralPrivateKey, differentSalt, sharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "A different salt must be rejected.");

        byte[] tamperedMac = (byte[])mac.Clone();
        tamperedMac[^1] ^= 0x01;
        Assert.IsFalse(
            EcdhMacAlgorithm.Verify(proverPublicKey, verifierEphemeralPrivateKey, salt, sharedInfo, message, tamperedMac, Hkdf, Hmac, G1ScalarMultiply),
            "A flipped MAC byte must be rejected.");

        byte[] truncatedMac = mac[..^1];
        Assert.IsFalse(
            EcdhMacAlgorithm.Verify(proverPublicKey, verifierEphemeralPrivateKey, salt, sharedInfo, message, truncatedMac, Hkdf, Hmac, G1ScalarMultiply),
            "A truncated (31-byte) MAC must be rejected.");

        byte[] wrongProverPublicKey = DerivePublicPoint(DeriveScalar("ecdhmac-tamper-wrong-prover-private-key"));
        Assert.IsFalse(
            EcdhMacAlgorithm.Verify(wrongProverPublicKey, verifierEphemeralPrivateKey, salt, sharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "A wrong prover public key (d'*G) must be rejected.");

        //A changed input on the signing side must change the produced MAC, not merely fail verification later.
        byte[] macWithDifferentSharedInfo = new byte[MacSize];
        EcdhMacAlgorithm.Sign(proverPrivateKey, verifierEphemeralPublicKey, salt, differentSharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, macWithDifferentSharedInfo);
        Assert.IsFalse(
            mac.AsSpan().SequenceEqual(macWithDifferentSharedInfo),
            "A different sharedInfo must change the MAC produced by Sign.");
    }


    [TestMethod]
    public void InfinityPeerPointIsRejectedByDeriveMacKeySignSplitSignAndVerify()
    {
        byte[] privateKey = DeriveScalar("ecdhmac-infinity-peer-private-key");
        byte[] walletKeyShare = DeriveScalar("ecdhmac-infinity-peer-wallet-share");
        byte[] wscaKeyShare = DeriveScalar("ecdhmac-infinity-peer-wsca-share");
        byte[] baseKey = DeriveScalar("ecdhmac-infinity-peer-base-key");
        byte[] verifierEphemeralPrivateKey = DeriveScalar("ecdhmac-infinity-peer-verifier-ephemeral-private-key");
        byte[] message = Encoding.ASCII.GetBytes("infinity peer point validation");
        byte[] salt = [];
        byte[] sharedInfo = [];
        byte[] mac = new byte[MacSize];

        //The all-zero 33-byte encoding is the canonical SEC1 point at infinity (a 0x00 prefix with a zeroed
        //coordinate field), which is never a member of the prime-order subgroup <G>.
        byte[] infinityPoint = new byte[CompressedSize];

        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.DeriveMacKey(privateKey, infinityPoint, salt, sharedInfo, Hkdf, G1ScalarMultiply, mac),
            "DeriveMacKey must reject the encoded point at infinity.");

        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.Sign(privateKey, infinityPoint, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac),
            "Sign must reject the encoded point at infinity for the verifier's ephemeral public key.");

        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.SplitSign(walletKeyShare, wscaKeyShare, baseKey, infinityPoint, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac),
            "SplitSign must reject the encoded point at infinity for the verifier's ephemeral public key.");

        Assert.IsFalse(
            EcdhMacAlgorithm.Verify(infinityPoint, verifierEphemeralPrivateKey, salt, sharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "Verify must reject an infinity prover public key by returning false, not throwing.");
    }


    [TestMethod]
    public void OffCurvePeerPointIsRejectedByDeriveMacKeySignSplitSignAndVerify()
    {
        byte[] privateKey = DeriveScalar("ecdhmac-offcurve-peer-private-key");
        byte[] walletKeyShare = DeriveScalar("ecdhmac-offcurve-peer-wallet-share");
        byte[] wscaKeyShare = DeriveScalar("ecdhmac-offcurve-peer-wsca-share");
        byte[] baseKey = DeriveScalar("ecdhmac-offcurve-peer-base-key");
        byte[] verifierEphemeralPrivateKey = DeriveScalar("ecdhmac-offcurve-peer-verifier-ephemeral-private-key");
        byte[] message = Encoding.ASCII.GetBytes("off-curve peer point validation");
        byte[] salt = [];
        byte[] sharedInfo = [];
        byte[] mac = new byte[MacSize];

        //x = 1 is a quadratic non-residue for P-256's y^2 = x^3 - 3x + b: alpha = 1 + a + b (with a = p - 3) is
        //not a square mod p (verified independently via the Legendre symbol alpha^((p-1)/2) mod p = p - 1), so no
        //point exists at this x. The encoding is otherwise well-formed (a valid 0x02 parity prefix), so this
        //probes the decode's on-curve check specifically, distinct from the infinity-encoding check above.
        byte[] offCurvePoint = new byte[CompressedSize];
        offCurvePoint[0] = 0x02;
        offCurvePoint[^1] = 0x01;

        //Pins the mathematical fact itself: if x = 1 ever decoded to a real point, this assertion — not only
        //the derived-API ones below — fails, so the fixture cannot silently rot into an on-curve value.
        Assert.ThrowsExactly<InvalidOperationException>(
            () => P256BigIntegerG1Reference.Decode(offCurvePoint),
            "x = 1 must have no point on P-256: the reference decoder must reject it as a non-residue.");

        AssertThrowsArgumentOrInvalidOperation(
            () => EcdhMacAlgorithm.DeriveMacKey(privateKey, offCurvePoint, salt, sharedInfo, Hkdf, G1ScalarMultiply, mac),
            "DeriveMacKey must reject an off-curve peer point.");

        AssertThrowsArgumentOrInvalidOperation(
            () => EcdhMacAlgorithm.Sign(privateKey, offCurvePoint, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac),
            "Sign must reject an off-curve verifier ephemeral public key.");

        AssertThrowsArgumentOrInvalidOperation(
            () => EcdhMacAlgorithm.SplitSign(walletKeyShare, wscaKeyShare, baseKey, offCurvePoint, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac),
            "SplitSign must reject an off-curve verifier ephemeral public key.");

        //With the Decode assertion above pinning that this input IS off-curve, this pins Verify's contract for
        //it: rejected as false, never an escaping throw.
        Assert.IsFalse(
            EcdhMacAlgorithm.Verify(offCurvePoint, verifierEphemeralPrivateKey, salt, sharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "Verify must reject an off-curve prover public key by returning false, not throwing.");
    }


    [TestMethod]
    public void VerifyPropagatesTheInjectedHkdfsRejectionOfAnOversizedSharedInfo()
    {
        byte[] proverPrivateKey = DeriveScalar("ecdhmac-oversized-info-prover-private-key");
        byte[] proverPublicKey = DerivePublicPoint(proverPrivateKey);
        byte[] verifierEphemeralPrivateKey = DeriveScalar("ecdhmac-oversized-info-verifier-ephemeral-private-key");
        byte[] message = Encoding.ASCII.GetBytes("oversized sharedInfo is a configuration error");
        byte[] salt = [];
        byte[] oversizedSharedInfo = new byte[Sha256Hkdf.MaxInfoSizeBytes + 1];
        byte[] mac = new byte[MacSize];

        //sharedInfo is the verifier's OWN protocol context: the injected Sha256Hkdf's info bound must surface as
        //a throw, never be swallowed into a false that is indistinguishable from a forged MAC.
        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.Verify(proverPublicKey, verifierEphemeralPrivateKey, salt, oversizedSharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "Verify must propagate the injected HKDF's rejection of an oversized sharedInfo, not return false.");
    }


    [TestMethod]
    public void OutOfRangeScalarsThrowArgumentExceptionEverywhereAndVerifyThrowsForItsOwnKey()
    {
        byte[] validScalar = DeriveScalar("ecdhmac-scalar-range-valid");
        byte[] zeroScalar = new byte[ScalarSize];
        byte[] orderScalar = OrderBytes();
        byte[] verifierEphemeralPublicKey = DerivePublicPoint(DeriveScalar("ecdhmac-scalar-range-ephemeral"));
        byte[] proverPublicKey = DerivePublicPoint(validScalar);
        byte[] message = Encoding.ASCII.GetBytes("scalar range validation");
        byte[] salt = [];
        byte[] sharedInfo = [];
        byte[] mac = new byte[MacSize];

        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.Sign(zeroScalar, verifierEphemeralPublicKey, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac),
            "privateKey = 0 must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.Sign(orderScalar, verifierEphemeralPublicKey, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac),
            "privateKey = n must be rejected.");

        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.SplitSign(zeroScalar, validScalar, validScalar, verifierEphemeralPublicKey, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac),
            "walletKeyShare = 0 must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.SplitSign(validScalar, orderScalar, validScalar, verifierEphemeralPublicKey, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac),
            "wscaKeyShare = n must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.SplitSign(validScalar, validScalar, zeroScalar, verifierEphemeralPublicKey, salt, sharedInfo, message, Hkdf, Hmac, G1ScalarMultiply, mac),
            "baseKey = 0 must be rejected.");

        //verifierEphemeralPrivateKey is the verifier's OWN material (not adversarial prover-supplied content), so
        //an out-of-range value is a caller error: Verify throws rather than returning false.
        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.Verify(proverPublicKey, zeroScalar, salt, sharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "Verify must throw for an out-of-range (zero) verifierEphemeralPrivateKey.");
        Assert.ThrowsExactly<ArgumentException>(
            () => EcdhMacAlgorithm.Verify(proverPublicKey, orderScalar, salt, sharedInfo, message, mac, Hkdf, Hmac, G1ScalarMultiply),
            "Verify must throw for verifierEphemeralPrivateKey = n.");
    }


    //Assert.ThrowsExactly<T> pins a single exception type, but the off-curve rejection legitimately surfaces as
    //either ArgumentException or InvalidOperationException depending on which backend check fires first — the
    //delegate's documented decode contract — so both are accepted here.
    private static void AssertThrowsArgumentOrInvalidOperation(Action action, string message)
    {
        try
        {
            action();
        }
        catch(ArgumentException)
        {
            return;
        }
        catch(InvalidOperationException)
        {
            return;
        }

        Assert.Fail(message);
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


    private static byte[] DerivePublicPoint(byte[] scalar)
    {
        Span<byte> generator = stackalloc byte[CompressedSize];
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.P256).CopyTo(generator);
        byte[] point = new byte[CompressedSize];
        G1ScalarMultiply(generator, scalar, point, CurveParameterSet.P256);

        return point;
    }


    //p = zU*zW*bU mod n, formed in a different operation order (right-to-left) than SplitSign's internal
    //point-side chain (E' = zU*E, E'' = zW*E'), so the two computations are independent checks of the same
    //associativity identity.
    private static byte[] ComposePrivateKey(byte[] walletKeyShare, byte[] wscaKeyShare, byte[] baseKey)
    {
        Span<byte> walletTimesWsca = stackalloc byte[ScalarSize];
        ScalarMultiply(walletKeyShare, wscaKeyShare, walletTimesWsca, CurveParameterSet.P256);
        byte[] composed = new byte[ScalarSize];
        ScalarMultiply(walletTimesWsca, baseKey, composed, CurveParameterSet.P256);

        return composed;
    }


    private static byte[] OrderBytes()
    {
        byte[] big = Order.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] order = new byte[ScalarSize];
        big.CopyTo(order.AsSpan(ScalarSize - big.Length));

        return order;
    }


    //Builds a platform ECDiffieHellman key from our scalar/point representation, for the independent-oracle
    //tests. Windows CNG requires the public point when importing a private key, so Q is filled from the same
    //compressed point via the reference decoder (reachable through InternalsVisibleTo, as in SecdsaSplitSignTests).
    private static ECDiffieHellman CreatePlatformEcdhKey(byte[] privateKeyScalar, byte[] publicKeyCompressed)
    {
        P256BigIntegerG1Reference.AffinePoint point = P256BigIntegerG1Reference.Decode(publicKeyCompressed);

        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privateKeyScalar,
            Q = new ECPoint
            {
                X = To32(point.X),
                Y = To32(point.Y)
            }
        };

        return ECDiffieHellman.Create(parameters);
    }


    private static byte[] To32(BigInteger value)
    {
        byte[] big = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] result = new byte[ScalarSize];
        big.CopyTo(result.AsSpan(ScalarSize - big.Length));

        return result;
    }
}
