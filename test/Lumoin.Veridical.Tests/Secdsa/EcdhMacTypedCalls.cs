using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Cryptography;
using Lumoin.Veridical.Secdsa;
using System;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Span-shaped entry points over the typed ECDH-MAC API of <see cref="EcdhMacAlgorithm"/>: each method wraps its span
/// arguments in the tagged protocol values, calls the typed entry point, and copies the result out, clearing the output
/// when the call fails. The tests keep their fixed byte vectors and call these, so every test exercises the typed API and
/// the validation of the typed values.
/// </summary>
internal static class EcdhMacTypedCalls
{
    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;


    private static G1Point Point(ReadOnlySpan<byte> bytes) => G1Point.FromCanonical(bytes, CurveParameterSet.P256, Pool);


    /// <summary>The typed key derivation from a private key and a peer point.</summary>
    public static void DeriveMacKey(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> peerPublicPoint,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedInfo,
        EcdhMacKeyDerivationDelegate keyDerivation,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> macKey)
    {
        try
        {
            using PrivateScalar key = PrivateScalar.FromCanonical(privateKey, Pool);
            using G1Point peer = Point(peerPublicPoint);
            using MacSalt macSalt = MacSalt.FromCanonical(salt, Pool);
            using SharedInfo info = SharedInfo.FromCanonical(sharedInfo, Pool);
            using MacKey derived = EcdhMacAlgorithm.DeriveMacKey(key, peer, macSalt, info, keyDerivation, g1ScalarMultiply, macKey.Length, Pool);
            derived.AsReadOnlySpan().CopyTo(macKey);
        }
        catch
        {
            macKey.Clear();
            throw;
        }
    }


    /// <summary>The typed MAC generation.</summary>
    public static void Sign(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> verifierEphemeralPublicKey,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> mac)
    {
        try
        {
            RequireTagLength(mac);
            using PrivateScalar key = PrivateScalar.FromCanonical(privateKey, Pool);
            using G1Point verifier = Point(verifierEphemeralPublicKey);
            using MacSalt macSalt = MacSalt.FromCanonical(salt, Pool);
            using SharedInfo info = SharedInfo.FromCanonical(sharedInfo, Pool);
            using MacTag tag = EcdhMacAlgorithm.Sign(key, verifier, macSalt, info, message, keyDerivation, hmac, g1ScalarMultiply, Pool);
            tag.AsReadOnlySpan().CopyTo(mac);
        }
        catch
        {
            mac.Clear();
            throw;
        }
    }


    /// <summary>The typed MAC verification by the holder of the ephemeral private key.</summary>
    public static bool Verify(
        ReadOnlySpan<byte> proverPublicKey,
        ReadOnlySpan<byte> verifierEphemeralPrivateKey,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> mac,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac,
        G1ScalarMultiplyDelegate g1ScalarMultiply)
    {
        using G1Point prover = Point(proverPublicKey);
        using PrivateScalar key = PrivateScalar.FromCanonical(verifierEphemeralPrivateKey, Pool);
        using MacSalt macSalt = MacSalt.FromCanonical(salt, Pool);
        using SharedInfo info = SharedInfo.FromCanonical(sharedInfo, Pool);
        if(mac.Length != MacTag.SizeBytes)
        {
            //A tag of the wrong length cannot be a valid tag, so the wire value is rejected before a typed tag exists.
            return false;
        }

        using MacTag tag = MacTag.FromCanonical(mac, Pool);

        return EcdhMacAlgorithm.Verify(prover, key, macSalt, info, message, tag, keyDerivation, hmac, g1ScalarMultiply);
    }


    /// <summary>The typed key-share signature.</summary>
    public static void SplitSign(
        ReadOnlySpan<byte> walletKeyShare,
        ReadOnlySpan<byte> wscaKeyShare,
        ReadOnlySpan<byte> baseKey,
        ReadOnlySpan<byte> verifierEphemeralPublicKey,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        Span<byte> mac)
    {
        try
        {
            RequireTagLength(mac);
            using PrivateScalar wallet = PrivateScalar.FromCanonical(walletKeyShare, Pool);
            using PrivateScalar wsca = PrivateScalar.FromCanonical(wscaKeyShare, Pool);
            using PrivateScalar baseScalar = PrivateScalar.FromCanonical(baseKey, Pool);
            using G1Point verifier = Point(verifierEphemeralPublicKey);
            using MacSalt macSalt = MacSalt.FromCanonical(salt, Pool);
            using SharedInfo info = SharedInfo.FromCanonical(sharedInfo, Pool);
            using MacTag tag = EcdhMacAlgorithm.SplitSign(wallet, wsca, baseScalar, verifier, macSalt, info, message, keyDerivation, hmac, g1ScalarMultiply, Pool);
            tag.AsReadOnlySpan().CopyTo(mac);
        }
        catch
        {
            mac.Clear();
            throw;
        }
    }


    /// <summary>The typed validation of the peer point.</summary>
    public static void PrepareKeyAgreement(ReadOnlySpan<byte> peerPublicPoint, G1ScalarMultiplyDelegate g1ScalarMultiply, Span<byte> keyHolderInput)
    {
        try
        {
            using G1Point peer = Point(peerPublicPoint);
            using G1Point validated = EcdhMacAlgorithm.PrepareKeyAgreement(peer, g1ScalarMultiply, Pool);
            validated.AsReadOnlySpan().CopyTo(keyHolderInput);
        }
        catch
        {
            keyHolderInput.Clear();
            throw;
        }
    }


    /// <summary>The typed key-share application.</summary>
    public static void ApplyKeyShare(ReadOnlySpan<byte> keyShare, ReadOnlySpan<byte> point, G1ScalarMultiplyDelegate g1ScalarMultiply, Span<byte> result)
    {
        try
        {
            using PrivateScalar share = PrivateScalar.FromCanonical(keyShare, Pool);
            using G1Point input = Point(point);
            using G1Point product = EcdhMacAlgorithm.ApplyKeyShare(share, input, g1ScalarMultiply, Pool);
            product.AsReadOnlySpan().CopyTo(result);
        }
        catch
        {
            result.Clear();
            throw;
        }
    }


    /// <summary>The typed key derivation from a shared secret.</summary>
    public static void DeriveMacKeyFromSharedSecret(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> sharedInfo,
        EcdhMacKeyDerivationDelegate keyDerivation,
        Span<byte> macKey)
    {
        try
        {
            using MacSalt macSalt = MacSalt.FromCanonical(salt, Pool);
            using SharedSecret secret = SharedSecret.FromCanonical(sharedSecret, Pool);
            using SharedInfo info = SharedInfo.FromCanonical(sharedInfo, Pool);
            using MacKey derived = EcdhMacAlgorithm.DeriveMacKeyFromSharedSecret(macSalt, secret, info, keyDerivation, macKey.Length, Pool);
            derived.AsReadOnlySpan().CopyTo(macKey);
        }
        catch
        {
            macKey.Clear();
            throw;
        }
    }


    /// <summary>The typed completion of the signature from a shared secret.</summary>
    public static void CompleteSign(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac,
        Span<byte> mac)
    {
        try
        {
            RequireTagLength(mac);
            using MacSalt macSalt = MacSalt.FromCanonical(salt, Pool);
            using SharedSecret secret = SharedSecret.FromCanonical(sharedSecret, Pool);
            using SharedInfo info = SharedInfo.FromCanonical(sharedInfo, Pool);
            using MacTag tag = EcdhMacAlgorithm.CompleteSign(macSalt, secret, info, message, keyDerivation, hmac, Pool);
            tag.AsReadOnlySpan().CopyTo(mac);
        }
        catch
        {
            mac.Clear();
            throw;
        }
    }


    /// <summary>The typed completion of the verification from a shared secret.</summary>
    public static bool CompleteVerify(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> sharedInfo,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> mac,
        EcdhMacKeyDerivationDelegate keyDerivation,
        HmacSha256Delegate hmac)
    {
        using MacSalt macSalt = MacSalt.FromCanonical(salt, Pool);
        using SharedSecret secret = SharedSecret.FromCanonical(sharedSecret, Pool);
        using SharedInfo info = SharedInfo.FromCanonical(sharedInfo, Pool);
        if(mac.Length != MacTag.SizeBytes)
        {
            //A tag of the wrong length cannot be a valid tag, so the wire value is rejected before a typed tag exists.
            return false;
        }

        using MacTag tag = MacTag.FromCanonical(mac, Pool);

        return EcdhMacAlgorithm.CompleteVerify(macSalt, secret, info, message, tag, keyDerivation, hmac);
    }


    /// <summary>The typed tag check under a MAC key.</summary>
    public static bool VerifyMac(ReadOnlySpan<byte> macKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac, HmacSha256Delegate hmac)
    {
        using MacKey key = MacKey.FromCanonical(macKey, Pool);
        if(mac.Length != MacTag.SizeBytes)
        {
            //A tag of the wrong length cannot be a valid tag, so the wire value is rejected before a typed tag exists.
            return false;
        }

        using MacTag tag = MacTag.FromCanonical(mac, Pool);

        return EcdhMacAlgorithm.VerifyMac(key, message, tag, hmac);
    }


    private static void RequireTagLength(ReadOnlySpan<byte> mac)
    {
        if(mac.Length != MacTag.SizeBytes)
        {
            throw new ArgumentException($"A MAC tag is {MacTag.SizeBytes} bytes; the destination is {mac.Length}.", nameof(mac));
        }
    }
}
