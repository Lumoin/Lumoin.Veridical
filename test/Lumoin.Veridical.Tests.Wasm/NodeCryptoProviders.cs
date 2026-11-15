using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Lumoin.Veridical.Tests.TestInfrastructure;

namespace Lumoin.Veridical.Tests.Wasm;

/// <summary>
/// Replaces the providers of <see cref="TestPlatformCrypto"/> with ones backed by Node's crypto
/// module, because the browser-wasm runtime has no implementation of the .NET cryptography
/// classes the tests use as oracles. The bindings live in the host rather than in the test
/// assembly so the native test project carries no browser-only code, no interop source
/// generation and no platform-compatibility attributes.
/// </summary>
[SupportedOSPlatform("browser")]
internal static class NodeCryptoProviders
{
    /// <summary>Installs the Node-backed providers; call once, before any test runs.</summary>
    public static void Register()
    {
        TestPlatformCrypto.AesEncryptBlock = EncryptBlock;
        TestPlatformCrypto.AesGcmEncrypt = EncryptGcm;
        TestPlatformCrypto.AesGcmDecrypt = DecryptGcm;
        TestPlatformCrypto.GenerateP256Key = GenerateKey;
        TestPlatformCrypto.SignP256 = Sign;
        TestPlatformCrypto.VerifyP256 = Verify;
        TestPlatformCrypto.VerifyP256Digest = VerifyDigest;
        TestPlatformCrypto.AgreeP256 = Agree;
        TestPlatformCrypto.ReadCertificatePublicKey = ReadCertificate;
    }


    private static void EncryptBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        NodeCryptoInterop.AesEncryptBlock(key.ToArray(), input.ToArray()).CopyTo(output);
    }


    private static void EncryptGcm(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> ciphertext,
        Span<byte> tag)
    {
        byte[] sealedBytes = NodeCryptoInterop.AesGcmEncrypt(key.ToArray(), iv.ToArray(), plaintext.ToArray(), associatedData.ToArray(), tag.Length);
        sealedBytes.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
        sealedBytes.AsSpan(plaintext.Length).CopyTo(tag);
    }


    private static bool DecryptGcm(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintext)
    {
        byte[] opened = NodeCryptoInterop.AesGcmDecrypt(key.ToArray(), iv.ToArray(), ciphertext.ToArray(), tag.ToArray(), associatedData.ToArray());
        if(opened[^1] == 0)
        {
            return false;
        }

        opened.AsSpan(0, opened.Length - 1).CopyTo(plaintext);

        return true;
    }


    private static PlatformP256Key GenerateKey()
    {
        byte[] generated = NodeCryptoInterop.P256Generate();

        return new PlatformP256Key(
            generated[..PlatformP256Key.ComponentSize],
            generated[PlatformP256Key.ComponentSize..(2 * PlatformP256Key.ComponentSize)],
            generated[(2 * PlatformP256Key.ComponentSize)..]);
    }


    private static void Sign(PlatformP256Key key, ReadOnlySpan<byte> message, Span<byte> signature)
    {
        NodeCryptoInterop.P256Sign(key.PrivateKey, key.PublicX, key.PublicY, message.ToArray()).CopyTo(signature);
    }


    private static bool Verify(ReadOnlySpan<byte> publicX, ReadOnlySpan<byte> publicY, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        return NodeCryptoInterop.P256Verify(publicX.ToArray(), publicY.ToArray(), message.ToArray(), signature.ToArray());
    }


    private static bool VerifyDigest(ReadOnlySpan<byte> publicX, ReadOnlySpan<byte> publicY, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        return NodeCryptoInterop.P256VerifyDigest(publicX.ToArray(), publicY.ToArray(), digest.ToArray(), signature.ToArray());
    }


    private static void Agree(PlatformP256Key own, ReadOnlySpan<byte> peerX, ReadOnlySpan<byte> peerY, Span<byte> secret)
    {
        NodeCryptoInterop.P256Agree(own.PrivateKey, peerX.ToArray(), peerY.ToArray()).CopyTo(secret);
    }


    private static bool ReadCertificate(ReadOnlySpan<byte> certificate, Span<byte> publicX, Span<byte> publicY)
    {
        byte[] key;
        try
        {
            key = NodeCryptoInterop.CertificatePublicKey(certificate.ToArray());
        }
        catch(JSException exception)
        {
            throw new CryptographicException("The certificate could not be parsed.", exception);
        }

        if(key.Length == 0)
        {
            return false;
        }

        key.AsSpan(0, PlatformP256Key.ComponentSize).CopyTo(publicX);
        key.AsSpan(PlatformP256Key.ComponentSize).CopyTo(publicY);

        return true;
    }
}
