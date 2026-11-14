using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;

namespace Lumoin.Veridical.Tests.Wasm;

/// <summary>
/// The bindings to <c>wwwroot/platform-crypto.mjs</c>, which <c>main.mjs</c> registers as the
/// module <c>platform-crypto</c> before the tests run. Every call is synchronous and crosses the
/// interop boundary as byte arrays, so the marshalling copies stay inside this class and its
/// callers in <see cref="NodeCryptoProviders"/>.
/// </summary>
[SupportedOSPlatform("browser")]
internal static partial class NodeCryptoInterop
{
    /// <summary>The name <c>main.mjs</c> registers the module under.</summary>
    private const string ModuleName = "platform-crypto";


    /// <summary>Encrypts one block with AES in ECB mode and no padding.</summary>
    /// <param name="key">The 16, 24 or 32-byte key.</param>
    /// <param name="input">The block to encrypt.</param>
    /// <returns>The ciphertext block.</returns>
    [JSImport("aesEncryptBlock", ModuleName)]
    internal static partial byte[] AesEncryptBlock(byte[] key, byte[] input);


    /// <summary>Generates a P-256 key pair.</summary>
    /// <returns>The private scalar, the x-coordinate and the y-coordinate, 32 bytes each, concatenated.</returns>
    [JSImport("p256Generate", ModuleName)]
    internal static partial byte[] P256Generate();


    /// <summary>Signs a message with ECDSA over P-256 and SHA-256.</summary>
    /// <param name="privateKey">The private scalar.</param>
    /// <param name="publicX">The public x-coordinate.</param>
    /// <param name="publicY">The public y-coordinate.</param>
    /// <param name="message">The message to hash and sign.</param>
    /// <returns>The IEEE P1363 signature.</returns>
    [JSImport("p256Sign", ModuleName)]
    internal static partial byte[] P256Sign(byte[] privateKey, byte[] publicX, byte[] publicY, byte[] message);


    /// <summary>Verifies an IEEE P1363 signature over the SHA-256 of a message.</summary>
    /// <param name="publicX">The public x-coordinate.</param>
    /// <param name="publicY">The public y-coordinate.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="signature">The signature.</param>
    /// <returns><see langword="true"/> when the signature is valid.</returns>
    [JSImport("p256Verify", ModuleName)]
    internal static partial bool P256Verify(byte[] publicX, byte[] publicY, byte[] message, byte[] signature);


    /// <summary>Verifies an IEEE P1363 signature over a digest the caller computed.</summary>
    /// <param name="publicX">The public x-coordinate.</param>
    /// <param name="publicY">The public y-coordinate.</param>
    /// <param name="digest">The signed digest.</param>
    /// <param name="signature">The signature.</param>
    /// <returns><see langword="true"/> when the signature is valid.</returns>
    [JSImport("p256VerifyDigest", ModuleName)]
    internal static partial bool P256VerifyDigest(byte[] publicX, byte[] publicY, byte[] digest, byte[] signature);


    /// <summary>Computes the raw ECDH shared secret over P-256.</summary>
    /// <param name="privateKey">The own private scalar.</param>
    /// <param name="peerX">The peer's public x-coordinate.</param>
    /// <param name="peerY">The peer's public y-coordinate.</param>
    /// <returns>The 32-byte shared secret.</returns>
    [JSImport("p256Agree", ModuleName)]
    internal static partial byte[] P256Agree(byte[] privateKey, byte[] peerX, byte[] peerY);


    /// <summary>Reads the public key of a DER X.509 certificate.</summary>
    /// <param name="certificate">The DER certificate.</param>
    /// <returns>The x-coordinate followed by the y-coordinate when the key is a P-256 key; an empty array otherwise.</returns>
    [JSImport("certificatePublicKey", ModuleName)]
    internal static partial byte[] CertificatePublicKey(byte[] certificate);
}
