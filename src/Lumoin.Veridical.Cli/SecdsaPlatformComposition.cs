using Lumoin.Base;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Cryptography;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The SECDSA delegates the tool composes: the managed P-256 scalar and G1 backends, SHA-256 for the
/// Fiat-Shamir hash, HMAC-SHA-256 and HKDF-SHA-256 for the ECDH-MAC, RFC 6979 for the nonce source, the
/// platform's AES-256-GCM and random number generator for ECIES, and ECDSA over P-256 with SHA-256 for the
/// challenger and prover signatures of the transferable proof. The library selects none of these; this type is
/// the one place the tool, as composition root, chooses them.
/// The backends are disposed with the composition.
/// </summary>
internal sealed class SecdsaPlatformComposition: IDisposable
{
    private readonly ScalarArithmeticBackend scalar;
    private readonly G1ArithmeticBackend g1;


    /// <summary>Composes the P-256 backends and the platform hash, MAC and key-derivation delegates.</summary>
    public SecdsaPlatformComposition()
    {
        scalar = P256ManagedScalarBackend.Create();
        g1 = P256ManagedG1Backend.Create();
    }


    /// <summary>The RFC 6979 deterministic nonce source over HMAC-SHA-256.</summary>
    public SecdsaNonceSource NonceSource { get; } = Rfc6979SecdsaNonceSource.Create(Sha256Hmac.Compute);

    /// <summary>The SHA-256 Fiat-Shamir hash.</summary>
    public FiatShamirHashDelegate Hash { get; } = ComputeSha256;

    /// <summary>HKDF-SHA-256 as the ECDH-MAC key derivation of Algorithms 16 and 17.</summary>
    public EcdhMacKeyDerivationDelegate Hkdf { get; } = Sha256Hkdf.DeriveKey;

    /// <summary>HMAC-SHA-256.</summary>
    public HmacSha256Delegate Hmac { get; } = Sha256Hmac.Compute;

    /// <summary>The platform random number generator as the entropy source of ECIES and of the proof seed.</summary>
    public SecdsaEntropySource Entropy { get; } = RandomNumberGenerator.Fill;

    /// <summary>The platform's AES-GCM as the ECIES authenticated encryption.</summary>
    public AeadEncryptDelegate AesGcmEncrypt { get; } = EncryptAesGcm;

    /// <summary>The platform's AES-GCM as the ECIES authenticated decryption.</summary>
    public AeadDecryptDelegate AesGcmDecrypt { get; } = DecryptAesGcm;

    /// <summary>HKDF-SHA-256 with the seed as input keying material and the derivation byte array as info, as the seeded-key derivation of the transferable proof.</summary>
    public SeedKeyDerivationDelegate SeedKeyDerivation { get; } = DeriveSeedKeys;

    /// <summary>Scalar multiplication mod the P-256 order.</summary>
    public ScalarMultiplyDelegate ScalarMultiply => scalar.Multiply;

    /// <summary>Scalar addition mod the P-256 order.</summary>
    public ScalarAddDelegate ScalarAdd => scalar.Add;

    /// <summary>Scalar inversion mod the P-256 order.</summary>
    public ScalarInvertDelegate ScalarInvert => scalar.Invert;

    /// <summary>Reduction mod the P-256 order.</summary>
    public ScalarReduceDelegate ScalarReduce => scalar.Reduce;

    /// <summary>G1 addition.</summary>
    public G1AddDelegate G1Add => g1.Add;

    /// <summary>G1 negation.</summary>
    public G1NegateDelegate G1Negate => g1.Negate;

    /// <summary>G1 scalar multiplication, constant-time.</summary>
    public G1ScalarMultiplyDelegate G1ScalarMultiply => g1.ScalarMultiply;


    /// <summary>The ECIES key derivation: X9.63 over SHA-256, rented from <paramref name="pool"/>.</summary>
    /// <param name="pool">The pool the derivation's scratch buffers are rented from.</param>
    /// <returns>The key derivation delegate.</returns>
    public EciesKeyDerivationDelegate CreateEciesKeyDerivation(BaseMemoryPool pool) => X963KeyDerivation.Create(Hash, pool);


    /// <summary>Signs a transferable-proof structure with ECDSA over P-256 and SHA-256 under an RFC 6979 nonce, writing <c>r || s</c>.</summary>
    /// <param name="privateKey">The signing scalar, 32-byte big-endian.</param>
    /// <param name="structure">The encoded structure.</param>
    /// <param name="signature">Receives the 64-byte signature.</param>
    /// <returns>The number of signature bytes written.</returns>
    public int SignStructure(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> structure, Span<byte> signature)
    {
        Span<byte> digest = stackalloc byte[SecdsaAlgorithm.ScalarSizeBytes];
        Span<byte> nonce = stackalloc byte[SecdsaAlgorithm.ScalarSizeBytes];
        try
        {
            Sha256.HashData(structure, digest);
            NonceSource(CurveParameterSet.P256, privateKey, digest, nonce);
            SecdsaAlgorithm.Sign(
                privateKey, digest, nonce, ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply,
                signature[..SecdsaAlgorithm.ScalarSizeBytes], signature.Slice(SecdsaAlgorithm.ScalarSizeBytes, SecdsaAlgorithm.ScalarSizeBytes));

            return 2 * SecdsaAlgorithm.ScalarSizeBytes;
        }
        finally
        {
            nonce.Clear();
        }
    }


    /// <summary>Verifies an ECDSA <c>r || s</c> signature over a transferable-proof structure.</summary>
    /// <param name="publicKey">The compressed public key.</param>
    /// <param name="structure">The encoded structure.</param>
    /// <param name="signature">The signature; wire data.</param>
    /// <returns><see langword="true"/> when the signature verifies; <see langword="false"/> for any malformed or invalid signature.</returns>
    public bool VerifyStructure(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> structure, ReadOnlySpan<byte> signature)
    {
        if(signature.Length != 2 * SecdsaAlgorithm.ScalarSizeBytes)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[SecdsaAlgorithm.ScalarSizeBytes];
        Sha256.HashData(structure, digest);

        return SecdsaAlgorithm.Verify(
            publicKey, digest, signature[..SecdsaAlgorithm.ScalarSizeBytes], signature[SecdsaAlgorithm.ScalarSizeBytes..],
            ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        scalar.Dispose();
        g1.Dispose();
    }


    private static void EncryptAesGcm(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> ciphertext,
        Span<byte> tag)
    {
        using AesGcm aes = new(key, tag.Length);
        aes.Encrypt(iv, plaintext, ciphertext, tag, associatedData);
    }


    private static bool DecryptAesGcm(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintext)
    {
        using AesGcm aes = new(key, tag.Length);
        try
        {
            aes.Decrypt(iv, ciphertext, tag, plaintext, associatedData);

            return true;
        }
        catch(AuthenticationTagMismatchException)
        {
            return false;
        }
    }


    private static void DeriveSeedKeys(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> derivationInput, Span<byte> output)
    {
        Sha256Hkdf.DeriveKey(ReadOnlySpan<byte>.Empty, masterKey, derivationInput, output);
    }


    private static void ComputeSha256(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        Sha256.HashData(input, output);
    }
}
