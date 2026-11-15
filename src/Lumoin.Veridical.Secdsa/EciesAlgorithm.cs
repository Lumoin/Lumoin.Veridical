using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Security.Cryptography;
using static Lumoin.Veridical.Secdsa.P256PointValidation;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The Elliptic Curve Integrated Encryption Scheme over NIST P-256 as Verheul's Annex A.4 specifies it
/// (Algorithm 18, encryption, and Algorithm 19, decryption): an ephemeral Diffie-Hellman exchange with the
/// recipient's public key, a key derivation <c>K = KDF(Z_AB, A)</c> over the shared secret, and authenticated
/// encryption <c>(C, T) = ENC[K, P, A]</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Delegates, not choices.</b> The key derivation, the authenticated encryption, the entropy for the ephemeral
/// key and all group arithmetic enter as named delegates; the split of the derived key material into key and IV,
/// the tag length and the role of <c>A</c> in the derivation are the <see cref="EciesParameterSet"/> the caller
/// passes. <see cref="EciesParameterSet.X963Sha256Aes256Gcm"/> is the set the paper describes as typical, with
/// <see cref="X963KeyDerivation"/> as its derivation.
/// </para>
/// <para>
/// <b>Phases.</b> The decryption is one operation when the private scalar is in software
/// (<see cref="TryDecrypt"/>) and three when it lives in an HSM, a TPM or a cloud KMS: <see cref="PrepareDecryption"/>
/// validates <c>E</c> and yields the value for the key holder; the key holder performs the raw agreement and returns
/// the shared secret <c>Z_AB</c> (a PKCS#11 <c>CKM_ECDH1_DERIVE</c> without a derivation function) or the derived
/// key material; <see cref="TryCompleteDecryption(SharedSecret, EciesCiphertext, AdditionalData, EciesParameterSet, EciesKeyDerivationDelegate, AeadDecryptDelegate, BaseMemoryPool, out EciesPlaintext)"/>
/// derives the key where needed and decrypts. The software path runs exactly the same phases, so the two give
/// byte-identical results. If the key holder performs the whole decryption inside the HSM, the library has
/// nothing to do: the plaintext comes back from the HSM.
/// </para>
/// <para>
/// <b>Authentication failure.</b> A decryption that fails authentication returns <see langword="false"/> and no
/// plaintext; the buffer the plaintext would have occupied is cleared before it is returned to the pool. A
/// plaintext is released only after the tag verified, so a party that feeds the decryption data it did not
/// legitimately obtain learns nothing from it.
/// </para>
/// <para>
/// <b>Secrets.</b> The ephemeral scalar, the shared point, the shared secret and the derived key material are
/// cleared before the operation returns. The ciphertext is public; the caller authenticates the additional data
/// and the recipient key.
/// </para>
/// </remarks>
public static class EciesAlgorithm
{
    /// <summary>The P-256 scalar octet length.</summary>
    public const int ScalarSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The P-256 SEC1 compressed point length.</summary>
    public const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.P256;


    /// <summary>
    /// Algorithm 18, ECIES encryption: generates an ephemeral key pair, agrees a shared secret with the
    /// recipient's public key, derives the key material and encrypts the plaintext.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Step 1 samples <c>e ∈ [1, n−1]</c> from <paramref name="entropy"/> by rejection (no bias) and computes
    /// <c>E = e·G</c>; step 2 computes <c>S = e·D</c> and takes its x-coordinate as <c>Z_AB</c>; step 3 derives
    /// <c>K = KDF(Z_AB, A)</c>; step 4 forms <c>(C, T) = ENC[K, P, A]</c>; step 5 clears <c>e</c> and <c>K</c>.
    /// </para>
    /// <para>
    /// The recipient key <paramref name="recipientPublicKey"/> and <paramref name="associatedData"/> are the
    /// sender's own inputs: the caller authenticates that the key is the intended recipient's. A key that is not a
    /// canonical finite on-curve point is a caller error and throws.
    /// </para>
    /// </remarks>
    /// <param name="plaintext">The plaintext <c>P</c>; secret.</param>
    /// <param name="associatedData">The additional authenticated data <c>A</c>; authenticated, not encrypted.</param>
    /// <param name="recipientPublicKey">The recipient's public key <c>D = d·G</c>.</param>
    /// <param name="parameters">The ECIES parameter set.</param>
    /// <param name="entropy">The entropy source for the ephemeral scalar.</param>
    /// <param name="keyDerivation">The key derivation <c>KDF(Z_AB, A)</c>.</param>
    /// <param name="aeadEncrypt">The authenticated encryption <c>ENC[K, P, A]</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="pool">The pool the ciphertext and the secret intermediates are rented from.</param>
    /// <param name="tag">An optional tag carrying provenance entries for the ciphertext.</param>
    /// <returns>The ciphertext <c>(E, C, T)</c>, owned by the caller.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="parameters"/> is invalid or <paramref name="recipientPublicKey"/> is not a canonical finite on-curve point.</exception>
    /// <exception cref="InvalidOperationException">When the entropy source fails to produce an in-range scalar, or the shared point is the point at infinity.</exception>
    public static EciesCiphertext Encrypt(
        EciesPlaintext plaintext,
        AdditionalData associatedData,
        G1Point recipientPublicKey,
        EciesParameterSet parameters,
        SecdsaEntropySource entropy,
        EciesKeyDerivationDelegate keyDerivation,
        AeadEncryptDelegate aeadEncrypt,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(associatedData);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentNullException.ThrowIfNull(entropy);
        ArgumentNullException.ThrowIfNull(keyDerivation);
        ArgumentNullException.ThrowIfNull(aeadEncrypt);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);
        parameters.Validate();

        Span<byte> recipient = stackalloc byte[CompressedPointSizeBytes];
        ValidateCanonical(recipientPublicKey.AsReadOnlySpan(), g1ScalarMultiply, recipient, nameof(recipientPublicKey));

        Span<byte> ephemeralScalar = stackalloc byte[ScalarSizeBytes];
        Span<byte> ephemeralPublicKey = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            //Step 1: e random in [1, n-1], E = e·G.
            P256ScalarSampling.Sample(entropy, ephemeralScalar);
            Span<byte> generator = stackalloc byte[CompressedPointSizeBytes];
            WellKnownCurves.GetG1GeneratorCompressed(Curve).CopyTo(generator);
            g1ScalarMultiply(generator, ephemeralScalar, ephemeralPublicKey, Curve);

            //Steps 2 to 4: S = e·D, Z_AB, K = KDF(Z_AB, A), (C, T) = ENC[K, P, A].
            using SharedSecret sharedSecret = ComputeSharedSecret(ephemeralScalar, recipient, g1ScalarMultiply, pool);

            return Seal(ephemeralPublicKey, sharedSecret, plaintext, associatedData, parameters, keyDerivation, aeadEncrypt, pool, tag);
        }
        finally
        {
            //Step 5: delete e; K is cleared when its owner is disposed in the seal.
            ephemeralScalar.Clear();
        }
    }


    /// <summary>
    /// Algorithm 18 steps 3 and 4 for an ephemeral public key and shared secret that the caller already holds:
    /// derives <c>K = KDF(Z_AB, A)</c> and forms <c>(C, T) = ENC[K, P, A]</c>. The transferable proof uses it with an
    /// ephemeral key that is a sum of derived keys instead of one random scalar.
    /// </summary>
    /// <param name="ephemeralPublicKey">The compressed ephemeral public key <c>E</c> placed in the ciphertext.</param>
    /// <param name="sharedSecret">The shared secret <c>Z_AB</c>; secret.</param>
    /// <param name="plaintext">The plaintext <c>P</c>; secret.</param>
    /// <param name="associatedData">The additional authenticated data <c>A</c>.</param>
    /// <param name="parameters">The ECIES parameter set.</param>
    /// <param name="keyDerivation">The key derivation.</param>
    /// <param name="aeadEncrypt">The authenticated encryption.</param>
    /// <param name="pool">The pool the ciphertext and key material are rented from.</param>
    /// <param name="tag">An optional tag carrying provenance entries for the ciphertext.</param>
    /// <returns>The ciphertext, owned by the caller.</returns>
    internal static EciesCiphertext Seal(
        ReadOnlySpan<byte> ephemeralPublicKey,
        SharedSecret sharedSecret,
        EciesPlaintext plaintext,
        AdditionalData associatedData,
        EciesParameterSet parameters,
        EciesKeyDerivationDelegate keyDerivation,
        AeadEncryptDelegate aeadEncrypt,
        BaseMemoryPool pool,
        Tag? tag)
    {
        ReadOnlySpan<byte> plain = plaintext.GetBytes();
        using DerivedKeyMaterial keyMaterial = DeriveKeyMaterial(sharedSecret, associatedData, parameters, keyDerivation, pool);
        IMemoryOwner<byte> owner = pool.Rent(CompressedPointSizeBytes + parameters.TagSizeBytes + plain.Length);
        bool completed = false;
        try
        {
            Span<byte> destination = owner.Memory.Span;
            ephemeralPublicKey.CopyTo(destination);
            Span<byte> authenticationTag = destination.Slice(EciesCiphertext.TagOffset, parameters.TagSizeBytes);
            Span<byte> encrypted = destination[(EciesCiphertext.TagOffset + parameters.TagSizeBytes)..];
            aeadEncrypt(keyMaterial.GetKeyBytes(), keyMaterial.GetIvBytes(), plain, associatedData.GetBytes(), encrypted, authenticationTag);
            completed = true;
        }
        finally
        {
            if(!completed)
            {
                owner.Dispose();
            }
        }

        return new EciesCiphertext(owner, EciesCiphertext.TagFor(parameters, tag));
    }


    /// <summary>
    /// The raw Diffie-Hellman agreement of ECIES: <c>S = scalar·point</c> and its x-coordinate <c>Z_AB</c>
    /// (Algorithm 18 step 2, Algorithm 19 step 1). This is the software equivalent of the key holder's
    /// <c>CKM_ECDH1_DERIVE</c> without a derivation function.
    /// </summary>
    /// <remarks>
    /// <paramref name="privateKey"/> is secret and stays with its holder. The peer point is validated here, so a
    /// caller that has not run <see cref="PrepareDecryption"/> is still safe.
    /// </remarks>
    /// <param name="privateKey">The private scalar, 32-byte big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="peerPoint">The peer's point, such as the ephemeral public key <c>E</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="pool">The pool the shared secret is rented from.</param>
    /// <returns>The shared secret <c>Z_AB</c>, owned by the caller.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="privateKey"/> is out of range or <paramref name="peerPoint"/> is not a canonical finite point.</exception>
    /// <exception cref="InvalidOperationException">When <paramref name="peerPoint"/> is not on the curve or the shared point is the point at infinity.</exception>
    public static SharedSecret AgreeSharedSecret(
        ReadOnlySpan<byte> privateKey,
        G1Point peerPoint,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(peerPoint);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);
        RequireLength(privateKey, ScalarSizeBytes, nameof(privateKey));
        RequireScalarInRange(privateKey, nameof(privateKey));

        Span<byte> peer = stackalloc byte[CompressedPointSizeBytes];
        ValidateCanonical(peerPoint.AsReadOnlySpan(), g1ScalarMultiply, peer, nameof(peerPoint));

        return ComputeSharedSecret(privateKey, peer, g1ScalarMultiply, pool);
    }


    /// <summary>
    /// Decryption phase one (Algorithm 19 before step 1): validates the ephemeral public key <c>E</c> of a
    /// ciphertext, the only part of the decryption that arrives from the counterparty, and yields the value to
    /// hand to the key holder. The validation is the one <see cref="EcdhMacAlgorithm.PrepareKeyAgreement"/> applies:
    /// length, not infinity, on the curve through the group delegate's decode contract, and canonical encoding.
    /// </summary>
    /// <remarks>
    /// <c>E</c> is public. A ciphertext whose <c>E</c> is rejected must be rejected by the caller, as the paper
    /// stops the protocol on error. The key holder's result is checked only by the tag in the completion phase.
    /// </remarks>
    /// <param name="ciphertext">The ciphertext.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication, whose decode contract rejects off-curve points.</param>
    /// <param name="pool">The pool the point is rented from.</param>
    /// <returns>The validated, canonical ephemeral public key, owned by the caller.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <c>E</c> encodes infinity or is not the canonical encoding of a finite point.</exception>
    /// <exception cref="InvalidOperationException">When <c>E</c> is not on the curve.</exception>
    public static G1Point PrepareDecryption(
        EciesCiphertext ciphertext,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        Span<byte> keyHolderInput = stackalloc byte[CompressedPointSizeBytes];
        ValidateCanonical(ciphertext.GetEphemeralPublicKeyBytes(), g1ScalarMultiply, keyHolderInput, nameof(ciphertext));

        return G1Point.FromCanonical(keyHolderInput, Curve, pool);
    }


    /// <summary>
    /// Derives the key material <c>K = KDF(Z_AB, A)</c> (Algorithm 18 step 3, Algorithm 19 step 2). The shared data
    /// the derivation receives is <c>A</c> when the parameter set says so and empty otherwise.
    /// </summary>
    /// <param name="sharedSecret">The shared secret <c>Z_AB</c>; secret.</param>
    /// <param name="associatedData">The additional authenticated data <c>A</c>.</param>
    /// <param name="parameters">The ECIES parameter set.</param>
    /// <param name="keyDerivation">The key derivation.</param>
    /// <param name="pool">The pool the key material is rented from.</param>
    /// <returns>The key material, owned by the caller, who disposes it to delete <c>K</c>.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="parameters"/> is invalid.</exception>
    public static DerivedKeyMaterial DeriveKeyMaterial(
        SharedSecret sharedSecret,
        AdditionalData associatedData,
        EciesParameterSet parameters,
        EciesKeyDerivationDelegate keyDerivation,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);
        ArgumentNullException.ThrowIfNull(associatedData);
        ArgumentNullException.ThrowIfNull(keyDerivation);
        ArgumentNullException.ThrowIfNull(pool);
        parameters.Validate();

        IMemoryOwner<byte> owner = pool.Rent(parameters.KeyMaterialSizeBytes);
        try
        {
            ReadOnlySpan<byte> sharedData = parameters.AssociatedDataIsKdfSharedData ? associatedData.GetBytes() : ReadOnlySpan<byte>.Empty;
            keyDerivation(sharedSecret.AsReadOnlySpan(), sharedData, owner.Memory.Span);
        }
        catch
        {
            owner.Dispose();

            throw;
        }

        return new DerivedKeyMaterial(owner, DerivedKeyMaterial.TagFor(parameters, null));
    }


    /// <summary>
    /// Decryption phase two from the key holder's shared secret (Algorithm 19 steps 2 and 3): derives
    /// <c>K = KDF(Z_AB, A)</c> and authenticated-decrypts. The derived key is cleared before return.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Failure.</b> A ciphertext made under another parameter set, a wrong shared secret, a tampered
    /// ciphertext, tag or additional data all return <see langword="false"/> with no plaintext; the plaintext
    /// buffer is cleared before it is released. The key holder is trusted with the private scalar, so an incorrect
    /// <c>Z_AB</c> is detected only as this failure.
    /// </para>
    /// <para>
    /// The ciphertext and <paramref name="associatedData"/> come from the counterparty; the caller authenticates
    /// the additional data's meaning.
    /// </para>
    /// </remarks>
    /// <param name="sharedSecret">The shared secret <c>Z_AB</c> the key holder returned; secret.</param>
    /// <param name="ciphertext">The ciphertext <c>(E, C, T)</c>.</param>
    /// <param name="associatedData">The additional authenticated data <c>A</c>.</param>
    /// <param name="parameters">The ECIES parameter set.</param>
    /// <param name="keyDerivation">The key derivation.</param>
    /// <param name="aeadDecrypt">The authenticated decryption.</param>
    /// <param name="pool">The pool the plaintext and key material are rented from.</param>
    /// <param name="plaintext">Receives the plaintext, owned by the caller, only when the function returns <see langword="true"/>; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the tag verified and the plaintext was released.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="parameters"/> is invalid.</exception>
    public static bool TryCompleteDecryption(
        SharedSecret sharedSecret,
        EciesCiphertext ciphertext,
        AdditionalData associatedData,
        EciesParameterSet parameters,
        EciesKeyDerivationDelegate keyDerivation,
        AeadDecryptDelegate aeadDecrypt,
        BaseMemoryPool pool,
        out EciesPlaintext? plaintext)
    {
        using DerivedKeyMaterial keyMaterial = DeriveKeyMaterial(sharedSecret, associatedData, parameters, keyDerivation, pool);

        return TryCompleteDecryption(keyMaterial, ciphertext, associatedData, parameters, aeadDecrypt, pool, out plaintext);
    }


    /// <summary>
    /// Decryption phase two from key material the key holder derived itself (Algorithm 19 step 3), as a PKCS#11
    /// <c>CKM_ECDH1_DERIVE</c> with a derivation function returns it: authenticated-decrypts under the supplied
    /// key and IV. The caller disposes the key material, which deletes <c>K</c>.
    /// </summary>
    /// <remarks>See the shared-secret overload for the failure behaviour.</remarks>
    /// <param name="keyMaterial">The key material the key holder derived; secret.</param>
    /// <param name="ciphertext">The ciphertext <c>(E, C, T)</c>.</param>
    /// <param name="associatedData">The additional authenticated data <c>A</c>.</param>
    /// <param name="parameters">The ECIES parameter set, which must equal the one the key material and the ciphertext were made under.</param>
    /// <param name="aeadDecrypt">The authenticated decryption.</param>
    /// <param name="pool">The pool the plaintext is rented from.</param>
    /// <param name="plaintext">Receives the plaintext, owned by the caller, only when the function returns <see langword="true"/>; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the tag verified and the plaintext was released.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="parameters"/> is invalid.</exception>
    public static bool TryCompleteDecryption(
        DerivedKeyMaterial keyMaterial,
        EciesCiphertext ciphertext,
        AdditionalData associatedData,
        EciesParameterSet parameters,
        AeadDecryptDelegate aeadDecrypt,
        BaseMemoryPool pool,
        out EciesPlaintext? plaintext)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(associatedData);
        ArgumentNullException.ThrowIfNull(aeadDecrypt);
        ArgumentNullException.ThrowIfNull(pool);
        parameters.Validate();

        plaintext = null;

        //A ciphertext or key material made under another parameter set is rejected: its field sizes are not ours.
        if(ciphertext.Parameters != parameters || keyMaterial.Parameters != parameters)
        {
            return false;
        }

        ReadOnlySpan<byte> encrypted = ciphertext.GetEncryptedBytes();
        IMemoryOwner<byte> owner = SecdsaMemory.Rent(encrypted.Length, pool);
        bool released = false;
        try
        {
            bool authentic;
            try
            {
                authentic = aeadDecrypt(
                    keyMaterial.GetKeyBytes(), keyMaterial.GetIvBytes(), encrypted,
                    ciphertext.GetAuthenticationTagBytes(), associatedData.GetBytes(), owner.Memory.Span);
            }
            catch(CryptographicException)
            {
                //A platform cipher may report an authentication failure by exception; it is the same expected outcome.
                authentic = false;
            }

            if(!authentic)
            {
                return false;
            }

            plaintext = new EciesPlaintext(owner, Tag.Empty);
            released = true;

            return true;
        }
        finally
        {
            if(!released)
            {
                //No plaintext is returned on failure: clear the buffer before the pool takes it back.
                owner.Memory.Span.Clear();
                owner.Dispose();
            }
        }
    }


    /// <summary>
    /// The all-software ECIES decryption (Algorithm 19): runs the same phases a key holder in an HSM would, with
    /// the private scalar in this process. Validates <c>E</c>, computes <c>S = d·E</c> and <c>Z_AB</c>, derives the
    /// key and authenticated-decrypts, returning no plaintext on a tag failure.
    /// </summary>
    /// <remarks>
    /// A ciphertext whose ephemeral key is malformed, off the curve or at infinity comes from the counterparty and
    /// returns <see langword="false"/>; a private key out of range is the caller's and throws.
    /// </remarks>
    /// <param name="privateKey">The recipient's private scalar <c>d</c>, 32-byte big-endian, in <c>[1, n−1]</c>; secret.</param>
    /// <param name="ciphertext">The ciphertext <c>(E, C, T)</c>.</param>
    /// <param name="associatedData">The additional authenticated data <c>A</c>.</param>
    /// <param name="parameters">The ECIES parameter set.</param>
    /// <param name="keyDerivation">The key derivation.</param>
    /// <param name="aeadDecrypt">The authenticated decryption.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="pool">The pool the intermediates and the plaintext are rented from.</param>
    /// <param name="plaintext">Receives the plaintext, owned by the caller, only when the function returns <see langword="true"/>; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the tag verified and the plaintext was released.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="privateKey"/> is out of range or <paramref name="parameters"/> is invalid.</exception>
    public static bool TryDecrypt(
        ReadOnlySpan<byte> privateKey,
        EciesCiphertext ciphertext,
        AdditionalData associatedData,
        EciesParameterSet parameters,
        EciesKeyDerivationDelegate keyDerivation,
        AeadDecryptDelegate aeadDecrypt,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool,
        out EciesPlaintext? plaintext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        RequireLength(privateKey, ScalarSizeBytes, nameof(privateKey));
        RequireScalarInRange(privateKey, nameof(privateKey));

        plaintext = null;
        G1Point ephemeralPublicKey;
        try
        {
            ephemeralPublicKey = PrepareDecryption(ciphertext, g1ScalarMultiply, pool);
        }
        catch(ArgumentException)
        {
            return false;
        }
        catch(InvalidOperationException)
        {
            return false;
        }

        using(ephemeralPublicKey)
        {
            using SharedSecret sharedSecret = AgreeSharedSecret(privateKey, ephemeralPublicKey, g1ScalarMultiply, pool);

            return TryCompleteDecryption(sharedSecret, ciphertext, associatedData, parameters, keyDerivation, aeadDecrypt, pool, out plaintext);
        }
    }


    /// <summary>Computes <c>S = scalar·point</c> for an already validated point and wraps its x-coordinate as the shared secret.</summary>
    private static SharedSecret ComputeSharedSecret(
        ReadOnlySpan<byte> scalar,
        ReadOnlySpan<byte> validatedPoint,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool)
    {
        //S_AB is THE Diffie-Hellman secret; cleared in a finally so a throw cannot leave it on the stack.
        Span<byte> sharedPoint = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            g1ScalarMultiply(validatedPoint, scalar, sharedPoint, Curve);
            if(sharedPoint[0] == 0x00)
            {
                throw new InvalidOperationException("The Diffie-Hellman shared point is the point at infinity; the private key or peer point is degenerate.");
            }

            //Z_AB is the x-coordinate: the compressed encoding's trailing 32 bytes.
            return SharedSecret.FromCanonical(sharedPoint[1..], pool);
        }
        finally
        {
            sharedPoint.Clear();
        }
    }
}
