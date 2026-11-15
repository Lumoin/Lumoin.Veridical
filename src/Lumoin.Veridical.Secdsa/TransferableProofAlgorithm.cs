using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Security.Cryptography;
using static Lumoin.Veridical.Secdsa.P256PointValidation;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The signed, transferable proof of a discrete-logarithm statement that Verheul's Annex A.5 specifies: the
/// challenge and ECIES-encrypted seed of party <c>T</c> (Algorithm 22), the response of the prover (Algorithm 23) and
/// the verification by a third party (Algorithm 24). The statement is <c>Dᵢ = d·Gᵢ</c> for generators
/// <c>G₀, …, Gₙ</c> and public keys <c>D₀, …, Dₙ</c> with the same <c>d</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Delegates, not choices.</b> The signature schemes of the challenger and the prover, the seed derivation, the
/// ECIES derivation and cipher, the hash and the group arithmetic enter as named delegates; every byte layout comes
/// from a <see cref="SecdsaLayoutProfile"/>, because the paper leaves the byte representation of the signed
/// structures open. The algorithms never concatenate fields themselves.
/// </para>
/// <para>
/// <b>Phases.</b> Algorithm 23 steps 5 to 7 are an ordinary ECIES decryption with the private key <c>d</c> and are the
/// only steps that need it, so they can run in an HSM. The response is therefore three operations:
/// <see cref="TryPrepareResponse"/> (steps 1 to 4 and the validation of <c>E</c>), the key holder's decryption, and
/// <see cref="TryFinishResponse"/> (steps 8 to 15, including the mandatory step 11), or
/// <see cref="TryCompleteResponse"/> when the key holder returns the shared secret <c>Z_AB</c>.
/// <see cref="TryRespond"/> runs the same phases with <c>d</c> in this process, so the two paths give
/// byte-identical responses.
/// </para>
/// <para>
/// <b>Step 11.</b> A successful decryption in step 7 only shows that the challenger knew the key derived from
/// <c>d·E</c>. If a generator is a known multiple of another, <c>G₁ = c·G₀</c>, the challenger knows <c>d·G₁</c> and
/// can form a challenge that decrypts although <c>D₁ ≠ d·G₁</c>. Step 11 therefore decrypts again under the key derived
/// from <c>Σ eᵢ·Dᵢ</c> and requires the same plaintext; it is not optional and is part of every response path.
/// </para>
/// <para>
/// <b>Secrets.</b> The seed, the ephemeral keys, the shared secrets and the derived key material are rented from the
/// supplied pool and cleared before the operations return. The challenge, the response and the statement are public.
/// </para>
/// </remarks>
public static class TransferableProofAlgorithm
{
    /// <summary>
    /// The largest signature, in bytes, a challenge or response carries and a <see cref="StructureSignDelegate"/>
    /// may write. It bounds the buffer rented for signing and the size accepted from the wire.
    /// </summary>
    public const int MaxSignatureSizeBytes = 65536;

    private const int ScalarSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    private const int CompressedPointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.P256;


    /// <summary>
    /// Algorithm 22, challenge and ECIES-encrypted data generation by party <c>T</c>: derives the ephemeral keys
    /// <c>eᵢ</c> from the seed, forms <c>H2 = H(H(e₀ ‖ … ‖ eₙ))</c> and <c>E = Σ eᵢ·Gᵢ</c>, signs the challenge scope and
    /// encrypts <c>Seed ‖ ASD</c> towards <c>E</c> under the key derived from <c>Σ eᵢ·Dᵢ</c>.
    /// </summary>
    /// <remarks>
    /// Step 1 is the caller's: it draws the seed with <see cref="ProofSeed.Generate"/> and passes it in, which keeps
    /// the algorithm deterministic for a given seed. Step 12 deletes the seed: the caller disposes it, which clears
    /// it. The derivation key material is deleted before this method returns. The statement is the challenger's own
    /// input; a point that is not on the curve is a caller error and throws.
    /// </remarks>
    /// <param name="statement">The generators, public keys and additional authenticated data <c>AAD</c>.</param>
    /// <param name="additionalSecretData">The additional secret data <c>ASD</c>, with the <see cref="AdditionalDataRole.Secret"/> role; may be empty.</param>
    /// <param name="seed">The seed <c>Seed</c>.</param>
    /// <param name="profile">The layout profile every structure is encoded with.</param>
    /// <param name="parameters">The ECIES parameter set.</param>
    /// <param name="seedKeyDerivation">The derivation <c>K(Seed, D, |q| + 8)</c>.</param>
    /// <param name="eciesKeyDerivation">The ECIES key derivation <c>KDF(Z_AB, AAD)</c>.</param>
    /// <param name="aeadEncrypt">The ECIES authenticated encryption.</param>
    /// <param name="challengeSign">The challenger's signature with its signing key <c>s</c>.</param>
    /// <param name="hash">The hash function <c>H</c>, SHA-256.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="pool">The pool all values are rented from.</param>
    /// <param name="ciphertext">Receives the ECIES ciphertext <c>(E, C, T)</c>, owned by the caller.</param>
    /// <returns>The challenge <c>Chal(AAD) = (E, H2, AAD, Sig)</c>, owned by the caller.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="parameters"/> is invalid or <paramref name="additionalSecretData"/> does not have the secret role.</exception>
    /// <exception cref="InvalidOperationException">When a statement point is off the curve, <c>E</c> or the shared point is the point at infinity, or the signature delegate reports an unusable length.</exception>
    public static TransferableChallenge Issue(
        ProofStatement statement,
        AdditionalData additionalSecretData,
        ProofSeed seed,
        SecdsaLayoutProfile profile,
        EciesParameterSet parameters,
        SeedKeyDerivationDelegate seedKeyDerivation,
        EciesKeyDerivationDelegate eciesKeyDerivation,
        AeadEncryptDelegate aeadEncrypt,
        StructureSignDelegate challengeSign,
        FiatShamirHashDelegate hash,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        BaseMemoryPool pool,
        out EciesCiphertext ciphertext)
    {
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(additionalSecretData);
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(seedKeyDerivation);
        ArgumentNullException.ThrowIfNull(eciesKeyDerivation);
        ArgumentNullException.ThrowIfNull(aeadEncrypt);
        ArgumentNullException.ThrowIfNull(challengeSign);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(pool);
        parameters.Validate();
        if(additionalSecretData.Role != AdditionalDataRole.Secret)
        {
            throw new ArgumentException("The additional secret data must have the secret role.", nameof(additionalSecretData));
        }

        using IMemoryOwner<byte> keyOwner = pool.Rent(statement.Count * ScalarSizeBytes);
        Span<byte> ephemeral = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> sharedPoint = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            //Step 4: ei = 1 + (K(Seed, [i] || G || D || AAD, |q| + 8) mod (q - 1)).
            DeriveKeys(seed, statement, profile, seedKeyDerivation, pool, keyOwner.Memory.Span);
            using P256ScalarVector keys = P256ScalarVector.FromCanonical(keyOwner.Memory.Span, pool);

            //Steps 6 and 8: E = sum ei·Gi and S_AB = sum ei·Di.
            SumOfProducts(statement.Generators, keys.AsReadOnlySpan(), g1ScalarMultiply, g1Add, ephemeral);
            SumOfProducts(statement.PublicKeys, keys.AsReadOnlySpan(), g1ScalarMultiply, g1Add, sharedPoint);
            if(ephemeral[0] == 0x00 || sharedPoint[0] == 0x00)
            {
                throw new InvalidOperationException("The ephemeral public key or the shared point is the point at infinity; the statement is degenerate.");
            }

            //Step 5: H2 = H(H(e0 || ... || en)).
            using ProofDigest primary = HashScalars(keys, profile, hash, pool);
            using ProofDigest secondary = HashPrimary(primary, hash, pool);

            //Step 7: signature on E || G || D || H2 || AAD, over the profile's byte representation of the structure.
            using G1Point ephemeralPublicKey = G1Point.FromCanonical(ephemeral, Curve, pool);
            using IMemoryOwner<byte> signatureBuffer = pool.Rent(MaxSignatureSizeBytes);
            int signatureLength;
            using(LayoutWriter scope = new(pool))
            {
                profile.EncodeChallengeScope(ephemeralPublicKey, statement, secondary, scope);
                signatureLength = challengeSign(scope.WrittenBytes, signatureBuffer.Memory.Span);
            }

            RequireSignatureLength(signatureLength);

            //Steps 9 to 11: Z_AB, K = KDF(Z_AB, AAD), (C, T) = ENC[K, Seed || ASD, AAD].
            using SharedSecret sharedSecret = SharedSecret.FromCanonical(sharedPoint[1..], pool);
            using EciesPlaintext plaintext = EncodePayload(seed, additionalSecretData, profile, pool);
            EciesCiphertext sealedCiphertext = EciesAlgorithm.Seal(
                ephemeral, sharedSecret, plaintext, statement.AdditionalAuthenticatedData, parameters, eciesKeyDerivation, aeadEncrypt, pool, null);
            try
            {
                //Step 13: Chal(AAD) = (E, H2, AAD, Sig).
                TransferableChallenge challenge = TransferableChallenge.FromParts(
                    ephemeralPublicKey, secondary, statement.AdditionalAuthenticatedData,
                    signatureBuffer.Memory.Span[..signatureLength], profile.Id, pool);
                ciphertext = sealedCiphertext;

                return challenge;
            }
            catch
            {
                sealedCiphertext.Dispose();

                throw;
            }
        }
        finally
        {
            //Step 12: delete the ephemeral material; the keys are cleared when their owners are disposed.
            ephemeral.Clear();
            sharedPoint.Clear();
            keyOwner.Memory.Span.Clear();
        }
    }


    /// <summary>
    /// Algorithm 23 steps 1 to 4, and the validation of <c>E</c> for the key holder: checks that the challenge was
    /// formed under the verifier's layout profile for this statement, verifies the signature <c>Sig</c> of party
    /// <c>T</c> over the challenge scope, and validates the ephemeral public key.
    /// </summary>
    /// <remarks>
    /// The challenge comes from another party and is wire data, so a failure returns <see langword="false"/> and
    /// no point. Steps 5 to 7 follow with the private key, in this process or in an HSM.
    /// </remarks>
    /// <param name="challenge">The challenge <c>Chal(AAD)</c>.</param>
    /// <param name="statement">The prover's statement; its additional authenticated data must equal the challenge's.</param>
    /// <param name="profile">The layout profile the challenge must have been signed under.</param>
    /// <param name="challengeVerify">Verifies <c>Sig</c> under the public key <c>S</c> of party <c>T</c>.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication, whose decode contract rejects off-curve points.</param>
    /// <param name="pool">The pool the point is rented from.</param>
    /// <param name="ephemeralPublicKey">Receives the validated, canonical <c>E</c> to hand to the key holder, owned by the caller, only when the function returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when steps 1 to 4 pass and <c>E</c> is a valid finite point.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static bool TryPrepareResponse(
        TransferableChallenge challenge,
        ProofStatement statement,
        SecdsaLayoutProfile profile,
        StructureVerifyDelegate challengeVerify,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        BaseMemoryPool pool,
        out G1Point? ephemeralPublicKey)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(challengeVerify);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        ephemeralPublicKey = null;
        if(!MatchesStatement(challenge, statement, profile) || !VerifyChallengeSignature(challenge, statement, profile, challengeVerify, pool))
        {
            return false;
        }

        Span<byte> canonical = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            ValidateCanonical(challenge.GetEphemeralPublicKeyBytes(), g1ScalarMultiply, canonical, nameof(challenge));
        }
        catch(ArgumentException)
        {
            return false;
        }
        catch(InvalidOperationException)
        {
            return false;
        }

        ephemeralPublicKey = G1Point.FromCanonical(canonical, Curve, pool);

        return true;
    }


    /// <summary>
    /// Algorithm 23 steps 6 to 15 from the key holder's shared secret: derives <c>K = KDF(Z_AB, AAD)</c>,
    /// decrypts <c>Seed ‖ ASD</c> and finishes the response with <see cref="TryFinishResponse"/>.
    /// </summary>
    /// <remarks>
    /// The challenge signature <c>Sig</c> is verified first (step 4), so no decryption result is used and no response
    /// is signed for an unsigned or foreign challenge. Any failure returns <see langword="false"/> with no response and
    /// no additional secret data.
    /// </remarks>
    /// <param name="sharedSecret">The shared secret <c>Z_AB</c> from <c>d·E</c> that the key holder returned; secret.</param>
    /// <param name="challenge">The challenge.</param>
    /// <param name="ciphertext">The ECIES ciphertext <c>(E, C, T)</c> that accompanies the challenge.</param>
    /// <param name="statement">The prover's statement.</param>
    /// <param name="profile">The layout profile.</param>
    /// <param name="parameters">The ECIES parameter set.</param>
    /// <param name="challengeVerify">Verifies <c>Sig</c> under the public key <c>S</c> of party <c>T</c>.</param>
    /// <param name="seedKeyDerivation">The derivation <c>K(Seed, D, |q| + 8)</c>.</param>
    /// <param name="eciesKeyDerivation">The ECIES key derivation.</param>
    /// <param name="aeadDecrypt">The ECIES authenticated decryption.</param>
    /// <param name="responseSign">The prover's signature with its record signing key <c>v</c>.</param>
    /// <param name="hash">The hash function <c>H</c>, SHA-256.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="pool">The pool all values are rented from.</param>
    /// <param name="response">Receives the response <c>(H1, SigP)</c>, owned by the caller, only when the function returns <see langword="true"/>.</param>
    /// <param name="additionalSecretData">Receives the additional secret data <c>ASD</c>, owned by the caller, only when the function returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when the response was formed.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static bool TryCompleteResponse(
        SharedSecret sharedSecret,
        TransferableChallenge challenge,
        EciesCiphertext ciphertext,
        ProofStatement statement,
        SecdsaLayoutProfile profile,
        EciesParameterSet parameters,
        StructureVerifyDelegate challengeVerify,
        SeedKeyDerivationDelegate seedKeyDerivation,
        EciesKeyDerivationDelegate eciesKeyDerivation,
        AeadDecryptDelegate aeadDecrypt,
        StructureSignDelegate responseSign,
        FiatShamirHashDelegate hash,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        BaseMemoryPool pool,
        out TransferableResponse? response,
        out AdditionalData? additionalSecretData)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(challengeVerify);
        ArgumentNullException.ThrowIfNull(pool);

        response = null;
        additionalSecretData = null;
        if(!MatchesStatement(challenge, statement, profile) || !VerifyChallengeSignature(challenge, statement, profile, challengeVerify, pool))
        {
            return false;
        }

        if(!EciesAlgorithm.TryCompleteDecryption(
            sharedSecret, ciphertext, statement.AdditionalAuthenticatedData, parameters, eciesKeyDerivation, aeadDecrypt, pool, out EciesPlaintext? decrypted))
        {
            return false;
        }

        using(decrypted)
        {
            return FinishVerified(
                decrypted!, challenge, ciphertext, statement, profile, parameters, seedKeyDerivation, eciesKeyDerivation, aeadDecrypt,
                responseSign, hash, g1ScalarMultiply, g1Add, pool, out response, out additionalSecretData);
        }
    }


    /// <summary>
    /// Algorithm 23 steps 8 to 15 from the plaintext of the ECIES decryption (step 7): recomputes the ephemeral keys
    /// from the recovered seed, verifies that they yield <c>E</c> (step 9), repeats the decryption under the key derived
    /// from <c>Σ eᵢ·Dᵢ</c> and requires the same plaintext (steps 10 and 11), forms <c>H1</c>, checks <c>H(H1) = H2</c> and
    /// signs the response scope.
    /// </summary>
    /// <remarks>
    /// This is the entry point for a key holder that performs the whole decryption, <c>CKM_ECDH1_DERIVE</c> and the
    /// authenticated decryption, inside the HSM. Step 11 needs the ciphertext and does not need the HSM, because it
    /// decrypts under the key derived from the public side of the statement; it is mandatory here as on every path.
    /// The challenge signature <c>Sig</c> is verified before the plaintext is used, so an unsigned or foreign
    /// challenge yields no response and no additional secret data.
    /// </remarks>
    /// <param name="decrypted">The plaintext <c>Seed ‖ ASD</c> of step 7; secret.</param>
    /// <param name="challenge">The challenge.</param>
    /// <param name="ciphertext">The ECIES ciphertext that accompanies the challenge.</param>
    /// <param name="statement">The prover's statement.</param>
    /// <param name="profile">The layout profile.</param>
    /// <param name="parameters">The ECIES parameter set.</param>
    /// <param name="challengeVerify">Verifies <c>Sig</c> under the public key <c>S</c> of party <c>T</c>.</param>
    /// <param name="seedKeyDerivation">The derivation <c>K(Seed, D, |q| + 8)</c>.</param>
    /// <param name="eciesKeyDerivation">The ECIES key derivation.</param>
    /// <param name="aeadDecrypt">The ECIES authenticated decryption.</param>
    /// <param name="responseSign">The prover's signature with its record signing key <c>v</c>.</param>
    /// <param name="hash">The hash function <c>H</c>, SHA-256.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="pool">The pool all values are rented from.</param>
    /// <param name="response">Receives the response <c>(H1, SigP)</c>, owned by the caller, only when the function returns <see langword="true"/>.</param>
    /// <param name="additionalSecretData">Receives the additional secret data <c>ASD</c>, owned by the caller, only when the function returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when every check passed and the response was formed.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When the signature delegate reports an unusable length or a statement point is off the curve.</exception>
    public static bool TryFinishResponse(
        EciesPlaintext decrypted,
        TransferableChallenge challenge,
        EciesCiphertext ciphertext,
        ProofStatement statement,
        SecdsaLayoutProfile profile,
        EciesParameterSet parameters,
        StructureVerifyDelegate challengeVerify,
        SeedKeyDerivationDelegate seedKeyDerivation,
        EciesKeyDerivationDelegate eciesKeyDerivation,
        AeadDecryptDelegate aeadDecrypt,
        StructureSignDelegate responseSign,
        FiatShamirHashDelegate hash,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        BaseMemoryPool pool,
        out TransferableResponse? response,
        out AdditionalData? additionalSecretData)
    {
        ArgumentNullException.ThrowIfNull(decrypted);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(challengeVerify);
        ArgumentNullException.ThrowIfNull(pool);

        response = null;
        additionalSecretData = null;
        if(!MatchesStatement(challenge, statement, profile) || !VerifyChallengeSignature(challenge, statement, profile, challengeVerify, pool))
        {
            return false;
        }

        return FinishVerified(
            decrypted, challenge, ciphertext, statement, profile, parameters, seedKeyDerivation, eciesKeyDerivation, aeadDecrypt,
            responseSign, hash, g1ScalarMultiply, g1Add, pool, out response, out additionalSecretData);
    }


    /// <summary>Steps 8 to 15 for a challenge whose signature the caller has already verified.</summary>
    private static bool FinishVerified(
        EciesPlaintext decrypted,
        TransferableChallenge challenge,
        EciesCiphertext ciphertext,
        ProofStatement statement,
        SecdsaLayoutProfile profile,
        EciesParameterSet parameters,
        SeedKeyDerivationDelegate seedKeyDerivation,
        EciesKeyDerivationDelegate eciesKeyDerivation,
        AeadDecryptDelegate aeadDecrypt,
        StructureSignDelegate responseSign,
        FiatShamirHashDelegate hash,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        BaseMemoryPool pool,
        out TransferableResponse? response,
        out AdditionalData? additionalSecretData)
    {
        ArgumentNullException.ThrowIfNull(decrypted);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(seedKeyDerivation);
        ArgumentNullException.ThrowIfNull(eciesKeyDerivation);
        ArgumentNullException.ThrowIfNull(aeadDecrypt);
        ArgumentNullException.ThrowIfNull(responseSign);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(pool);
        parameters.Validate();

        response = null;
        additionalSecretData = null;
        if(!MatchesStatement(challenge, statement, profile))
        {
            return false;
        }

        //Step 7 result: Seed || ASD. The challenger produced it, so it is decoded as wire data.
        if(!profile.DecodeSeedPayload(decrypted.GetBytes(), pool, out ProofSeed? seed, out AdditionalData? asd))
        {
            return false;
        }

        bool succeeded = false;
        using IMemoryOwner<byte> keyOwner = pool.Rent(statement.Count * ScalarSizeBytes);
        Span<byte> recomputed = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> sharedPoint = stackalloc byte[CompressedPointSizeBytes];
        try
        {
            //Step 8: recompute ei from the seed.
            DeriveKeys(seed!, statement, profile, seedKeyDerivation, pool, keyOwner.Memory.Span);
            using P256ScalarVector keys = P256ScalarVector.FromCanonical(keyOwner.Memory.Span, pool);

            //Step 9: E = sum ei·Gi.
            SumOfProducts(statement.Generators, keys.AsReadOnlySpan(), g1ScalarMultiply, g1Add, recomputed);
            if(recomputed[0] == 0x00 || !CryptographicOperations.FixedTimeEquals(recomputed, challenge.GetEphemeralPublicKeyBytes()))
            {
                return false;
            }

            //Step 10: Z'_AB is the x-coordinate of sum ei·Di.
            SumOfProducts(statement.PublicKeys, keys.AsReadOnlySpan(), g1ScalarMultiply, g1Add, sharedPoint);
            if(sharedPoint[0] == 0x00)
            {
                return false;
            }

            //Step 11: decrypting under the key derived from Z'_AB must return the plaintext of step 7.
            using(SharedSecret recomputedSecret = SharedSecret.FromCanonical(sharedPoint[1..], pool))
            {
                if(!EciesAlgorithm.TryCompleteDecryption(
                    recomputedSecret, ciphertext, statement.AdditionalAuthenticatedData, parameters, eciesKeyDerivation, aeadDecrypt, pool, out EciesPlaintext? again))
                {
                    return false;
                }

                using(again)
                {
                    if(!CryptographicOperations.FixedTimeEquals(again!.GetBytes(), decrypted.GetBytes()))
                    {
                        return false;
                    }
                }
            }

            //Steps 12 and 13: H1 = H(e0 || ... || en) and the redundant check H(H1) = H2.
            using ProofDigest primary = HashScalars(keys, profile, hash, pool);
            using ProofDigest secondary = HashPrimary(primary, hash, pool);
            if(!CryptographicOperations.FixedTimeEquals(secondary.GetBytes(), challenge.GetSecondaryDigestBytes()))
            {
                return false;
            }

            //Step 14: SigP on E || G || D || H2 || AAD || H1 with the record signing key.
            using G1Point ephemeralPublicKey = challenge.GetEphemeralPublicKey(pool);
            using IMemoryOwner<byte> signatureBuffer = pool.Rent(MaxSignatureSizeBytes);
            int signatureLength;
            using(LayoutWriter scope = new(pool))
            {
                profile.EncodeResponseScope(ephemeralPublicKey, statement, secondary, primary, scope);
                signatureLength = responseSign(scope.WrittenBytes, signatureBuffer.Memory.Span);
            }

            RequireSignatureLength(signatureLength);

            //Step 15: Resp = (H1, SigP) and ASD.
            response = TransferableResponse.FromParts(primary, signatureBuffer.Memory.Span[..signatureLength], profile.Id, pool);
            additionalSecretData = asd;
            succeeded = true;

            return true;
        }
        finally
        {
            recomputed.Clear();
            sharedPoint.Clear();
            keyOwner.Memory.Span.Clear();
            seed!.Dispose();
            if(!succeeded)
            {
                asd!.Dispose();
            }
        }
    }


    /// <summary>
    /// The all-software response (Algorithm 23): runs <see cref="TryPrepareResponse"/>, the raw agreement
    /// <c>S = d·E</c> and <see cref="TryCompleteResponse"/> with the private key in this process. The result is
    /// byte-identical to the one the phased path gives with a key holder that returns <c>Z_AB</c>.
    /// </summary>
    /// <param name="privateKey">The prover's private scalar <c>d = d₀</c>, in <c>[1, q − 1]</c> by construction; secret.</param>
    /// <param name="challenge">The challenge.</param>
    /// <param name="ciphertext">The ECIES ciphertext that accompanies the challenge.</param>
    /// <param name="statement">The prover's statement.</param>
    /// <param name="profile">The layout profile.</param>
    /// <param name="parameters">The ECIES parameter set.</param>
    /// <param name="challengeVerify">Verifies <c>Sig</c> under the public key <c>S</c> of party <c>T</c>.</param>
    /// <param name="seedKeyDerivation">The derivation <c>K(Seed, D, |q| + 8)</c>.</param>
    /// <param name="eciesKeyDerivation">The ECIES key derivation.</param>
    /// <param name="aeadDecrypt">The ECIES authenticated decryption.</param>
    /// <param name="responseSign">The prover's signature with its record signing key <c>v</c>.</param>
    /// <param name="hash">The hash function <c>H</c>, SHA-256.</param>
    /// <param name="g1ScalarMultiply">G1 scalar multiplication.</param>
    /// <param name="g1Add">G1 addition.</param>
    /// <param name="pool">The pool all values are rented from.</param>
    /// <param name="response">Receives the response, owned by the caller, only when the function returns <see langword="true"/>.</param>
    /// <param name="additionalSecretData">Receives the additional secret data, owned by the caller, only when the function returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when the response was formed.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static bool TryRespond(
        PrivateScalar privateKey,
        TransferableChallenge challenge,
        EciesCiphertext ciphertext,
        ProofStatement statement,
        SecdsaLayoutProfile profile,
        EciesParameterSet parameters,
        StructureVerifyDelegate challengeVerify,
        SeedKeyDerivationDelegate seedKeyDerivation,
        EciesKeyDerivationDelegate eciesKeyDerivation,
        AeadDecryptDelegate aeadDecrypt,
        StructureSignDelegate responseSign,
        FiatShamirHashDelegate hash,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        BaseMemoryPool pool,
        out TransferableResponse? response,
        out AdditionalData? additionalSecretData)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        response = null;
        additionalSecretData = null;
        if(!TryPrepareResponse(challenge, statement, profile, challengeVerify, g1ScalarMultiply, pool, out G1Point? ephemeralPublicKey))
        {
            return false;
        }

        using(ephemeralPublicKey)
        {
            using SharedSecret sharedSecret = EciesAlgorithm.AgreeSharedSecret(privateKey, ephemeralPublicKey!, g1ScalarMultiply, pool);

            return TryCompleteResponse(
                sharedSecret, challenge, ciphertext, statement, profile, parameters, challengeVerify, seedKeyDerivation, eciesKeyDerivation, aeadDecrypt,
                responseSign, hash, g1ScalarMultiply, g1Add, pool, out response, out additionalSecretData);
        }
    }


    /// <summary>
    /// Algorithm 24, verification by a third party <c>P</c>: checks the layout profile and the statement, verifies
    /// both signatures over the profile's byte representations and requires <c>H2 = H(H1)</c>. No private key and no
    /// group arithmetic is needed.
    /// </summary>
    /// <remarks>
    /// The challenge and the response are wire data, so a rejection is a value and not an exception. The
    /// verdict says which check rejected. Statement (9) is accepted if and only if the verdict is
    /// <see cref="TransferableProofVerdict.Accept"/>.
    /// </remarks>
    /// <param name="challenge">The challenge <c>Chal(AAD)</c>.</param>
    /// <param name="response">The response <c>Resp</c>.</param>
    /// <param name="statement">The generators, public keys and additional authenticated data the verifier checks.</param>
    /// <param name="profile">The layout profile; the challenge and the response must have been signed under it.</param>
    /// <param name="challengeVerify">Verifies <c>Sig</c> under the public key <c>S</c> of party <c>T</c>.</param>
    /// <param name="responseVerify">Verifies <c>SigP</c> under the public key <c>V</c> of the prover.</param>
    /// <param name="hash">The hash function <c>H</c>, SHA-256.</param>
    /// <param name="pool">The pool the intermediates are rented from.</param>
    /// <returns>The verdict.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static TransferableProofVerdict Verify(
        TransferableChallenge challenge,
        TransferableResponse response,
        ProofStatement statement,
        SecdsaLayoutProfile profile,
        StructureVerifyDelegate challengeVerify,
        StructureVerifyDelegate responseVerify,
        FiatShamirHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(challengeVerify);
        ArgumentNullException.ThrowIfNull(responseVerify);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(pool);

        //The layout profile of the challenge, the response and the verifier must be one and the same.
        if(challenge.Profile != profile.Id || response.Profile != profile.Id)
        {
            return TransferableProofVerdict.RejectProfileMismatch;
        }

        if(!CryptographicOperations.FixedTimeEquals(challenge.GetAdditionalAuthenticatedDataBytes(), statement.AdditionalAuthenticatedData.GetBytes()))
        {
            return TransferableProofVerdict.RejectStatementMismatch;
        }

        //Step 4: Sig on E || G || D || H2 || AAD under the public key S of T.
        if(!VerifyChallengeSignature(challenge, statement, profile, challengeVerify, pool))
        {
            return TransferableProofVerdict.RejectChallengeSignature;
        }

        //Step 5: SigP on E || G || D || H2 || AAD || H1 under the public key V of the prover.
        using(G1Point ephemeralPublicKey = challenge.GetEphemeralPublicKey(pool))
        using(ProofDigest secondary = challenge.GetSecondaryDigest(pool))
        using(ProofDigest primary = response.GetPrimaryDigest(pool))
        using(LayoutWriter scope = new(pool))
        {
            profile.EncodeResponseScope(ephemeralPublicKey, statement, secondary, primary, scope);
            if(!responseVerify(scope.WrittenBytes, response.GetSignatureBytes()))
            {
                return TransferableProofVerdict.RejectResponseSignature;
            }
        }

        //Step 6: accept if and only if H2 = H(H1).
        using(ProofDigest primary = response.GetPrimaryDigest(pool))
        using(ProofDigest expected = HashPrimary(primary, hash, pool))
        {
            return CryptographicOperations.FixedTimeEquals(expected.GetBytes(), challenge.GetSecondaryDigestBytes())
                ? TransferableProofVerdict.Accept
                : TransferableProofVerdict.RejectDigest;
        }
    }


    /// <summary>Checks that the challenge was signed under this profile and carries the data of this statement.</summary>
    private static bool MatchesStatement(TransferableChallenge challenge, ProofStatement statement, SecdsaLayoutProfile profile)
    {
        return challenge.Profile == profile.Id
            && CryptographicOperations.FixedTimeEquals(challenge.GetAdditionalAuthenticatedDataBytes(), statement.AdditionalAuthenticatedData.GetBytes());
    }


    /// <summary>Verifies <c>Sig</c> over the profile's challenge scope.</summary>
    private static bool VerifyChallengeSignature(
        TransferableChallenge challenge,
        ProofStatement statement,
        SecdsaLayoutProfile profile,
        StructureVerifyDelegate challengeVerify,
        BaseMemoryPool pool)
    {
        using G1Point ephemeralPublicKey = challenge.GetEphemeralPublicKey(pool);
        using ProofDigest secondary = challenge.GetSecondaryDigest(pool);
        using LayoutWriter scope = new(pool);
        profile.EncodeChallengeScope(ephemeralPublicKey, statement, secondary, scope);

        return challengeVerify(scope.WrittenBytes, challenge.GetSignatureBytes());
    }


    /// <summary>Derives every ephemeral key <c>eᵢ</c> from the seed into <paramref name="keys"/>, 32 bytes each.</summary>
    private static void DeriveKeys(
        ProofSeed seed,
        ProofStatement statement,
        SecdsaLayoutProfile profile,
        SeedKeyDerivationDelegate seedKeyDerivation,
        BaseMemoryPool pool,
        Span<byte> keys)
    {
        Span<byte> wide = stackalloc byte[P256SeededKeyReduction.WideSizeBytes];
        try
        {
            for(int index = 0; index < statement.Count; index++)
            {
                using LayoutWriter derivationInput = new(pool);
                profile.EncodeDerivationInput(index, statement, derivationInput);
                seedKeyDerivation(seed.GetBytes(), derivationInput.WrittenBytes, wide);
                P256SeededKeyReduction.Reduce(wide, keys.Slice(index * ScalarSizeBytes, ScalarSizeBytes));
            }
        }
        finally
        {
            wide.Clear();
        }
    }


    /// <summary>Computes <c>Σ scalarᵢ·pointᵢ</c> over a point vector with the same number of scalars.</summary>
    private static void SumOfProducts(
        P256PointVector points,
        ReadOnlySpan<byte> scalars,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1AddDelegate g1Add,
        Span<byte> result)
    {
        Span<byte> term = stackalloc byte[CompressedPointSizeBytes];
        Span<byte> next = stackalloc byte[CompressedPointSizeBytes];
        for(int index = 0; index < points.Count; index++)
        {
            g1ScalarMultiply(points.GetPointBytes(index), scalars.Slice(index * ScalarSizeBytes, ScalarSizeBytes), term, Curve);
            if(index == 0)
            {
                term.CopyTo(result);
            }
            else
            {
                g1Add(result, term, next, Curve);
                next.CopyTo(result);
            }
        }
    }


    /// <summary>Hashes the profile's byte representation of the ephemeral keys: <c>H1 = H(e₀ ‖ … ‖ eₙ)</c>.</summary>
    private static ProofDigest HashScalars(P256ScalarVector keys, SecdsaLayoutProfile profile, FiatShamirHashDelegate hash, BaseMemoryPool pool)
    {
        Span<byte> digest = stackalloc byte[ProofDigest.SizeBytes];
        using LayoutWriter encoded = new(pool);
        profile.EncodeScalarVector(keys, encoded);
        hash(encoded.WrittenBytes, digest, WellKnownHashAlgorithms.Sha256);

        return ProofDigest.FromCanonical(digest, ProofDigestKind.Primary, pool);
    }


    /// <summary>Hashes the primary hash: <c>H2 = H(H1)</c>. <c>H1</c> has a fixed width, so no layout is involved.</summary>
    private static ProofDigest HashPrimary(ProofDigest primary, FiatShamirHashDelegate hash, BaseMemoryPool pool)
    {
        Span<byte> digest = stackalloc byte[ProofDigest.SizeBytes];
        hash(primary.GetBytes(), digest, WellKnownHashAlgorithms.Sha256);

        return ProofDigest.FromCanonical(digest, ProofDigestKind.Secondary, pool);
    }


    /// <summary>Encodes <c>Seed ‖ ASD</c> with the profile into an ECIES plaintext.</summary>
    private static EciesPlaintext EncodePayload(ProofSeed seed, AdditionalData additionalSecretData, SecdsaLayoutProfile profile, BaseMemoryPool pool)
    {
        using LayoutWriter payload = new(pool);
        profile.EncodeSeedPayload(seed, additionalSecretData, payload);

        return EciesPlaintext.FromCanonical(payload.WrittenBytes, pool);
    }


    private static void RequireSignatureLength(int signatureLength)
    {
        if(signatureLength < 1 || signatureLength > MaxSignatureSizeBytes)
        {
            throw new InvalidOperationException($"The signature delegate must write between 1 and {MaxSignatureSizeBytes} bytes; it reported {signatureLength}.");
        }
    }
}
