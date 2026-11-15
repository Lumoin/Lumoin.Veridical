using Lumoin.Base;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Secdsa;
using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lumoin.Veridical.Cli;

/// <summary>The JSON a <c>secdsa-proof-challenge</c> prints: the public challenge and the public ECIES ciphertext, both hex.</summary>
/// <param name="Challenge">The challenge <c>Chal(AAD)</c> in the requested layout, as hex.</param>
/// <param name="Ciphertext">The ECIES ciphertext in the requested layout, as hex; in the provisional layout it is <c>E || T || C</c>.</param>
internal sealed record ProofChallengeOutput(string Challenge, string Ciphertext);


/// <summary>The result of the response completion: the public response and the secret additional data the prover recovered.</summary>
/// <param name="Response">The response <c>Resp</c> in the requested layout, as hex.</param>
/// <param name="AdditionalSecretData">The additional secret data <c>ASD</c> as hex; secret, so the callers write it to a file and never print it.</param>
internal sealed record ProofResponseResult(string Response, string AdditionalSecretData);


/// <summary>The source-generated serialization context of the proof outputs, so the tool serializes without reflection and stays native-AOT clean.</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ProofChallengeOutput))]
internal sealed partial class SecdsaProofJsonContext: JsonSerializerContext
{
}


/// <summary>
/// The operations behind the Algorithm 41, ECIES and transferable-proof subcommands and their MCP tools. Points,
/// hashes, signatures, records, challenges, responses and ciphertexts are hex; secret scalars, shared secrets,
/// plaintexts and additional secret data arrive as hex the caller read from a file and are cleared after use.
/// The transferable proof uses the layout profile the caller names (the provisional length-prefixed layout, ASN.1 DER or deterministic CBOR; the default is the provisional one), ECDSA over P-256 with SHA-256 for both
/// signatures, HKDF-SHA-256 for the seeded keys, and X9.63 over SHA-256 with AES-256-GCM for ECIES; none of these
/// is an interoperability format.
/// </summary>
internal static class SecdsaProofOperations
{
    private const int ScalarBytes = SecdsaAlgorithm.ScalarSizeBytes;

    private static EciesParameterSet Parameters { get; } = EciesParameterSet.X963Sha256Aes256Gcm;

    private static SecdsaLayoutProfile ProvisionalProfile { get; } = SecdsaProvisionalLayout.Profile;

    /// <summary>The name of the provisional length-prefixed layout, the default of every transferable-proof command.</summary>
    public const string ProvisionalLayoutName = "provisional";

    /// <summary>The name of the ASN.1 DER layout.</summary>
    public const string DerLayoutName = "der";

    /// <summary>The name of the deterministic CBOR layout.</summary>
    public const string CborLayoutName = "cbor";

    /// <summary>The layout names the transferable-proof commands accept.</summary>
    public static string[] LayoutNames { get; } = [ProvisionalLayoutName, DerLayoutName, CborLayoutName];


    /// <summary>Resolves a layout name to the shipped profile it names.</summary>
    /// <param name="layout">One of <see cref="LayoutNames"/>.</param>
    /// <returns>The profile.</returns>
    /// <exception cref="ArgumentException">The name is not one of the shipped layouts.</exception>
    public static SecdsaLayoutProfile ResolveLayout(string layout)
    {
        return layout switch
        {
            ProvisionalLayoutName => SecdsaProvisionalLayout.Profile,
            DerLayoutName => SecdsaDerLayout.Profile,
            CborLayoutName => SecdsaCborLayout.Profile,
            _ => throw new ArgumentException($"The layout must be one of {string.Join(", ", LayoutNames)}; it was '{layout}'.", nameof(layout))
        };
    }


    /// <summary>Algorithm 41, prover side: proves that a signature result is consistent with the user key.</summary>
    /// <param name="publicKeyHex">The user public key <c>Q_U</c> as hex.</param>
    /// <param name="messageHashHex">The message hash as hex.</param>
    /// <param name="signatureHex">The signature <c>r || s</c> as hex.</param>
    /// <returns>The record <c>(R, G'', Q_U'', proof)</c> as hex.</returns>
    /// <exception cref="ArgumentException">An input is invalid or the signature does not verify.</exception>
    public static string ResultProve(string publicKeyHex, string messageHashHex, string signatureHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        return Guard(() =>
        {
            using SecdsaSignature signature = SecdsaSignature.FromCanonical(HexInput.Decode(signatureHex, "signature"), pool);
            using SignatureResultRecord record = SecdsaSignatureResultConformity.Prove(
                signature, HexInput.Decode(messageHashHex, "message hash"), HexInput.Decode(publicKeyHex, "public key"), composition.NonceSource,
                composition.Hash, composition.ScalarMultiply, composition.ScalarAdd, composition.ScalarInvert, composition.ScalarReduce,
                composition.G1ScalarMultiply, composition.G1Add, pool);

            return Convert.ToHexStringLower(record.AsReadOnlySpan());
        });
    }


    /// <summary>Algorithm 41, verifier side: checks a record; any result other than no alarm is the compromise alarm.</summary>
    /// <param name="publicKeyHex">The user public key <c>Q_U</c> as hex.</param>
    /// <param name="messageHashHex">The message hash as hex.</param>
    /// <param name="recordHex">The record as hex.</param>
    /// <returns>The outcome.</returns>
    public static VerificationResult ResultCheck(string publicKeyHex, string messageHashHex, string recordHex)
    {
        try
        {
            using var composition = new SecdsaPlatformComposition();
            using SignatureResultRecord record = SignatureResultRecord.FromCanonical(HexInput.Decode(recordHex, "record"), BaseMemoryPool.Shared);
            SignatureResultConformity conformity = SecdsaSignatureResultConformity.Check(
                record, HexInput.Decode(messageHashHex, "message hash"), HexInput.Decode(publicKeyHex, "public key"), composition.Hash,
                composition.ScalarReduce, composition.G1ScalarMultiply, composition.G1Add, composition.G1Negate);
            string statement = "that the signature result is consistent with the user key";

            return conformity switch
            {
                SignatureResultConformity.NoAlarm => VerificationResult.Valid(statement),
                SignatureResultConformity.AlarmMalformedRecord => VerificationResult.Malformed("ALARM: the record or the key is malformed."),
                SignatureResultConformity.AlarmProofRejected => VerificationResult.Rejected($"{statement} (ALARM: the proof does not verify)"),
                _ => VerificationResult.Rejected($"{statement} (ALARM: the nonce point does not match the blinded pair)")
            };
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
    }


    /// <summary>ECIES encryption (Algorithm 18) towards a recipient public key.</summary>
    /// <param name="recipientPublicKeyHex">The recipient public key as hex.</param>
    /// <param name="plaintextHex">The plaintext as hex (secret).</param>
    /// <param name="associatedDataHex">The additional authenticated data as hex; may be empty.</param>
    /// <returns>The ciphertext <c>E || T || C</c> as hex.</returns>
    public static string EciesEncrypt(string recipientPublicKeyHex, string plaintextHex, string associatedDataHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        return Guard(() =>
        {
            using G1Point recipient = G1Point.FromCanonical(HexInput.Decode(recipientPublicKeyHex, "recipient public key"), CurveParameterSet.P256, pool);
            using EciesPlaintext plaintext = EciesPlaintext.FromCanonical(HexInput.Decode(plaintextHex, "plaintext"), pool);
            using AdditionalData associatedData = AdditionalData.FromCanonical(HexInput.Decode(associatedDataHex, "associated data"), AdditionalDataRole.Authenticated, pool);
            using EciesCiphertext ciphertext = EciesAlgorithm.Encrypt(
                plaintext, associatedData, recipient, Parameters, composition.Entropy, composition.CreateEciesKeyDerivation(pool),
                composition.AesGcmEncrypt, composition.G1ScalarMultiply, pool);

            return Convert.ToHexStringLower(ciphertext.AsReadOnlySpan());
        });
    }


    /// <summary>ECIES decryption (Algorithm 19) with the private key in this process.</summary>
    /// <param name="privateKeyHex">The recipient private scalar as hex (secret).</param>
    /// <param name="ciphertextHex">The ciphertext as hex.</param>
    /// <param name="associatedDataHex">The additional authenticated data as hex; may be empty.</param>
    /// <returns>The plaintext as hex (secret).</returns>
    /// <exception cref="ArgumentException">An input is invalid or authentication fails; no plaintext is released.</exception>
    public static string EciesDecrypt(string privateKeyHex, string ciphertextHex, string associatedDataHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        return Guard(() => DecryptWith(composition, privateKeyHex, ciphertextHex, associatedDataHex, pool));
    }


    /// <summary>ECIES decryption phase one: validates the ephemeral public key of a ciphertext for the key holder.</summary>
    /// <param name="ciphertextHex">The ciphertext as hex.</param>
    /// <returns>The validated, canonical ephemeral public key as hex.</returns>
    public static string EciesPrepareDecryption(string ciphertextHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        return Guard(() =>
        {
            using EciesCiphertext ciphertext = DecodeCiphertext(ProvisionalProfile, ciphertextHex, pool);
            using G1Point point = EciesAlgorithm.PrepareDecryption(ciphertext, composition.G1ScalarMultiply, pool);

            return Convert.ToHexStringLower(point.AsReadOnlySpan());
        });
    }


    /// <summary>The key holder's raw agreement <c>Z_AB</c> = x(d·E) in software.</summary>
    /// <param name="privateKeyHex">The private scalar as hex (secret).</param>
    /// <param name="pointHex">The peer point, such as the ephemeral public key, as hex.</param>
    /// <returns>The shared secret as hex (secret).</returns>
    public static string EciesAgree(string privateKeyHex, string pointHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        return Guard(() =>
        {
            using G1Point point = G1Point.FromCanonical(HexInput.Decode(pointHex, "point"), CurveParameterSet.P256, pool);
            Span<byte> privateBytes = stackalloc byte[ScalarBytes];
            try
            {
                HexInput.DecodeExact(privateKeyHex, privateBytes, "private key");
                using PrivateScalar privateKey = PrivateScalar.FromCanonical(privateBytes, pool);
                using SharedSecret secret = EciesAlgorithm.AgreeSharedSecret(privateKey, point, composition.G1ScalarMultiply, pool);

                return Convert.ToHexStringLower(secret.AsReadOnlySpan());
            }
            finally
            {
                privateBytes.Clear();
            }
        });
    }


    /// <summary>ECIES decryption phase two: derives the key from the key holder's shared secret and decrypts.</summary>
    /// <param name="sharedSecretHex">The shared secret <c>Z_AB</c> as hex (secret).</param>
    /// <param name="ciphertextHex">The ciphertext as hex.</param>
    /// <param name="associatedDataHex">The additional authenticated data as hex; may be empty.</param>
    /// <returns>The plaintext as hex (secret).</returns>
    /// <exception cref="ArgumentException">An input is invalid or authentication fails; no plaintext is released.</exception>
    public static string EciesCompleteDecryption(string sharedSecretHex, string ciphertextHex, string associatedDataHex)
    {
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        return Guard(() =>
        {
            using SharedSecret sharedSecret = SharedSecret.FromCanonical(HexInput.Decode(sharedSecretHex, "shared secret"), pool);
            using EciesCiphertext ciphertext = DecodeCiphertext(ProvisionalProfile, ciphertextHex, pool);
            using AdditionalData associatedData = AdditionalData.FromCanonical(HexInput.Decode(associatedDataHex, "associated data"), AdditionalDataRole.Authenticated, pool);
            if(!EciesAlgorithm.TryCompleteDecryption(
                sharedSecret, ciphertext, associatedData, Parameters, composition.CreateEciesKeyDerivation(pool), composition.AesGcmDecrypt, pool, out EciesPlaintext? plaintext))
            {
                throw new ArgumentException("Authentication failed; no plaintext was released.");
            }

            using(plaintext)
            {
                return Convert.ToHexStringLower(plaintext!.GetBytes());
            }
        });
    }


    /// <summary>Algorithm 22: issues a challenge and the ECIES ciphertext that carries the seed.</summary>
    /// <param name="signingKeyHex">The challenger's signing scalar as hex (secret).</param>
    /// <param name="generatorsHex">The concatenated compressed generators as hex.</param>
    /// <param name="publicKeysHex">The concatenated compressed public keys as hex, pairwise with the generators.</param>
    /// <param name="associatedDataHex">The additional authenticated data as hex; may be empty.</param>
    /// <param name="additionalSecretDataHex">The additional secret data as hex (secret); may be empty.</param>
    /// <param name="layout">The layout of the signed structures and of the printed challenge and ciphertext: <c>provisional</c>, <c>der</c> or <c>cbor</c>.</param>
    /// <returns>The challenge and the ciphertext as a JSON object.</returns>
    public static string ProofChallenge(string signingKeyHex, string generatorsHex, string publicKeysHex, string associatedDataHex, string additionalSecretDataHex, string layout)
    {
        SecdsaLayoutProfile profile = ResolveLayout(layout);
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] signingKey = HexInput.Decode(signingKeyHex, "signing key");
        try
        {
            return Guard(() =>
            {
                RequireScalarSize(signingKey, "signing key");
                using StatementScope statement = new(generatorsHex, publicKeysHex, associatedDataHex, pool);
                using AdditionalData additionalSecretData = AdditionalData.FromCanonical(HexInput.Decode(additionalSecretDataHex, "additional secret data"), AdditionalDataRole.Secret, pool);
                using ProofSeed seed = ProofSeed.Generate(composition.Entropy, pool);
                using TransferableChallenge challenge = TransferableProofAlgorithm.Issue(
                    statement.Statement, additionalSecretData, seed, profile, Parameters, composition.SeedKeyDerivation,
                    composition.CreateEciesKeyDerivation(pool), composition.AesGcmEncrypt,
                    (structure, signature) => composition.SignStructure(signingKey, structure, signature),
                    composition.Hash, composition.G1ScalarMultiply, composition.G1Add, pool, out EciesCiphertext ciphertext);
                using(ciphertext)
                using(LayoutWriter encoded = new(pool))
                {
                    profile.EncodeChallenge(challenge, encoded);

                    return JsonSerializer.Serialize(
                        new ProofChallengeOutput(Convert.ToHexStringLower(encoded.WrittenBytes), Convert.ToHexStringLower(ciphertext.AsReadOnlySpan())),
                        SecdsaProofJsonContext.Default.ProofChallengeOutput);
                }
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingKey);
        }
    }


    /// <summary>Algorithm 23 steps 1 to 4: checks a challenge and yields the ephemeral public key for the key holder.</summary>
    /// <param name="challengeHex">The challenge as hex.</param>
    /// <param name="generatorsHex">The concatenated compressed generators as hex.</param>
    /// <param name="publicKeysHex">The concatenated compressed public keys as hex.</param>
    /// <param name="associatedDataHex">The additional authenticated data the prover expects, as hex; may be empty.</param>
    /// <param name="challengerPublicKeyHex">The challenger's public key <c>S</c> as hex.</param>
    /// <param name="layout">The layout the challenge was formed under: <c>provisional</c>, <c>der</c> or <c>cbor</c>.</param>
    /// <returns>The validated ephemeral public key as hex.</returns>
    /// <exception cref="ArgumentException">An input is invalid or the challenge is rejected.</exception>
    public static string ProofRespondPrepare(string challengeHex, string generatorsHex, string publicKeysHex, string associatedDataHex, string challengerPublicKeyHex, string layout)
    {
        SecdsaLayoutProfile profile = ResolveLayout(layout);
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        return Guard(() =>
        {
            byte[] challengerPublicKey = HexInput.Decode(challengerPublicKeyHex, "challenger public key");
            using StatementScope statement = new(generatorsHex, publicKeysHex, associatedDataHex, pool);
            using TransferableChallenge challenge = DecodeChallenge(profile, challengeHex, pool);
            if(!TransferableProofAlgorithm.TryPrepareResponse(
                challenge, statement.Statement, profile, (structure, signature) => composition.VerifyStructure(challengerPublicKey, structure, signature),
                composition.G1ScalarMultiply, pool, out G1Point? ephemeralPublicKey))
            {
                throw new ArgumentException("The challenge was rejected: its profile, additional data, signature or ephemeral public key is not valid for this statement.");
            }

            using(ephemeralPublicKey)
            {
                return Convert.ToHexStringLower(ephemeralPublicKey!.AsReadOnlySpan());
            }
        });
    }


    /// <summary>Algorithm 23 steps 6 to 15 from the key holder's shared secret: forms the response and recovers the additional secret data.</summary>
    /// <param name="sharedSecretHex">The shared secret <c>Z_AB</c> from <c>d·E</c> as hex (secret).</param>
    /// <param name="challengeHex">The challenge as hex.</param>
    /// <param name="ciphertextHex">The ECIES ciphertext as hex.</param>
    /// <param name="generatorsHex">The concatenated compressed generators as hex.</param>
    /// <param name="publicKeysHex">The concatenated compressed public keys as hex.</param>
    /// <param name="associatedDataHex">The additional authenticated data the prover expects, as hex; may be empty.</param>
    /// <param name="signingKeyHex">The prover's record signing scalar as hex (secret).</param>
    /// <param name="challengerPublicKeyHex">The challenger's public key S, 33 bytes as hex, under which the challenge signature is verified.</param>
    /// <param name="layout">The layout the challenge and the ciphertext were formed under, and the response is encoded in: <c>provisional</c>, <c>der</c> or <c>cbor</c>.</param>
    /// <returns>The response and the additional secret data.</returns>
    /// <exception cref="ArgumentException">An input is invalid or a check of the response fails; no response is produced.</exception>
    public static ProofResponseResult ProofRespondComplete(
        string sharedSecretHex,
        string challengeHex,
        string ciphertextHex,
        string generatorsHex,
        string publicKeysHex,
        string associatedDataHex,
        string signingKeyHex,
        string challengerPublicKeyHex,
        string layout)
    {
        SecdsaLayoutProfile profile = ResolveLayout(layout);
        using var composition = new SecdsaPlatformComposition();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] signingKey = HexInput.Decode(signingKeyHex, "signing key");
        try
        {
            return Guard(() =>
            {
                RequireScalarSize(signingKey, "signing key");
                byte[] challengerPublicKey = HexInput.Decode(challengerPublicKeyHex, "challenger public key");
                using SharedSecret sharedSecret = SharedSecret.FromCanonical(HexInput.Decode(sharedSecretHex, "shared secret"), pool);
                using StatementScope statement = new(generatorsHex, publicKeysHex, associatedDataHex, pool);
                using TransferableChallenge challenge = DecodeChallenge(profile, challengeHex, pool);
                using EciesCiphertext ciphertext = DecodeCiphertext(ProvisionalProfile, ciphertextHex, pool);
                if(!TransferableProofAlgorithm.TryCompleteResponse(
                    sharedSecret, challenge, ciphertext, statement.Statement, profile, Parameters,
                    (structure, signature) => composition.VerifyStructure(challengerPublicKey, structure, signature), composition.SeedKeyDerivation,
                    composition.CreateEciesKeyDerivation(pool), composition.AesGcmDecrypt,
                    (structure, signature) => composition.SignStructure(signingKey, structure, signature),
                    composition.Hash, composition.G1ScalarMultiply, composition.G1Add, pool,
                    out TransferableResponse? response, out AdditionalData? additionalSecretData))
                {
                    throw new ArgumentException("No response was formed: the decryption, the seeded keys, the repeated decryption or the hash check failed.");
                }

                using(response)
                using(additionalSecretData)
                using(LayoutWriter encoded = new(pool))
                {
                    profile.EncodeResponse(response!, encoded);

                    return new ProofResponseResult(Convert.ToHexStringLower(encoded.WrittenBytes), Convert.ToHexStringLower(additionalSecretData!.GetBytes()));
                }
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingKey);
        }
    }


    /// <summary>Algorithm 24: verifies a transferable proof as a third party.</summary>
    /// <param name="challengeHex">The challenge as hex.</param>
    /// <param name="responseHex">The response as hex.</param>
    /// <param name="generatorsHex">The concatenated compressed generators as hex.</param>
    /// <param name="publicKeysHex">The concatenated compressed public keys as hex.</param>
    /// <param name="associatedDataHex">The additional authenticated data as hex; may be empty.</param>
    /// <param name="challengerPublicKeyHex">The challenger's public key <c>S</c> as hex.</param>
    /// <param name="proverPublicKeyHex">The prover's record public key <c>V</c> as hex.</param>
    /// <param name="layout">The layout the proof was formed under: <c>provisional</c>, <c>der</c> or <c>cbor</c>.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult ProofVerify(
        string challengeHex,
        string responseHex,
        string generatorsHex,
        string publicKeysHex,
        string associatedDataHex,
        string challengerPublicKeyHex,
        string proverPublicKeyHex,
        string layout)
    {
        try
        {
            SecdsaLayoutProfile profile = ResolveLayout(layout);
            using var composition = new SecdsaPlatformComposition();
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            byte[] challengerPublicKey = HexInput.Decode(challengerPublicKeyHex, "challenger public key");
            byte[] proverPublicKey = HexInput.Decode(proverPublicKeyHex, "prover public key");
            using StatementScope statement = new(generatorsHex, publicKeysHex, associatedDataHex, pool);
            using TransferableChallenge challenge = DecodeChallenge(profile, challengeHex, pool);
            using TransferableResponse response = DecodeResponse(profile, responseHex, pool);
            TransferableProofVerdict verdict = TransferableProofAlgorithm.Verify(
                challenge, response, statement.Statement, profile,
                (structure, signature) => composition.VerifyStructure(challengerPublicKey, structure, signature),
                (structure, signature) => composition.VerifyStructure(proverPublicKey, structure, signature),
                composition.Hash, pool);
            string subject = "that every generator/public-key pair shares one private key, attributable to the prover";

            return verdict == TransferableProofVerdict.Accept
                ? VerificationResult.Valid(subject)
                : VerificationResult.Rejected($"{subject} ({verdict})");
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
    }


    private static string DecryptWith(SecdsaPlatformComposition composition, string privateKeyHex, string ciphertextHex, string associatedDataHex, BaseMemoryPool pool)
    {
        Span<byte> privateBytes = stackalloc byte[ScalarBytes];
        try
        {
            HexInput.DecodeExact(privateKeyHex, privateBytes, "private key");
            using PrivateScalar privateKey = PrivateScalar.FromCanonical(privateBytes, pool);
            using EciesCiphertext ciphertext = DecodeCiphertext(ProvisionalProfile, ciphertextHex, pool);
            using AdditionalData associatedData = AdditionalData.FromCanonical(HexInput.Decode(associatedDataHex, "associated data"), AdditionalDataRole.Authenticated, pool);
            if(!EciesAlgorithm.TryDecrypt(
                privateKey, ciphertext, associatedData, Parameters, composition.CreateEciesKeyDerivation(pool), composition.AesGcmDecrypt,
                composition.G1ScalarMultiply, pool, out EciesPlaintext? plaintext))
            {
                throw new ArgumentException("Authentication failed; no plaintext was released.");
            }

            using(plaintext)
            {
                return Convert.ToHexStringLower(plaintext!.GetBytes());
            }
        }
        finally
        {
            privateBytes.Clear();
        }
    }


    private static EciesCiphertext DecodeCiphertext(SecdsaLayoutProfile profile, string ciphertextHex, BaseMemoryPool pool)
    {
        if(!profile.DecodeCiphertext(HexInput.Decode(ciphertextHex, "ciphertext"), Parameters, pool, out EciesCiphertext? ciphertext))
        {
            throw new ArgumentException("The ciphertext is not a well-formed ciphertext of the layout.");
        }

        return ciphertext!;
    }


    private static TransferableChallenge DecodeChallenge(SecdsaLayoutProfile profile, string challengeHex, BaseMemoryPool pool)
    {
        if(!profile.DecodeChallenge(HexInput.Decode(challengeHex, "challenge"), pool, out TransferableChallenge? challenge))
        {
            throw new ArgumentException("The challenge is not a well-formed challenge of the layout.");
        }

        return challenge!;
    }


    private static TransferableResponse DecodeResponse(SecdsaLayoutProfile profile, string responseHex, BaseMemoryPool pool)
    {
        if(!profile.DecodeResponse(HexInput.Decode(responseHex, "response"), pool, out TransferableResponse? response))
        {
            throw new ArgumentException("The response is not a well-formed response of the layout.");
        }

        return response!;
    }


    private static void RequireScalarSize(byte[] scalar, string name)
    {
        if(scalar.Length != ScalarBytes)
        {
            throw new ArgumentException($"The {name} must be {ScalarBytes} bytes.", name);
        }
    }


    private static T Guard<T>(Func<T> operation)
    {
        try
        {
            return operation();
        }
        catch(InvalidOperationException error)
        {
            throw new ArgumentException(error.Message, nameof(operation), error);
        }
    }


    /// <summary>The generators, public keys and additional data of a statement, disposed together.</summary>
    private sealed class StatementScope: IDisposable
    {
        private P256PointVector Generators { get; }

        private P256PointVector PublicKeys { get; }

        private AdditionalData AssociatedData { get; }

        public ProofStatement Statement { get; }


        public StatementScope(string generatorsHex, string publicKeysHex, string associatedDataHex, BaseMemoryPool pool)
        {
            Generators = P256PointVector.FromCanonical(HexInput.Decode(generatorsHex, "generators"), pool);
            PublicKeys = P256PointVector.FromCanonical(HexInput.Decode(publicKeysHex, "public keys"), pool);
            AssociatedData = AdditionalData.FromCanonical(HexInput.Decode(associatedDataHex, "associated data"), AdditionalDataRole.Authenticated, pool);
            Statement = new ProofStatement(Generators, PublicKeys, AssociatedData);
        }


        public void Dispose()
        {
            AssociatedData.Dispose();
            PublicKeys.Dispose();
            Generators.Dispose();
        }
    }
}
