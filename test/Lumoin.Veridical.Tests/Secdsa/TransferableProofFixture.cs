using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Security.Cryptography;
using static Lumoin.Veridical.Tests.Secdsa.SecdsaTestSupport;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// A keyed-hash stand-in for the challenger and prover signature schemes, which the algorithms take as delegates:
/// the signature of a structure is its HMAC-SHA-256 under a pooled key. The scheme is not under test; only that
/// the algorithms sign and verify exactly the bytes the layout profile produced.
/// </summary>
internal sealed class MacSignature: IDisposable
{
    private IMemoryOwner<byte> Key { get; }


    public MacSignature(BaseMemoryPool pool, string label)
    {
        Key = pool.Rent(DigestSize);
        MessageHash(System.Text.Encoding.UTF8.GetBytes(label), Key.Memory.Span);
    }


    public int Sign(ReadOnlySpan<byte> structure, Span<byte> signature)
    {
        Hmac(Key.Memory.Span, structure, signature[..DigestSize]);

        return DigestSize;
    }


    public bool Verify(ReadOnlySpan<byte> structure, ReadOnlySpan<byte> signature)
    {
        Span<byte> expected = stackalloc byte[DigestSize];
        Hmac(Key.Memory.Span, structure, expected);

        return CryptographicOperations.FixedTimeEquals(expected, signature);
    }


    public void Dispose()
    {
        Key.Memory.Span.Clear();
        Key.Dispose();
    }
}


/// <summary>A challenge with its ECIES ciphertext, disposed together.</summary>
internal sealed class IssuedChallenge: IDisposable
{
    public TransferableChallenge Challenge { get; }

    public EciesCiphertext Ciphertext { get; }


    public IssuedChallenge(TransferableChallenge challenge, EciesCiphertext ciphertext)
    {
        Challenge = challenge;
        Ciphertext = ciphertext;
    }


    public void Dispose()
    {
        Challenge.Dispose();
        Ciphertext.Dispose();
    }
}


/// <summary>A response with the additional secret data the prover recovered, disposed together.</summary>
internal sealed class ProverResponse: IDisposable
{
    public TransferableResponse Response { get; }

    public AdditionalData SecretData { get; }


    public ProverResponse(TransferableResponse response, AdditionalData secretData)
    {
        Response = response;
        SecretData = secretData;
    }


    public void Dispose()
    {
        Response.Dispose();
        SecretData.Dispose();
    }
}


/// <summary>
/// A statement over three generators with the prover's private key, the two signing keys, the seed and the
/// delegates the algorithms need. <see cref="Create"/> with <c>consistent: false</c> makes <c>D₁ ≠ d·G₁</c>,
/// the statement that must not be provable.
/// </summary>
internal sealed class TransferableFixture: IDisposable
{
    public const int GeneratorCount = 3;

    public static EciesParameterSet Parameters { get; } = EciesParameterSet.X963Sha256Aes256Gcm;

    public BaseMemoryPool Pool { get; } = new();

    public IMemoryOwner<byte> PrivateKey { get; }

    public P256PointVector Generators { get; }

    public P256PointVector PublicKeys { get; }

    public AdditionalData AuthenticatedData { get; }

    public AdditionalData SecretData { get; }

    public ProofStatement Statement { get; }

    public ProofSeed Seed { get; }

    public MacSignature Challenger { get; }

    public MacSignature Prover { get; }

    public EciesKeyDerivationDelegate EciesKdf { get; }

    public SecdsaLayoutProfile Shipped { get; } = SecdsaProvisionalLayout.Profile;


    private TransferableFixture(string label, bool consistent)
    {
        PrivateKey = Pool.Rent(ScalarSize);
        DeriveScalar(System.Text.Encoding.UTF8.GetBytes(label + " d"), PrivateKey.Memory.Span);

        Span<byte> generators = stackalloc byte[GeneratorCount * PointSize];
        Span<byte> publicKeys = stackalloc byte[GeneratorCount * PointSize];
        Span<byte> multiplier = stackalloc byte[ScalarSize];
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.P256).CopyTo(generators);
        for(int index = 1; index < GeneratorCount; index++)
        {
            DeriveScalar(System.Text.Encoding.UTF8.GetBytes(label + " g" + index), multiplier);
            PublicPoint(multiplier, generators.Slice(index * PointSize, PointSize));
        }

        for(int index = 0; index < GeneratorCount; index++)
        {
            Multiply(generators.Slice(index * PointSize, PointSize), PrivateKey.Memory.Span, publicKeys.Slice(index * PointSize, PointSize));
        }

        if(!consistent)
        {
            //D1 becomes d·G1 + G0, which breaks Statement (9) for the second pair only.
            Span<byte> broken = stackalloc byte[PointSize];
            G1Add(publicKeys.Slice(PointSize, PointSize), generators[..PointSize], broken, CurveParameterSet.P256);
            broken.CopyTo(publicKeys.Slice(PointSize, PointSize));
        }

        Generators = P256PointVector.FromCanonical(generators, Pool);
        PublicKeys = P256PointVector.FromCanonical(publicKeys, Pool);
        AuthenticatedData = AdditionalData.FromCanonical("wallet-to-provider message"u8, AdditionalDataRole.Authenticated, Pool);
        SecretData = AdditionalData.FromCanonical("secret payload"u8, AdditionalDataRole.Secret, Pool);
        Statement = new ProofStatement(Generators, PublicKeys, AuthenticatedData);
        Seed = ProofSeed.Generate(new DeterministicEntropy(label + " seed").Source, Pool);
        Challenger = new MacSignature(Pool, label + " challenger");
        Prover = new MacSignature(Pool, label + " prover");
        EciesKdf = X963KeyDerivation.Create(Hash, Pool);
    }


    public static TransferableFixture Create(string label, bool consistent = true)
    {
        return new TransferableFixture(label, consistent);
    }


    public static void SeedKeyDerivation(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> derivationInput, Span<byte> output)
    {
        Sha256Hkdf.DeriveKey(ReadOnlySpan<byte>.Empty, masterKey, derivationInput, output);
    }


    public IssuedChallenge Issue(SecdsaLayoutProfile? profile = null, ProofStatement? statement = null)
    {
        TransferableChallenge challenge = TransferableProofAlgorithm.Issue(
            statement ?? Statement, SecretData, Seed, profile ?? Shipped, Parameters, SeedKeyDerivation, EciesKdf,
            TestPlatformCrypto.AesGcmEncrypt, Challenger.Sign, Hash, G1ScalarMultiply, G1Add, Pool, out EciesCiphertext ciphertext);

        return new IssuedChallenge(challenge, ciphertext);
    }


    public ProverResponse? Respond(
        IssuedChallenge issued,
        SecdsaLayoutProfile? profile = null,
        ReadOnlySpan<byte> privateKey = default,
        StructureVerifyDelegate? challengeVerify = null,
        EciesCiphertext? ciphertext = null,
        ProofStatement? statement = null)
    {
        ReadOnlySpan<byte> key = privateKey.IsEmpty ? PrivateKey.Memory.Span : privateKey;
        TransferableResponse? response = null;
        AdditionalData? secretData = null;
        try
        {
            bool formed = TransferableProofAlgorithm.TryRespond(
                key, issued.Challenge, ciphertext ?? issued.Ciphertext, statement ?? Statement, profile ?? Shipped, Parameters,
                challengeVerify ?? Challenger.Verify, SeedKeyDerivation, EciesKdf, TestPlatformCrypto.AesGcmDecrypt, Prover.Sign,
                Hash, G1ScalarMultiply, G1Add, Pool, out response, out secretData);
            if(!formed)
            {
                return null;
            }

            ProverResponse result = new(response!, secretData!);
            response = null;
            secretData = null;

            return result;
        }
        finally
        {
            response?.Dispose();
            secretData?.Dispose();
        }
    }


    public bool Responds(
        IssuedChallenge issued,
        SecdsaLayoutProfile? profile = null,
        ReadOnlySpan<byte> privateKey = default,
        StructureVerifyDelegate? challengeVerify = null,
        EciesCiphertext? ciphertext = null,
        ProofStatement? statement = null)
    {
        using ProverResponse? response = Respond(issued, profile, privateKey, challengeVerify, ciphertext, statement);

        return response is not null;
    }


    public TransferableProofVerdict Verify(
        TransferableChallenge challenge,
        TransferableResponse response,
        SecdsaLayoutProfile? profile = null,
        ProofStatement? statement = null,
        StructureVerifyDelegate? challengeVerify = null,
        StructureVerifyDelegate? responseVerify = null)
    {
        return TransferableProofAlgorithm.Verify(
            challenge, response, statement ?? Statement, profile ?? Shipped,
            challengeVerify ?? Challenger.Verify, responseVerify ?? Prover.Verify, Hash, Pool);
    }


    public TransferableChallenge Rebuild(
        TransferableChallenge source,
        ReadOnlySpan<byte> ephemeral,
        ReadOnlySpan<byte> secondary,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> signature,
        SecdsaLayoutProfileId? profile = null)
    {
        using G1Point point = G1Point.FromCanonical(ephemeral, CurveParameterSet.P256, Pool);
        using ProofDigest digest = ProofDigest.FromCanonical(secondary, ProofDigestKind.Secondary, Pool);
        using AdditionalData data = AdditionalData.FromCanonical(aad, AdditionalDataRole.Authenticated, Pool);

        return TransferableChallenge.FromParts(point, digest, data, signature, profile ?? source.Profile, Pool);
    }


    public TransferableResponse Rebuild(TransferableResponse source, ReadOnlySpan<byte> primary, ReadOnlySpan<byte> signature, SecdsaLayoutProfileId? profile = null)
    {
        using ProofDigest digest = ProofDigest.FromCanonical(primary, ProofDigestKind.Primary, Pool);

        return TransferableResponse.FromParts(digest, signature, profile ?? source.Profile, Pool);
    }


    public void Dispose()
    {
        PrivateKey.Memory.Span.Clear();
        PrivateKey.Dispose();
        Seed.Dispose();
        SecretData.Dispose();
        AuthenticatedData.Dispose();
        PublicKeys.Dispose();
        Generators.Dispose();
        Challenger.Dispose();
        Prover.Dispose();
        Pool.Dispose();
    }
}
