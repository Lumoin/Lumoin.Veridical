using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Security.Cryptography;
using static Lumoin.Veridical.Tests.Secdsa.SecdsaTestSupport;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the ECIES of Verheul Annex A.4 (Algorithms 18 and 19) over P-256 with the ANSI X9.63 SHA-256 key
/// derivation and AES-256-GCM: round trips, the all-software decryption against the phased decryption with a
/// simulated key holder between the phases (byte-identical plaintext), and a negative test for every
/// authenticated component: the tag, the ciphertext, the additional data, the ephemeral public key, the
/// recipient key and the parameter set. A failed decryption releases no plaintext.
/// </summary>
[TestClass]
internal sealed class EciesAlgorithmTests
{
    private static EciesParameterSet Parameters => EciesParameterSet.X963Sha256Aes256Gcm;


    [TestMethod]
    public void RoundTripRecoversPlaintextForEveryAssociatedDataShape()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);

        AssertRoundTrip(recipient, pool, "the plaintext of the ecies round trip"u8, "the additional authenticated data"u8);
        AssertRoundTrip(recipient, pool, "the plaintext of the ecies round trip"u8, ReadOnlySpan<byte>.Empty);
        AssertRoundTrip(recipient, pool, ReadOnlySpan<byte>.Empty, "only additional data"u8);
        AssertRoundTrip(recipient, pool, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
    }


    [TestMethod]
    public void CiphertextCarriesItsParametersAndEphemeralKeyOnTheCurve()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "ephemeral-one");

        Assert.AreEqual(Parameters, ciphertext.Parameters);
        Assert.AreEqual(SecdsaStructureKind.EciesCiphertext, ciphertext.Tag.Get<SecdsaStructureKind>());
        int ephemeralKeyBytes = ciphertext.GetEphemeralPublicKeyBytes().Length;
        int tagBytes = ciphertext.GetAuthenticationTagBytes().Length;
        int encryptedBytes = ciphertext.GetEncryptedBytes().Length;
        Assert.AreEqual(EciesCiphertext.EphemeralPublicKeySizeBytes, ephemeralKeyBytes);
        Assert.AreEqual(Parameters.TagSizeBytes, tagBytes);
        Assert.AreEqual("payload"u8.Length, encryptedBytes);

        //E = e·G for the scalar the injected entropy yields: the sampler takes the first 32 bytes, in range.
        Span<byte> expectedScalar = stackalloc byte[ScalarSize];
        new DeterministicEntropy("ephemeral-one").Fill(expectedScalar);
        Span<byte> expectedPublicKey = stackalloc byte[PointSize];
        PublicPoint(expectedScalar, expectedPublicKey);
        Assert.IsTrue(ciphertext.GetEphemeralPublicKeyBytes().SequenceEqual(expectedPublicKey));
    }


    [TestMethod]
    public void SameEntropyGivesSameCiphertextAndDifferentEntropyDoesNot()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext first = recipient.Encrypt("payload"u8, "aad"u8, pool, "entropy-a");
        using EciesCiphertext second = recipient.Encrypt("payload"u8, "aad"u8, pool, "entropy-a");
        using EciesCiphertext third = recipient.Encrypt("payload"u8, "aad"u8, pool, "entropy-b");

        Assert.IsTrue(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()));
        Assert.IsFalse(first.AsReadOnlySpan().SequenceEqual(third.AsReadOnlySpan()));
    }


    [TestMethod]
    public void PhasedDecryptionWithSimulatedKeyHolderIsByteIdenticalToAllSoftware()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload through an hsm"u8, "aad"u8, pool, "phased");
        using AdditionalData associatedData = AdditionalData.FromCanonical("aad"u8, AdditionalDataRole.Authenticated, pool);
        EciesKeyDerivationDelegate kdf = X963KeyDerivation.Create(Hash, pool);

        EciesPlaintext? software = null;
        EciesPlaintext? phased = null;
        EciesPlaintext? fromKey = null;
        try
        {
            Assert.IsTrue(EciesAlgorithm.TryDecrypt(
                recipient.Scalar, ciphertext, associatedData, Parameters, kdf, TestPlatformCrypto.AesGcmDecrypt, G1ScalarMultiply, pool, out software));

            //Phase one: the library validates E and hands the canonical point to the key holder.
            using G1Point keyHolderInput = EciesAlgorithm.PrepareDecryption(ciphertext, G1ScalarMultiply, pool);
            Assert.IsTrue(keyHolderInput.AsReadOnlySpan().SequenceEqual(ciphertext.GetEphemeralPublicKeyBytes()));

            //The key holder returns Z_AB.
            using SharedSecret sharedSecret = recipient.KeyHolderAgree(keyHolderInput, pool);
            Assert.IsTrue(EciesAlgorithm.TryCompleteDecryption(
                sharedSecret, ciphertext, associatedData, Parameters, kdf, TestPlatformCrypto.AesGcmDecrypt, pool, out phased));

            //Or the key holder derives K itself and returns it.
            using DerivedKeyMaterial keyMaterial = EciesAlgorithm.DeriveKeyMaterial(sharedSecret, associatedData, Parameters, kdf, pool);
            Assert.IsTrue(EciesAlgorithm.TryCompleteDecryption(
                keyMaterial, ciphertext, associatedData, Parameters, TestPlatformCrypto.AesGcmDecrypt, pool, out fromKey));

            Assert.IsNotNull(software);
            Assert.IsNotNull(phased);
            Assert.IsNotNull(fromKey);
            Assert.IsTrue(software.GetBytes().SequenceEqual("payload through an hsm"u8));
            Assert.IsTrue(software.GetBytes().SequenceEqual(phased.GetBytes()));
            Assert.IsTrue(software.GetBytes().SequenceEqual(fromKey.GetBytes()));
        }
        finally
        {
            software?.Dispose();
            phased?.Dispose();
            fromKey?.Dispose();
        }
    }


    [TestMethod]
    public void SharedSecretIsTheXCoordinateBothSidesAgreeOn()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "agree");
        using G1Point ephemeral = EciesAlgorithm.PrepareDecryption(ciphertext, G1ScalarMultiply, pool);
        using SharedSecret recipientSide = recipient.KeyHolderAgree(ephemeral, pool);

        //The sender's side: e·D, with e the deterministic ephemeral scalar.
        Span<byte> ephemeralScalar = stackalloc byte[ScalarSize];
        new DeterministicEntropy("agree").Fill(ephemeralScalar);
        Span<byte> point = stackalloc byte[PointSize];
        Multiply(recipient.PublicKey.AsReadOnlySpan(), ephemeralScalar, point);

        Assert.IsTrue(recipientSide.AsReadOnlySpan().SequenceEqual(point[1..]));
        Assert.AreEqual(SecdsaStructureKind.SharedSecret, recipientSide.Tag.Get<SecdsaStructureKind>());
    }


    [TestMethod]
    public void TamperedAuthenticationTagIsRejectedWithNoPlaintext()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "tag");
        using EciesCiphertext tampered = Tamper(ciphertext, TamperedPart.Tag, pool);

        AssertRejected(recipient, tampered, "aad"u8, pool);
    }


    [TestMethod]
    public void TamperedCiphertextIsRejectedWithNoPlaintext()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "ct");
        using EciesCiphertext tampered = Tamper(ciphertext, TamperedPart.Encrypted, pool);

        AssertRejected(recipient, tampered, "aad"u8, pool);
    }


    [TestMethod]
    public void TamperedAdditionalDataIsRejectedWithNoPlaintext()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "aad");

        AssertRejected(recipient, ciphertext, "aae"u8, pool);
        AssertRejected(recipient, ciphertext, ReadOnlySpan<byte>.Empty, pool);
    }


    [TestMethod]
    public void SubstitutedEphemeralPublicKeyIsRejectedWithNoPlaintext()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "ephemeral");

        //A different valid point: the agreed secret differs, so the derived key and the tag do not match.
        using EciesCiphertext substituted = Tamper(ciphertext, TamperedPart.EphemeralKey, pool);

        AssertRejected(recipient, substituted, "aad"u8, pool);
    }


    [TestMethod]
    public void OffCurveAndInfinityEphemeralKeysAreRejectedByPrepareAndByTryDecrypt()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "invalid-e");
        using EciesCiphertext offCurve = WithEphemeralKey(ciphertext, OffCurvePoint, pool);

        Assert.ThrowsExactly<InvalidOperationException>(() => EciesAlgorithm.PrepareDecryption(offCurve, G1ScalarMultiply, pool));
        AssertRejected(recipient, offCurve, "aad"u8, pool);

        //Infinity has no finite-point shape, so the container refuses to hold it.
        Assert.ThrowsExactly<ArgumentException>(() => WithInfinityEphemeralKey(ciphertext, pool));
    }


    [TestMethod]
    public void WrongRecipientKeyIsRejectedWithNoPlaintext()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using Recipient other = Recipient.Create(pool, "another recipient"u8);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "wrong-key");

        AssertRejected(other, ciphertext, "aad"u8, pool);
    }


    [TestMethod]
    public void CiphertextUnderAnotherParameterSetIsRejected()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "params");
        EciesParameterSet other = EciesParameterSet.Create("another-set", 16, 12, 16, associatedDataIsKdfSharedData: true);

        Assert.IsFalse(Decrypts(recipient, ciphertext, "aad"u8, other, pool));
    }


    [TestMethod]
    public void ParameterSetControlsKeySplitTagLengthAndSharedDataRole()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);

        //AES-128-GCM with a 96-bit tag.
        EciesParameterSet aes128 = EciesParameterSet.Create("test-aes128-tag12", 16, 12, 12, associatedDataIsKdfSharedData: true);
        using EciesCiphertext narrow = recipient.Encrypt("payload"u8, "aad"u8, pool, "p-aes128", aes128);
        int narrowTagBytes = narrow.GetAuthenticationTagBytes().Length;
        Assert.AreEqual(12, narrowTagBytes);
        AssertRoundTripUnder(recipient, narrow, "payload"u8, "aad"u8, aes128, pool);

        //Associated data kept out of the key derivation: the key no longer depends on it, the tag still does.
        EciesParameterSet separate = EciesParameterSet.Create("test-aad-not-in-kdf", 32, 12, 16, associatedDataIsKdfSharedData: false);
        using EciesCiphertext independent = recipient.Encrypt("payload"u8, "aad"u8, pool, "p-separate", separate);
        AssertRoundTripUnder(recipient, independent, "payload"u8, "aad"u8, separate, pool);

        Assert.IsFalse(Decrypts(recipient, independent, "aae"u8, separate, pool));
    }


    [TestMethod]
    public void ParameterSetRejectsInvalidSizes()
    {
        Assert.ThrowsExactly<ArgumentException>(() => EciesParameterSet.Create("", 32, 12, 16, true));
        Assert.ThrowsExactly<ArgumentException>(() => EciesParameterSet.Create("x", 0, 12, 16, true));
        Assert.ThrowsExactly<ArgumentException>(() => EciesParameterSet.Create("x", 32, 0, 16, true));
        Assert.ThrowsExactly<ArgumentException>(() => EciesParameterSet.Create("x", 32, 12, 0, true));
        Assert.ThrowsExactly<ArgumentException>(() => EciesParameterSet.Create("x", 100, 100, 16, true));
        Assert.ThrowsExactly<ArgumentException>(() => EciesParameterSet.Create("x", 32, 12, EciesParameterSet.MaxTagSizeBytes + 1, true));
        Assert.AreEqual(44, EciesParameterSet.X963Sha256Aes256Gcm.KeyMaterialSizeBytes);
    }


    [TestMethod]
    public void BrokenEntropySourceFailsInsteadOfLooping()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);

        Assert.ThrowsExactly<InvalidOperationException>(() => EncryptWithEntropy(recipient, AllOnesEntropy, pool));
        Assert.ThrowsExactly<InvalidOperationException>(() => EncryptWithEntropy(recipient, ZeroEntropy, pool));
    }


    [TestMethod]
    public void CiphertextContainerRejectsMalformedParts()
    {
        using var pool = new BaseMemoryPool();
        using Recipient recipient = Recipient.Create(pool);
        using EciesCiphertext ciphertext = recipient.Encrypt("payload"u8, "aad"u8, pool, "parts");

        Assert.ThrowsExactly<ArgumentException>(() => EciesCiphertext.FromParts(
            ciphertext.GetEphemeralPublicKeyBytes(), ciphertext.GetAuthenticationTagBytes()[1..], ciphertext.GetEncryptedBytes(), Parameters, pool));
        Assert.ThrowsExactly<ArgumentException>(() => EciesCiphertext.FromParts(
            ciphertext.GetEphemeralPublicKeyBytes()[1..], ciphertext.GetAuthenticationTagBytes(), ciphertext.GetEncryptedBytes(), Parameters, pool));
        Assert.ThrowsExactly<ArgumentException>(() => EciesCiphertext.FromParts(
            ciphertext.GetEphemeralPublicKeyBytes(), ciphertext.GetAuthenticationTagBytes(), ciphertext.GetEncryptedBytes(), default, pool));
    }


    [TestMethod]
    public void SharedSecretAndKeyMaterialContainersValidateLengths()
    {
        using var pool = new BaseMemoryPool();

        Assert.ThrowsExactly<ArgumentException>(() => SharedSecret.FromCanonical("short"u8, pool));
        Assert.ThrowsExactly<ArgumentException>(() => DerivedKeyMaterial.FromCanonical("short"u8, Parameters, pool));

        Span<byte> material = stackalloc byte[Parameters.KeyMaterialSizeBytes];
        for(int i = 0; i < material.Length; i++)
        {
            material[i] = (byte)i;
        }

        using DerivedKeyMaterial keyMaterial = DerivedKeyMaterial.FromCanonical(material, Parameters, pool);
        Assert.IsTrue(keyMaterial.GetKeyBytes().SequenceEqual(material[..Parameters.KeySizeBytes]));
        Assert.IsTrue(keyMaterial.GetIvBytes().SequenceEqual(material[Parameters.KeySizeBytes..]));
        Assert.AreEqual(Parameters, keyMaterial.Parameters);
    }


    private static ReadOnlySpan<byte> OffCurvePoint => "\u0002\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u0001"u8;


    private static void ZeroEntropy(Span<byte> destination)
    {
        destination.Clear();
    }


    private static void AllOnesEntropy(Span<byte> destination)
    {
        destination.Fill(0xFF);
    }


    private static EciesCiphertext EncryptWithEntropy(Recipient recipient, SecdsaEntropySource entropy, BaseMemoryPool pool)
    {
        using EciesPlaintext plaintext = EciesPlaintext.FromCanonical("payload"u8, pool);
        using AdditionalData associatedData = AdditionalData.FromCanonical("aad"u8, AdditionalDataRole.Authenticated, pool);

        return EciesAlgorithm.Encrypt(
            plaintext, associatedData, recipient.PublicKey, Parameters, entropy,
            X963KeyDerivation.Create(Hash, pool), TestPlatformCrypto.AesGcmEncrypt, G1ScalarMultiply, pool);
    }


    private static void AssertRoundTrip(Recipient recipient, BaseMemoryPool pool, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        using EciesCiphertext ciphertext = recipient.Encrypt(plaintext, aad, pool, "round-trip");
        AssertRoundTripUnder(recipient, ciphertext, plaintext, aad, Parameters, pool);
    }


    private static void AssertRoundTripUnder(
        Recipient recipient,
        EciesCiphertext ciphertext,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad,
        EciesParameterSet parameters,
        BaseMemoryPool pool)
    {
        using AdditionalData associatedData = AdditionalData.FromCanonical(aad, AdditionalDataRole.Authenticated, pool);
        EciesKeyDerivationDelegate kdf = X963KeyDerivation.Create(Hash, pool);

        EciesPlaintext? recovered = null;
        try
        {
            Assert.IsTrue(EciesAlgorithm.TryDecrypt(
                recipient.Scalar, ciphertext, associatedData, parameters, kdf, TestPlatformCrypto.AesGcmDecrypt, G1ScalarMultiply, pool, out recovered));
            Assert.IsNotNull(recovered);
            Assert.IsTrue(recovered.GetBytes().SequenceEqual(plaintext));
        }
        finally
        {
            recovered?.Dispose();
        }
    }


    private static void AssertRejected(Recipient recipient, EciesCiphertext ciphertext, ReadOnlySpan<byte> aad, BaseMemoryPool pool)
    {
        Assert.IsFalse(Decrypts(recipient, ciphertext, aad, Parameters, pool), "A failed decryption must release no plaintext.");
    }


    /// <summary>Runs the all-software decryption, checks that a plaintext is released exactly when it succeeds, and disposes it.</summary>
    private static bool Decrypts(Recipient recipient, EciesCiphertext ciphertext, ReadOnlySpan<byte> aad, EciesParameterSet parameters, BaseMemoryPool pool)
    {
        using AdditionalData associatedData = AdditionalData.FromCanonical(aad, AdditionalDataRole.Authenticated, pool);
        EciesKeyDerivationDelegate kdf = X963KeyDerivation.Create(Hash, pool);

        EciesPlaintext? plaintext = null;
        try
        {
            bool succeeded = EciesAlgorithm.TryDecrypt(
                recipient.Scalar, ciphertext, associatedData, parameters, kdf, TestPlatformCrypto.AesGcmDecrypt, G1ScalarMultiply, pool, out plaintext);
            Assert.AreEqual(succeeded, plaintext is not null);

            return succeeded;
        }
        finally
        {
            plaintext?.Dispose();
        }
    }


    private enum TamperedPart
    {
        Tag,
        Encrypted,
        EphemeralKey
    }


    private static EciesCiphertext Tamper(EciesCiphertext ciphertext, TamperedPart part, BaseMemoryPool pool)
    {
        Span<byte> ephemeral = stackalloc byte[PointSize];
        Span<byte> tag = stackalloc byte[Parameters.TagSizeBytes];
        Span<byte> encrypted = stackalloc byte[ciphertext.GetEncryptedBytes().Length];
        ciphertext.GetEphemeralPublicKeyBytes().CopyTo(ephemeral);
        ciphertext.GetAuthenticationTagBytes().CopyTo(tag);
        ciphertext.GetEncryptedBytes().CopyTo(encrypted);

        if(part == TamperedPart.Tag)
        {
            tag[0] ^= 0x01;
        }
        else if(part == TamperedPart.Encrypted)
        {
            encrypted[^1] ^= 0x01;
        }
        else
        {
            //A different valid point: twice the original.
            Span<byte> two = stackalloc byte[ScalarSize];
            two.Clear();
            two[^1] = 0x02;
            Span<byte> doubled = stackalloc byte[PointSize];
            Multiply(ephemeral, two, doubled);
            doubled.CopyTo(ephemeral);
        }

        return EciesCiphertext.FromParts(ephemeral, tag, encrypted, Parameters, pool);
    }


    private static EciesCiphertext WithEphemeralKey(EciesCiphertext ciphertext, ReadOnlySpan<byte> ephemeralKey, BaseMemoryPool pool)
    {
        return EciesCiphertext.FromParts(ephemeralKey, ciphertext.GetAuthenticationTagBytes(), ciphertext.GetEncryptedBytes(), Parameters, pool);
    }


    private static EciesCiphertext WithInfinityEphemeralKey(EciesCiphertext ciphertext, BaseMemoryPool pool)
    {
        Span<byte> infinity = stackalloc byte[PointSize];
        infinity.Clear();

        return WithEphemeralKey(ciphertext, infinity, pool);
    }


    /// <summary>A recipient key pair, with the simulated key holder's raw agreement.</summary>
    private sealed class Recipient: IDisposable
    {
        private IMemoryOwner<byte> Material { get; }

        private Recipient(IMemoryOwner<byte> material, PrivateScalar scalar, G1Point publicKey)
        {
            Material = material;
            Scalar = scalar;
            PublicKey = publicKey;
        }

        public ReadOnlySpan<byte> PrivateKey => Material.Memory.Span;

        public PrivateScalar Scalar { get; }

        public G1Point PublicKey { get; }


        public static Recipient Create(BaseMemoryPool pool)
        {
            return Create(pool, "ecies recipient key"u8);
        }


        public static Recipient Create(BaseMemoryPool pool, ReadOnlySpan<byte> label)
        {
            IMemoryOwner<byte> material = pool.Rent(ScalarSize);
            DeriveScalar(label, material.Memory.Span);
            Span<byte> publicKey = stackalloc byte[PointSize];
            PublicPoint(material.Memory.Span, publicKey);

            return new Recipient(material, PrivateScalar.FromCanonical(material.Memory.Span, pool), G1Point.FromCanonical(publicKey, CurveParameterSet.P256, pool));
        }


        public EciesCiphertext Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, BaseMemoryPool pool, string entropyLabel)
        {
            return Encrypt(plaintext, aad, pool, entropyLabel, Parameters);
        }


        public EciesCiphertext Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, BaseMemoryPool pool, string entropyLabel, EciesParameterSet parameters)
        {
            using EciesPlaintext plain = EciesPlaintext.FromCanonical(plaintext, pool);
            using AdditionalData associatedData = AdditionalData.FromCanonical(aad, AdditionalDataRole.Authenticated, pool);

            return EciesAlgorithm.Encrypt(
                plain, associatedData, PublicKey, parameters, new DeterministicEntropy(entropyLabel).Source,
                X963KeyDerivation.Create(Hash, pool), TestPlatformCrypto.AesGcmEncrypt, G1ScalarMultiply, pool);
        }


        public SharedSecret KeyHolderAgree(G1Point ephemeralPublicKey, BaseMemoryPool pool)
        {
            return EciesAlgorithm.AgreeSharedSecret(Scalar, ephemeralPublicKey, G1ScalarMultiply, pool);
        }


        public void Dispose()
        {
            Material.Memory.Span.Clear();
            Material.Dispose();
            Scalar.Dispose();
            PublicKey.Dispose();
        }
    }
}
