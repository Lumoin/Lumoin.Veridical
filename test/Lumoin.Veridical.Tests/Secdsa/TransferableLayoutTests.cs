using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Secdsa;
using System;
using System.Collections.Generic;
using static Lumoin.Veridical.Tests.Secdsa.SecdsaTestSupport;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the layout profiles: the byte layouts are decided by the profile and nowhere else, a typed value converts
/// losslessly between two profiles, the encodings are injective (a boundary shifted between adjacent variable-length
/// fields changes the bytes), and the decoders are strict about wire data. The second profile is the test-only one.
/// </summary>
[TestClass]
internal sealed class TransferableLayoutTests
{
    private static SecdsaLayoutProfile Shipped { get; } = SecdsaProvisionalLayout.Profile;

    private static SecdsaLayoutProfile Other { get; } = TestLayoutProfile.Profile;


    [TestMethod]
    public void PointVectorConvertsLosslesslyBetweenProfiles()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout points");

        AssertConverts(fixture.Generators, Shipped.EncodePointVector, Shipped.DecodePointVector, Other.EncodePointVector, Other.DecodePointVector, fixture.Pool);
        AssertConverts(fixture.PublicKeys, Other.EncodePointVector, Other.DecodePointVector, Shipped.EncodePointVector, Shipped.DecodePointVector, fixture.Pool);
    }


    [TestMethod]
    public void ScalarVectorConvertsLosslesslyBetweenProfiles()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout scalars");
        Span<byte> scalars = stackalloc byte[3 * ScalarSize];
        DeriveScalar("layout scalar 0"u8, scalars[..ScalarSize]);
        DeriveScalar("layout scalar 1"u8, scalars.Slice(ScalarSize, ScalarSize));
        DeriveScalar("layout scalar 2"u8, scalars[(2 * ScalarSize)..]);
        using P256ScalarVector vector = P256ScalarVector.FromCanonical(scalars, fixture.Pool);

        AssertConverts(vector, Shipped.EncodeScalarVector, Shipped.DecodeScalarVector, Other.EncodeScalarVector, Other.DecodeScalarVector, fixture.Pool);
        AssertConverts(vector, Other.EncodeScalarVector, Other.DecodeScalarVector, Shipped.EncodeScalarVector, Shipped.DecodeScalarVector, fixture.Pool);
    }


    [TestMethod]
    public void ChallengeAndResponseConvertLosslesslyAndKeepTheSigningProfile()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout containers");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);

        AssertConverts(issued.Challenge, Shipped.EncodeChallenge, Shipped.DecodeChallenge, Other.EncodeChallenge, Other.DecodeChallenge, fixture.Pool);
        AssertConverts(prover.Response, Shipped.EncodeResponse, Shipped.DecodeResponse, Other.EncodeResponse, Other.DecodeResponse, fixture.Pool);

        //Converted to the other transport layout, the value still records the profile it was signed under and still verifies under it.
        using LayoutWriter challengeBytes = new(fixture.Pool);
        Other.EncodeChallenge(issued.Challenge, challengeBytes);
        using LayoutWriter responseBytes = new(fixture.Pool);
        Other.EncodeResponse(prover.Response, responseBytes);
        Assert.IsTrue(Other.DecodeChallenge(challengeBytes.WrittenBytes, fixture.Pool, out TransferableChallenge? challenge));
        Assert.IsTrue(Other.DecodeResponse(responseBytes.WrittenBytes, fixture.Pool, out TransferableResponse? response));
        using(challenge)
        using(response)
        {
            Assert.AreEqual(Shipped.Id, challenge!.Profile);
            Assert.AreEqual(Shipped.Id, response!.Profile);
            Assert.AreEqual(TransferableProofVerdict.Accept, fixture.Verify(challenge, response));
        }
    }


    [TestMethod]
    public void CiphertextConvertsLosslesslyBetweenProfiles()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout ciphertext");
        using IssuedChallenge issued = fixture.Issue();
        using LayoutWriter shippedBytes = new(fixture.Pool);
        Shipped.EncodeCiphertext(issued.Ciphertext, shippedBytes);
        Assert.IsTrue(Shipped.DecodeCiphertext(shippedBytes.WrittenBytes, TransferableFixture.Parameters, fixture.Pool, out EciesCiphertext? viaShipped));
        using(viaShipped)
        {
            using LayoutWriter otherBytes = new(fixture.Pool);
            Other.EncodeCiphertext(viaShipped!, otherBytes);
            Assert.IsFalse(otherBytes.WrittenBytes.SequenceEqual(shippedBytes.WrittenBytes));
            Assert.IsTrue(Other.DecodeCiphertext(otherBytes.WrittenBytes, TransferableFixture.Parameters, fixture.Pool, out EciesCiphertext? viaOther));
            using(viaOther)
            {
                Assert.IsTrue(viaOther!.AsReadOnlySpan().SequenceEqual(issued.Ciphertext.AsReadOnlySpan()));
            }
        }
    }


    [TestMethod]
    public void SeedPayloadConvertsLosslesslyBetweenProfiles()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout payload");
        using LayoutWriter shippedBytes = new(fixture.Pool);
        Shipped.EncodeSeedPayload(fixture.Seed, fixture.SecretData, shippedBytes);
        Assert.IsTrue(Shipped.DecodeSeedPayload(shippedBytes.WrittenBytes, fixture.Pool, out ProofSeed? seed, out AdditionalData? data));
        using(seed)
        using(data)
        {
            using LayoutWriter otherBytes = new(fixture.Pool);
            Other.EncodeSeedPayload(seed!, data!, otherBytes);
            Assert.IsFalse(otherBytes.WrittenBytes.SequenceEqual(shippedBytes.WrittenBytes));
            Assert.IsTrue(Other.DecodeSeedPayload(otherBytes.WrittenBytes, fixture.Pool, out ProofSeed? seedBack, out AdditionalData? dataBack));
            using(seedBack)
            using(dataBack)
            {
                Assert.IsTrue(seedBack!.GetBytes().SequenceEqual(fixture.Seed.GetBytes()));
                Assert.IsTrue(dataBack!.GetBytes().SequenceEqual(fixture.SecretData.GetBytes()));
            }
        }
    }


    [TestMethod]
    public void EmptyAdditionalSecretDataSurvivesBothPayloadLayouts()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout empty payload");
        using AdditionalData empty = AdditionalData.FromCanonical(ReadOnlySpan<byte>.Empty, AdditionalDataRole.Secret, fixture.Pool);
        foreach(SecdsaLayoutProfile profile in new[] { Shipped, Other })
        {
            using LayoutWriter bytes = new(fixture.Pool);
            profile.EncodeSeedPayload(fixture.Seed, empty, bytes);
            Assert.IsTrue(profile.DecodeSeedPayload(bytes.WrittenBytes, fixture.Pool, out ProofSeed? seed, out AdditionalData? data));
            using(seed)
            using(data)
            {
                Assert.AreEqual(0, data!.Length);
            }
        }
    }


    [TestMethod]
    public void ProfilesEncodeTheSignedStructuresToDifferentBytes()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout differ");
        using IssuedChallenge issued = fixture.Issue();
        using G1Point ephemeral = issued.Challenge.GetEphemeralPublicKey(fixture.Pool);
        using ProofDigest secondary = issued.Challenge.GetSecondaryDigest(fixture.Pool);
        using LayoutWriter first = new(fixture.Pool);
        using LayoutWriter second = new(fixture.Pool);
        Shipped.EncodeChallengeScope(ephemeral, fixture.Statement, secondary, first);
        Other.EncodeChallengeScope(ephemeral, fixture.Statement, secondary, second);

        Assert.IsFalse(first.WrittenBytes.SequenceEqual(second.WrittenBytes));
    }


    [TestMethod]
    public void AdditionalDataBoundaryShiftChangesTheScopeBytesUnderBothProfiles()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout injective aad");
        using IssuedChallenge issued = fixture.Issue();
        using G1Point ephemeral = issued.Challenge.GetEphemeralPublicKey(fixture.Pool);
        using ProofDigest secondary = issued.Challenge.GetSecondaryDigest(fixture.Pool);
        using ProofDigest primary = ProofDigest.FromCanonical(secondary.GetBytes(), ProofDigestKind.Primary, fixture.Pool);

        foreach(SecdsaLayoutProfile profile in new[] { Shipped, Other })
        {
            HashSet<string> encodings = [];
            ReadOnlySpan<byte> material = "aab"u8;
            for(int length = 0; length <= material.Length; length++)
            {
                //The same bytes with the boundary between the additional data and the following field moved by one.
                using AdditionalData aad = AdditionalData.FromCanonical(material[..length], AdditionalDataRole.Authenticated, fixture.Pool);
                ProofStatement statement = new(fixture.Generators, fixture.PublicKeys, aad);
                using LayoutWriter challengeScope = new(fixture.Pool);
                using LayoutWriter responseScope = new(fixture.Pool);
                using LayoutWriter derivation = new(fixture.Pool);
                profile.EncodeChallengeScope(ephemeral, statement, secondary, challengeScope);
                profile.EncodeResponseScope(ephemeral, statement, secondary, primary, responseScope);
                profile.EncodeDerivationInput(0, statement, derivation);

                Assert.IsTrue(encodings.Add(Convert.ToHexString(challengeScope.WrittenBytes)), "Challenge scope collided.");
                Assert.IsTrue(encodings.Add(Convert.ToHexString(responseScope.WrittenBytes)), "Response scope collided.");
                Assert.IsTrue(encodings.Add(Convert.ToHexString(derivation.WrittenBytes)), "Derivation input collided.");
            }

            Assert.HasCount(4 * 3, encodings);
        }
    }


    [TestMethod]
    public void DerivationIndexDistinguishesEveryKey()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout index");

        foreach(SecdsaLayoutProfile profile in new[] { Shipped, Other })
        {
            HashSet<string> encodings = [];
            for(int index = 0; index < TransferableFixture.GeneratorCount; index++)
            {
                using LayoutWriter derivation = new(fixture.Pool);
                profile.EncodeDerivationInput(index, fixture.Statement, derivation);
                Assert.IsTrue(encodings.Add(Convert.ToHexString(derivation.WrittenBytes)));
            }
        }
    }


    [TestMethod]
    public void ContainerBoundaryShiftBetweenAdjacentVariableFieldsChangesTheBytes()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout injective containers");
        using IssuedChallenge issued = fixture.Issue();
        ReadOnlySpan<byte> ephemeral = issued.Challenge.GetEphemeralPublicKeyBytes();
        ReadOnlySpan<byte> secondary = issued.Challenge.GetSecondaryDigestBytes();

        foreach(SecdsaLayoutProfile profile in new[] { Shipped, Other })
        {
            //AAD || Sig is "ab" || "cd" in both: only the boundary moves.
            using TransferableChallenge first = fixture.Rebuild(issued.Challenge, ephemeral, secondary, "ab"u8, "cd"u8);
            using TransferableChallenge second = fixture.Rebuild(issued.Challenge, ephemeral, secondary, "a"u8, "bcd"u8);
            using LayoutWriter firstBytes = new(fixture.Pool);
            using LayoutWriter secondBytes = new(fixture.Pool);
            profile.EncodeChallenge(first, firstBytes);
            profile.EncodeChallenge(second, secondBytes);

            Assert.IsFalse(firstBytes.WrittenBytes.SequenceEqual(secondBytes.WrittenBytes));
        }

        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);
        foreach(SecdsaLayoutProfile profile in new[] { Shipped, Other })
        {
            //Profile identifier || signature is "idab" || "cd" in both: only the boundary moves.
            using TransferableResponse first = fixture.Rebuild(prover.Response, prover.Response.GetPrimaryDigestBytes(), "cd"u8, new SecdsaLayoutProfileId("idab"));
            using TransferableResponse second = fixture.Rebuild(prover.Response, prover.Response.GetPrimaryDigestBytes(), "d"u8, new SecdsaLayoutProfileId("idabc"));
            using LayoutWriter firstBytes = new(fixture.Pool);
            using LayoutWriter secondBytes = new(fixture.Pool);
            profile.EncodeResponse(first, firstBytes);
            profile.EncodeResponse(second, secondBytes);

            Assert.IsFalse(firstBytes.WrittenBytes.SequenceEqual(secondBytes.WrittenBytes));
        }
    }


    [TestMethod]
    public void ShippedDecodersRejectTrailingTruncatedAndOversizedInput()
    {
        using TransferableFixture fixture = TransferableFixture.Create("layout strict");
        using IssuedChallenge issued = fixture.Issue();
        using LayoutWriter encoded = new(fixture.Pool);
        Shipped.EncodeChallenge(issued.Challenge, encoded);
        ReadOnlySpan<byte> valid = encoded.WrittenBytes;

        Assert.IsTrue(DecodesChallenge(valid, fixture.Pool));
        Assert.IsFalse(DecodesChallenge(valid[..^1], fixture.Pool), "A truncated encoding must be rejected.");
        Assert.IsFalse(DecodesChallenge(valid[..4], fixture.Pool));
        Assert.IsFalse(DecodesChallenge(ReadOnlySpan<byte>.Empty, fixture.Pool));

        Span<byte> trailing = stackalloc byte[valid.Length + 1];
        valid.CopyTo(trailing);
        Assert.IsFalse(DecodesChallenge(trailing, fixture.Pool), "A trailing byte must be rejected.");

        Span<byte> oversized = stackalloc byte[valid.Length];
        valid.CopyTo(oversized);
        oversized[0] = 0xFF;
        Assert.IsFalse(DecodesChallenge(oversized, fixture.Pool), "A length that exceeds the input must be rejected.");

        Span<byte> noPoint = stackalloc byte[ScalarSize + sizeof(uint)];
        Assert.IsFalse(Shipped.DecodePointVector(noPoint, fixture.Pool, out P256PointVector? none));
        Assert.IsNull(none);
        none?.Dispose();
    }


    private static bool DecodesChallenge(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        bool decoded = Shipped.DecodeChallenge(bytes, pool, out TransferableChallenge? challenge);
        challenge?.Dispose();

        return decoded;
    }


    private static void AssertConverts<T>(
        T value,
        LayoutEncodeDelegate<T> encodeFirst,
        LayoutDecodeDelegate<T> decodeFirst,
        LayoutEncodeDelegate<T> encodeSecond,
        LayoutDecodeDelegate<T> decodeSecond,
        BaseMemoryPool pool)
        where T : SensitiveMemory
    {
        using LayoutWriter firstBytes = new(pool);
        encodeFirst(value, firstBytes);
        Assert.IsTrue(decodeFirst(firstBytes.WrittenBytes, pool, out T? viaFirst));
        using(viaFirst)
        {
            Assert.IsTrue(viaFirst!.AsReadOnlySpan().SequenceEqual(value.AsReadOnlySpan()), "Decoding the first layout must give the value back.");

            using LayoutWriter secondBytes = new(pool);
            encodeSecond(viaFirst, secondBytes);
            Assert.IsFalse(secondBytes.WrittenBytes.SequenceEqual(firstBytes.WrittenBytes), "The two layouts must differ.");
            Assert.IsTrue(decodeSecond(secondBytes.WrittenBytes, pool, out T? viaSecond));
            using(viaSecond)
            {
                Assert.IsTrue(viaSecond!.AsReadOnlySpan().SequenceEqual(value.AsReadOnlySpan()), "Converting to the second layout and back must be lossless.");
            }
        }
    }
}
