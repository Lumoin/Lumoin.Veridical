using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Secdsa;
using System;
using System.Buffers.Binary;
using System.Text;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// A second layout profile that exists only to prove that the transferable-proof algorithms are independent of the
/// byte layouts: 16-bit length prefixes, a different field order in every structure, different discriminators and a
/// different order of the fields of the containers. A value signed under it is rejected under the shipped profile and
/// the other way round, and a typed value converts losslessly between the two.
/// </summary>
internal static class TestLayoutProfile
{
    private const byte DerivationDiscriminator = 0x11;

    private const byte ChallengeScopeDiscriminator = 0x12;

    private const byte ResponseScopeDiscriminator = 0x13;

    private const int PointSize = P256PointVector.PointSizeBytes;

    private const int ScalarSize = P256ScalarVector.ScalarSizeBytes;

    private const int LengthSize = sizeof(ushort);


    /// <summary>The identifier of the test profile.</summary>
    public static SecdsaLayoutProfileId ProfileId { get; } = new("test-layout-u16-reordered");


    /// <summary>The test profile.</summary>
    public static SecdsaLayoutProfile Profile { get; } = new SecdsaLayoutProfile
    {
        Id = ProfileId,
        EncodePointVector = EncodePointVector,
        DecodePointVector = DecodePointVector,
        EncodeScalarVector = EncodeScalarVector,
        DecodeScalarVector = DecodeScalarVector,
        EncodeDerivationInput = EncodeDerivationInput,
        EncodeChallengeScope = EncodeChallengeScope,
        EncodeResponseScope = EncodeResponseScope,
        EncodeSeedPayload = EncodeSeedPayload,
        DecodeSeedPayload = DecodeSeedPayload,
        EncodeCiphertext = EncodeCiphertext,
        DecodeCiphertext = DecodeCiphertext,
        EncodeChallenge = EncodeChallenge,
        DecodeChallenge = DecodeChallenge,
        EncodeResponse = EncodeResponse,
        DecodeResponse = DecodeResponse
    };


    private static void EncodePointVector(P256PointVector vector, LayoutWriter writer)
    {
        writer.AppendUInt16BigEndian((ushort)vector.Count);
        writer.Append(vector.AsReadOnlySpan());
    }


    private static bool DecodePointVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256PointVector? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!TryReadCount(ref rest, PointSize, out ReadOnlySpan<byte> points) || !rest.IsEmpty)
        {
            return false;
        }

        value = P256PointVector.FromCanonical(points, pool);

        return true;
    }


    private static void EncodeScalarVector(P256ScalarVector vector, LayoutWriter writer)
    {
        writer.AppendUInt16BigEndian((ushort)vector.Count);
        writer.Append(vector.AsReadOnlySpan());
    }


    private static bool DecodeScalarVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256ScalarVector? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!TryReadCount(ref rest, ScalarSize, out ReadOnlySpan<byte> scalars) || !rest.IsEmpty)
        {
            return false;
        }

        value = P256ScalarVector.FromCanonical(scalars, pool);

        return true;
    }


    private static void EncodeDerivationInput(int index, ProofStatement statement, LayoutWriter writer)
    {
        writer.AppendByte(DerivationDiscriminator);
        EncodePointVector(statement.PublicKeys, writer);
        EncodePointVector(statement.Generators, writer);
        writer.AppendUInt16BigEndian((ushort)index);
        AppendLengthPrefixed(writer, statement.AdditionalAuthenticatedData.GetBytes());
    }


    private static void EncodeChallengeScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, LayoutWriter writer)
    {
        writer.AppendByte(ChallengeScopeDiscriminator);
        AppendLengthPrefixed(writer, statement.AdditionalAuthenticatedData.GetBytes());
        writer.Append(secondaryDigest.GetBytes());
        EncodePointVector(statement.Generators, writer);
        EncodePointVector(statement.PublicKeys, writer);
        writer.Append(ephemeralPublicKey.AsReadOnlySpan());
    }


    private static void EncodeResponseScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, ProofDigest primaryDigest, LayoutWriter writer)
    {
        writer.AppendByte(ResponseScopeDiscriminator);
        writer.Append(primaryDigest.GetBytes());
        AppendLengthPrefixed(writer, statement.AdditionalAuthenticatedData.GetBytes());
        writer.Append(secondaryDigest.GetBytes());
        EncodePointVector(statement.Generators, writer);
        EncodePointVector(statement.PublicKeys, writer);
        writer.Append(ephemeralPublicKey.AsReadOnlySpan());
    }


    private static void EncodeSeedPayload(ProofSeed seed, AdditionalData additionalSecretData, LayoutWriter writer)
    {
        AppendLengthPrefixed(writer, additionalSecretData.GetBytes());
        writer.Append(seed.GetBytes());
    }


    private static bool DecodeSeedPayload(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out ProofSeed? seed, out AdditionalData? additionalSecretData)
    {
        seed = null;
        additionalSecretData = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> data) || rest.Length != ProofSeed.SizeBytes)
        {
            return false;
        }

        seed = ProofSeed.FromCanonical(rest, pool);
        additionalSecretData = AdditionalData.FromCanonical(data, AdditionalDataRole.Secret, pool);

        return true;
    }


    private static void EncodeCiphertext(EciesCiphertext ciphertext, LayoutWriter writer)
    {
        writer.Append(ciphertext.GetEphemeralPublicKeyBytes());
        writer.Append(ciphertext.GetEncryptedBytes());
        writer.Append(ciphertext.GetAuthenticationTagBytes());
    }


    private static bool DecodeCiphertext(ReadOnlySpan<byte> encoded, EciesParameterSet parameters, BaseMemoryPool pool, out EciesCiphertext? ciphertext)
    {
        ciphertext = null;
        int overhead = PointSize + parameters.TagSizeBytes;
        if(encoded.Length < overhead)
        {
            return false;
        }

        ReadOnlySpan<byte> ephemeral = encoded[..PointSize];
        ReadOnlySpan<byte> encrypted = encoded[PointSize..^parameters.TagSizeBytes];
        ReadOnlySpan<byte> tag = encoded[^parameters.TagSizeBytes..];
        ciphertext = EciesCiphertext.FromParts(ephemeral, tag, encrypted, parameters, pool);

        return true;
    }


    private static void EncodeChallenge(TransferableChallenge challenge, LayoutWriter writer)
    {
        AppendLengthPrefixed(writer, Encoding.UTF8.GetBytes(challenge.Profile.Identifier));
        AppendLengthPrefixed(writer, challenge.GetSignatureBytes());
        AppendLengthPrefixed(writer, challenge.GetAdditionalAuthenticatedDataBytes());
        writer.Append(challenge.GetSecondaryDigestBytes());
        writer.Append(challenge.GetEphemeralPublicKeyBytes());
    }


    private static bool DecodeChallenge(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableChallenge? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> id)
            || !TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> signature)
            || !TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> aad)
            || rest.Length != ProofDigest.SizeBytes + PointSize
            || id.IsEmpty
            || signature.IsEmpty)
        {
            return false;
        }

        using G1Point point = G1Point.FromCanonical(rest[ProofDigest.SizeBytes..], CurveParameterSet.P256, pool);
        using ProofDigest digest = ProofDigest.FromCanonical(rest[..ProofDigest.SizeBytes], ProofDigestKind.Secondary, pool);
        using AdditionalData data = AdditionalData.FromCanonical(aad, AdditionalDataRole.Authenticated, pool);
        value = TransferableChallenge.FromParts(point, digest, data, signature, new SecdsaLayoutProfileId(Encoding.UTF8.GetString(id)), pool);

        return true;
    }


    private static void EncodeResponse(TransferableResponse response, LayoutWriter writer)
    {
        AppendLengthPrefixed(writer, Encoding.UTF8.GetBytes(response.Profile.Identifier));
        AppendLengthPrefixed(writer, response.GetSignatureBytes());
        writer.Append(response.GetPrimaryDigestBytes());
    }


    private static bool DecodeResponse(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableResponse? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> id)
            || !TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> signature)
            || rest.Length != ProofDigest.SizeBytes
            || id.IsEmpty
            || signature.IsEmpty)
        {
            return false;
        }

        using ProofDigest digest = ProofDigest.FromCanonical(rest, ProofDigestKind.Primary, pool);
        value = TransferableResponse.FromParts(digest, signature, new SecdsaLayoutProfileId(Encoding.UTF8.GetString(id)), pool);

        return true;
    }


    private static void AppendLengthPrefixed(LayoutWriter writer, ReadOnlySpan<byte> bytes)
    {
        writer.AppendUInt16BigEndian((ushort)bytes.Length);
        writer.Append(bytes);
    }


    private static bool TryTakeLengthPrefixed(ref ReadOnlySpan<byte> rest, out ReadOnlySpan<byte> bytes)
    {
        bytes = default;
        if(rest.Length < LengthSize)
        {
            return false;
        }

        int length = BinaryPrimitives.ReadUInt16BigEndian(rest);
        if(rest.Length - LengthSize < length)
        {
            return false;
        }

        bytes = rest.Slice(LengthSize, length);
        rest = rest[(LengthSize + length)..];

        return true;
    }


    private static bool TryReadCount(ref ReadOnlySpan<byte> rest, int elementSize, out ReadOnlySpan<byte> elements)
    {
        elements = default;
        if(rest.Length < LengthSize)
        {
            return false;
        }

        int count = BinaryPrimitives.ReadUInt16BigEndian(rest);
        int size = count * elementSize;
        if(count == 0 || rest.Length - LengthSize < size)
        {
            return false;
        }

        elements = rest.Slice(LengthSize, size);
        rest = rest[(LengthSize + size)..];

        return true;
    }
}
