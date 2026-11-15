using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers.Binary;
using System.Text;
using System.Text.Unicode;
using static Lumoin.Veridical.Secdsa.P256PointValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The one <see cref="SecdsaLayoutProfile"/> this library ships: a length-prefixed binary layout with fixed-width
/// big-endian integers, SEC1 compressed points and fixed-width scalars.
/// </summary>
/// <remarks>
/// <para>
/// <b>Provisional, not an interoperability format.</b> The paper leaves the byte representation of the signed and
/// derived structures open, and no deployment standard has fixed one. This profile exists so the algorithms are
/// usable and testable; it is identified as provisional by <see cref="ProfileId"/>, and a deployment that needs to
/// interoperate with other implementations supplies its own <see cref="SecdsaLayoutProfile"/> instead.
/// </para>
/// <para>
/// <b>Layout.</b> Every integer is big-endian. A byte string is a 4-byte length followed by the bytes. A point vector
/// is a 4-byte count followed by 33-byte compressed points. A scalar vector is a 4-byte count followed by 32-byte
/// scalars. The index <c>[i]</c> is a 4-byte integer. A leading discriminator byte separates the three structures
/// that are derived or signed: <c>0x01</c> for the derivation input, <c>0x02</c> for the challenge scope and <c>0x03</c>
/// for the response scope.
/// </para>
/// <list type="bullet">
/// <item><description>Derivation input: <c>0x01 ‖ [i] ‖ vector(Ḡ) ‖ vector(D̄) ‖ bytes(AAD)</c>.</description></item>
/// <item><description>Challenge scope: <c>0x02 ‖ E ‖ vector(Ḡ) ‖ vector(D̄) ‖ H2 ‖ bytes(AAD)</c>.</description></item>
/// <item><description>Response scope: <c>0x03 ‖ E ‖ vector(Ḡ) ‖ vector(D̄) ‖ H2 ‖ bytes(AAD) ‖ H1</c>.</description></item>
/// <item><description>Seed payload: <c>Seed ‖ ASD</c> with a 32-byte seed, so the additional secret data is the remainder.</description></item>
/// <item><description>Ciphertext: the canonical form <c>E ‖ T ‖ C</c>, with the tag length fixed by the parameter set.</description></item>
/// <item><description>Challenge: <c>bytes(profile id) ‖ E ‖ H2 ‖ bytes(AAD) ‖ bytes(Sig)</c>.</description></item>
/// <item><description>Response: <c>bytes(profile id) ‖ H1 ‖ bytes(SigP)</c>.</description></item>
/// </list>
/// <para>
/// <b>Injective.</b> Every variable-length field is length-prefixed or is the last field of its structure, every
/// other field has a fixed width, and the discriminator separates the three structures, so two different
/// structures never encode to the same bytes: moving a boundary between adjacent variable-length fields changes a
/// length prefix. The decoders are strict: a length that exceeds the input, a trailing byte or an invalid point
/// rejects the encoding.
/// </para>
/// </remarks>
public static class SecdsaProvisionalLayout
{
    /// <summary>The identifier of this profile.</summary>
    public static SecdsaLayoutProfileId ProfileId { get; } = new("secdsa-layout-provisional-length-prefixed-be32");

    /// <summary>The largest profile identifier a container carries, in UTF-8 bytes.</summary>
    public const int MaxProfileIdBytes = 256;

    private const byte DerivationDiscriminator = 0x01;

    private const byte ChallengeScopeDiscriminator = 0x02;

    private const byte ResponseScopeDiscriminator = 0x03;

    private const int PointSizeBytes = P256PointVector.PointSizeBytes;

    private const int ScalarSizeBytes = P256ScalarVector.ScalarSizeBytes;

    private const int LengthSizeBytes = sizeof(uint);


    /// <summary>The profile.</summary>
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
        writer.AppendUInt32BigEndian((uint)vector.Count);
        writer.Append(vector.AsReadOnlySpan());
    }


    private static bool DecodePointVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256PointVector? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!TryTakePoints(ref rest, out ReadOnlySpan<byte> points) || !rest.IsEmpty)
        {
            return false;
        }

        value = P256PointVector.FromCanonical(points, pool);

        return true;
    }


    private static void EncodeScalarVector(P256ScalarVector vector, LayoutWriter writer)
    {
        writer.AppendUInt32BigEndian((uint)vector.Count);
        writer.Append(vector.AsReadOnlySpan());
    }


    private static bool DecodeScalarVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256ScalarVector? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!TryReadLength(ref rest, out uint count) || count == 0 || count > (uint)(rest.Length / ScalarSizeBytes) || rest.Length != (int)count * ScalarSizeBytes)
        {
            return false;
        }

        for(int offset = 0; offset < rest.Length; offset += ScalarSizeBytes)
        {
            ReadOnlySpan<byte> scalar = rest.Slice(offset, ScalarSizeBytes);
            if(P256ScalarValidation.IsOutOfRange(scalar))
            {
                return false;
            }
        }

        value = P256ScalarVector.FromCanonical(rest, pool);

        return true;
    }


    private static void EncodeDerivationInput(int index, ProofStatement statement, LayoutWriter writer)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        writer.AppendByte(DerivationDiscriminator);
        writer.AppendUInt32BigEndian((uint)index);
        EncodePointVector(statement.Generators, writer);
        EncodePointVector(statement.PublicKeys, writer);
        AppendLengthPrefixed(writer, statement.AdditionalAuthenticatedData.GetBytes());
    }


    private static void EncodeChallengeScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, LayoutWriter writer)
    {
        writer.AppendByte(ChallengeScopeDiscriminator);
        writer.Append(ephemeralPublicKey.AsReadOnlySpan());
        EncodePointVector(statement.Generators, writer);
        EncodePointVector(statement.PublicKeys, writer);
        writer.Append(secondaryDigest.GetBytes());
        AppendLengthPrefixed(writer, statement.AdditionalAuthenticatedData.GetBytes());
    }


    private static void EncodeResponseScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, ProofDigest primaryDigest, LayoutWriter writer)
    {
        writer.AppendByte(ResponseScopeDiscriminator);
        writer.Append(ephemeralPublicKey.AsReadOnlySpan());
        EncodePointVector(statement.Generators, writer);
        EncodePointVector(statement.PublicKeys, writer);
        writer.Append(secondaryDigest.GetBytes());
        AppendLengthPrefixed(writer, statement.AdditionalAuthenticatedData.GetBytes());
        writer.Append(primaryDigest.GetBytes());
    }


    private static void EncodeSeedPayload(ProofSeed seed, AdditionalData additionalSecretData, LayoutWriter writer)
    {
        writer.Append(seed.GetBytes());
        writer.Append(additionalSecretData.GetBytes());
    }


    private static bool DecodeSeedPayload(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out ProofSeed? seed, out AdditionalData? additionalSecretData)
    {
        seed = null;
        additionalSecretData = null;
        if(encoded.Length < ProofSeed.SizeBytes)
        {
            return false;
        }

        seed = ProofSeed.FromCanonical(encoded[..ProofSeed.SizeBytes], pool);
        additionalSecretData = AdditionalData.FromCanonical(encoded[ProofSeed.SizeBytes..], AdditionalDataRole.Secret, pool);

        return true;
    }


    private static void EncodeCiphertext(EciesCiphertext ciphertext, LayoutWriter writer)
    {
        writer.Append(ciphertext.AsReadOnlySpan());
    }


    private static bool DecodeCiphertext(ReadOnlySpan<byte> encoded, EciesParameterSet parameters, BaseMemoryPool pool, out EciesCiphertext? ciphertext)
    {
        ciphertext = null;
        int headerSize = EciesCiphertext.TagOffset + parameters.TagSizeBytes;
        if(encoded.Length < headerSize || !HasFinitePointShape(encoded[..EciesCiphertext.EphemeralPublicKeySizeBytes]))
        {
            return false;
        }

        ciphertext = EciesCiphertext.FromParts(
            encoded[..EciesCiphertext.EphemeralPublicKeySizeBytes],
            encoded.Slice(EciesCiphertext.TagOffset, parameters.TagSizeBytes),
            encoded[headerSize..],
            parameters,
            pool);

        return true;
    }


    private static void EncodeChallenge(TransferableChallenge challenge, LayoutWriter writer)
    {
        AppendProfileId(writer, challenge.Profile);
        writer.Append(challenge.GetEphemeralPublicKeyBytes());
        writer.Append(challenge.GetSecondaryDigestBytes());
        AppendLengthPrefixed(writer, challenge.GetAdditionalAuthenticatedDataBytes());
        AppendLengthPrefixed(writer, challenge.GetSignatureBytes());
    }


    private static bool DecodeChallenge(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableChallenge? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!TryReadProfileId(ref rest, out SecdsaLayoutProfileId profile)
            || !TryTake(ref rest, PointSizeBytes, out ReadOnlySpan<byte> ephemeral)
            || !HasFinitePointShape(ephemeral)
            || !TryTake(ref rest, ProofDigest.SizeBytes, out ReadOnlySpan<byte> secondary)
            || !TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> aad)
            || !TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> signature)
            || !rest.IsEmpty
            || signature.IsEmpty
            || signature.Length > TransferableProofAlgorithm.MaxSignatureSizeBytes)
        {
            return false;
        }

        using G1Point point = G1Point.FromCanonical(ephemeral, CurveParameterSet.P256, pool);
        using ProofDigest digest = ProofDigest.FromCanonical(secondary, ProofDigestKind.Secondary, pool);
        using AdditionalData data = AdditionalData.FromCanonical(aad, AdditionalDataRole.Authenticated, pool);
        value = TransferableChallenge.FromParts(point, digest, data, signature, profile, pool);

        return true;
    }


    private static void EncodeResponse(TransferableResponse response, LayoutWriter writer)
    {
        AppendProfileId(writer, response.Profile);
        writer.Append(response.GetPrimaryDigestBytes());
        AppendLengthPrefixed(writer, response.GetSignatureBytes());
    }


    private static bool DecodeResponse(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableResponse? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!TryReadProfileId(ref rest, out SecdsaLayoutProfileId profile)
            || !TryTake(ref rest, ProofDigest.SizeBytes, out ReadOnlySpan<byte> primary)
            || !TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> signature)
            || !rest.IsEmpty
            || signature.IsEmpty
            || signature.Length > TransferableProofAlgorithm.MaxSignatureSizeBytes)
        {
            return false;
        }

        using ProofDigest digest = ProofDigest.FromCanonical(primary, ProofDigestKind.Primary, pool);
        value = TransferableResponse.FromParts(digest, signature, profile, pool);

        return true;
    }


    private static void AppendLengthPrefixed(LayoutWriter writer, ReadOnlySpan<byte> bytes)
    {
        writer.AppendUInt32BigEndian((uint)bytes.Length);
        writer.Append(bytes);
    }


    private static void AppendProfileId(LayoutWriter writer, SecdsaLayoutProfileId profile)
    {
        int length = Encoding.UTF8.GetByteCount(profile.Identifier);
        if(length == 0 || length > MaxProfileIdBytes)
        {
            throw new ArgumentException($"A profile identifier must be between 1 and {MaxProfileIdBytes} UTF-8 bytes.", nameof(profile));
        }

        Span<byte> utf8 = stackalloc byte[MaxProfileIdBytes];
        Encoding.UTF8.GetBytes(profile.Identifier, utf8);
        AppendLengthPrefixed(writer, utf8[..length]);
    }


    private static bool TryReadLength(ref ReadOnlySpan<byte> rest, out uint length)
    {
        length = 0;
        if(rest.Length < LengthSizeBytes)
        {
            return false;
        }

        length = BinaryPrimitives.ReadUInt32BigEndian(rest);
        rest = rest[LengthSizeBytes..];

        return true;
    }


    private static bool TryTake(ref ReadOnlySpan<byte> rest, int count, out ReadOnlySpan<byte> taken)
    {
        taken = default;
        if(rest.Length < count)
        {
            return false;
        }

        taken = rest[..count];
        rest = rest[count..];

        return true;
    }


    private static bool TryTakeLengthPrefixed(ref ReadOnlySpan<byte> rest, out ReadOnlySpan<byte> bytes)
    {
        bytes = default;
        if(!TryReadLength(ref rest, out uint length) || length > (uint)rest.Length)
        {
            return false;
        }

        bytes = rest[..(int)length];
        rest = rest[(int)length..];

        return true;
    }


    private static bool TryTakePoints(ref ReadOnlySpan<byte> rest, out ReadOnlySpan<byte> points)
    {
        points = default;
        if(!TryReadLength(ref rest, out uint count) || count == 0 || count > (uint)(rest.Length / PointSizeBytes))
        {
            return false;
        }

        int size = (int)count * PointSizeBytes;
        points = rest[..size];
        for(int offset = 0; offset < size; offset += PointSizeBytes)
        {
            if(!HasFinitePointShape(points.Slice(offset, PointSizeBytes)))
            {
                return false;
            }
        }

        rest = rest[size..];

        return true;
    }


    private static bool TryReadProfileId(ref ReadOnlySpan<byte> rest, out SecdsaLayoutProfileId profile)
    {
        profile = default;
        if(!TryTakeLengthPrefixed(ref rest, out ReadOnlySpan<byte> utf8)
            || utf8.IsEmpty
            || utf8.Length > MaxProfileIdBytes
            || !Utf8.IsValid(utf8))
        {
            return false;
        }

        profile = new SecdsaLayoutProfileId(Encoding.UTF8.GetString(utf8));

        return true;
    }
}
