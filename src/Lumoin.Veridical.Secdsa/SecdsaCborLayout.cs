using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Text;
using static Lumoin.Veridical.Secdsa.P256PointValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// A <see cref="SecdsaLayoutProfile"/> that writes every structure as CBOR (RFC 8949) in the core deterministic
/// encoding of section 4.2: definite lengths and shortest-form heads, arrays for structures and vectors, byte
/// strings for points, scalars, digests, seeds, additional data and signatures, and unsigned integers for the index
/// and for the structure discriminator.
/// </summary>
/// <remarks>
/// <para>
/// <b>What is standard and what is not.</b> The encoding rules are the standard ones named above. The structure
/// definitions below, their field order and their discriminators, are this library's own: the paper defines no byte
/// layout for the signed structures or the containers, so interoperability with another implementation of the paper
/// is not established by this profile. Two parties that both follow the definitions here interoperate; nothing
/// beyond that is claimed.
/// </para>
/// <para>
/// <b>Structure definitions.</b> Points are SEC 1 compressed (33 bytes), scalars are 32 bytes big-endian, digests
/// are 32 bytes, the seed is 32 bytes. In CDDL (RFC 8610):
/// </para>
/// <code>
/// point         = bstr .size 33
/// scalar        = bstr .size 32
/// digest        = bstr .size 32
/// point-vector  = [1* point]
/// scalar-vector = [1* scalar]
/// profile-id    = tstr .size (1..256)
/// signature     = bstr .size (1..65536)
///
/// point-vector-structure  = [8, point-vector]
/// scalar-vector-structure = [9, scalar-vector]
/// derivation-input = [1, index: 0..2147483647, generators: point-vector, public-keys: point-vector, aad: bstr]
/// challenge-scope  = [2, e: point, generators: point-vector, public-keys: point-vector, h2: digest, aad: bstr]
/// response-scope   = [3, e: point, generators: point-vector, public-keys: point-vector, h2: digest, aad: bstr, h1: digest]
/// seed-payload     = [4, seed: bstr .size 32, asd: bstr]
/// ciphertext       = [5, e: point, tag: bstr, encrypted: bstr]
/// challenge        = [6, profile-id, e: point, h2: digest, aad: bstr, sig: signature]
/// response         = [7, profile-id, h1: digest, sig: signature]
/// </code>
/// <para>
/// The generators <c>Ḡ</c>, the public keys <c>D̄</c>, the ephemeral public key <c>E</c>, the hashes <c>H1</c> and
/// <c>H2</c> and the additional authenticated data <c>AAD</c> of the scopes are the paper's names. The ciphertext
/// tag length is fixed by the ECIES parameter set the receiver is configured with. The scalar vector, the derivation
/// input and the seed payload carry secrets, so their encoders write only into the pooled
/// <see cref="LayoutWriter"/>, which clears its buffer.
/// </para>
/// <para>
/// <b>Injective.</b> Every item is self-delimiting with a definite length, so moving a boundary between adjacent
/// variable-length fields changes a length head; the leading discriminator differs for every structure, so two
/// different structure kinds never encode to the same bytes. The decoders are strict: they reject a head that is
/// not the shortest form of its value, an indefinite length, a wrong major type or element count, a length beyond
/// the input, an invalid point and every trailing byte.
/// </para>
/// <para>
/// <b>Profile identity.</b> A challenge or response container carries the identifier of the profile its signature
/// was formed under, as the <c>profile-id</c> field, whichever profile wrote the container. Decoding it with this
/// profile therefore restores the signing profile in the value's tag, and the signed scope bytes are rebuilt with
/// that profile.
/// </para>
/// </remarks>
public static class SecdsaCborLayout
{
    /// <summary>The identifier of this profile.</summary>
    public static SecdsaLayoutProfileId ProfileId { get; } = new("secdsa-layout-cbor-rfc8949-deterministic");

    private const uint DerivationKind = 1;

    private const uint ChallengeScopeKind = 2;

    private const uint ResponseScopeKind = 3;

    private const uint SeedPayloadKind = 4;

    private const uint CiphertextKind = 5;

    private const uint ChallengeKind = 6;

    private const uint ResponseKind = 7;

    private const uint PointVectorKind = 8;

    private const uint ScalarVectorKind = 9;

    private const int PointSizeBytes = P256PointVector.PointSizeBytes;

    private const int ScalarSizeBytes = P256ScalarVector.ScalarSizeBytes;

    private const int DigestSizeBytes = ProofDigest.SizeBytes;

    private const int MaxProfileIdBytes = SecdsaProvisionalLayout.MaxProfileIdBytes;

    private const int VectorStructureElements = 2;

    private const int DerivationElements = 5;

    private const int ChallengeScopeElements = 6;

    private const int ResponseScopeElements = 7;

    private const int SeedPayloadElements = 3;

    private const int CiphertextElements = 4;

    private const int ChallengeElements = 6;

    private const int ResponseElements = 4;

    private static int PointItemSize { get; } = SecdsaCbor.HeadSize(PointSizeBytes) + PointSizeBytes;

    private static int ScalarItemSize { get; } = SecdsaCbor.HeadSize(ScalarSizeBytes) + ScalarSizeBytes;


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


    /// <summary>Encodes a point vector as <c>point-vector-structure</c>.</summary>
    private static void EncodePointVector(P256PointVector vector, LayoutWriter writer)
    {
        SecdsaCbor.WriteArrayHead(writer, VectorStructureElements);
        SecdsaCbor.WriteUnsigned(writer, PointVectorKind);
        WritePoints(writer, vector);
    }


    /// <summary>Decodes a <c>point-vector-structure</c>.</summary>
    private static bool DecodePointVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256PointVector? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!SecdsaCbor.TryOpenStructure(ref rest, VectorStructureElements, PointVectorKind)
            || !TryReadVectorHead(ref rest, PointItemSize, out int count))
        {
            return false;
        }

        using IMemoryOwner<byte> points = pool.Rent(count * PointSizeBytes);
        Span<byte> destination = points.Memory.Span[..(count * PointSizeBytes)];
        if(!TryCollect(ref rest, PointSizeBytes, destination) || !rest.IsEmpty || !AllFinitePoints(destination))
        {
            return false;
        }

        value = P256PointVector.FromCanonical(destination, pool);

        return true;
    }


    /// <summary>Encodes a scalar vector as <c>scalar-vector-structure</c>.</summary>
    private static void EncodeScalarVector(P256ScalarVector vector, LayoutWriter writer)
    {
        SecdsaCbor.WriteArrayHead(writer, VectorStructureElements);
        SecdsaCbor.WriteUnsigned(writer, ScalarVectorKind);
        WriteScalars(writer, vector);
    }


    /// <summary>Decodes a <c>scalar-vector-structure</c>, rejecting a scalar that is not in the range of valid scalars.</summary>
    private static bool DecodeScalarVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256ScalarVector? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!SecdsaCbor.TryOpenStructure(ref rest, VectorStructureElements, ScalarVectorKind)
            || !TryReadVectorHead(ref rest, ScalarItemSize, out int count))
        {
            return false;
        }

        using IMemoryOwner<byte> scalars = pool.Rent(count * ScalarSizeBytes);
        Span<byte> destination = scalars.Memory.Span[..(count * ScalarSizeBytes)];
        try
        {
            if(!TryCollect(ref rest, ScalarSizeBytes, destination) || !rest.IsEmpty)
            {
                return false;
            }

            for(int offset = 0; offset < destination.Length; offset += ScalarSizeBytes)
            {
                if(P256ScalarValidation.IsOutOfRange(destination.Slice(offset, ScalarSizeBytes)))
                {
                    return false;
                }
            }

            value = P256ScalarVector.FromCanonical(destination, pool);

            return true;
        }
        finally
        {
            destination.Clear();
        }
    }


    /// <summary>Encodes <c>derivation-input</c>.</summary>
    private static void EncodeDerivationInput(int index, ProofStatement statement, LayoutWriter writer)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        SecdsaCbor.WriteArrayHead(writer, DerivationElements);
        SecdsaCbor.WriteUnsigned(writer, DerivationKind);
        SecdsaCbor.WriteUnsigned(writer, (uint)index);
        WritePoints(writer, statement.Generators);
        WritePoints(writer, statement.PublicKeys);
        SecdsaCbor.WriteByteString(writer, statement.AdditionalAuthenticatedData.GetBytes());
    }


    /// <summary>Encodes <c>challenge-scope</c>.</summary>
    private static void EncodeChallengeScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, LayoutWriter writer)
    {
        SecdsaCbor.WriteArrayHead(writer, ChallengeScopeElements);
        SecdsaCbor.WriteUnsigned(writer, ChallengeScopeKind);
        SecdsaCbor.WriteByteString(writer, ephemeralPublicKey.AsReadOnlySpan());
        WritePoints(writer, statement.Generators);
        WritePoints(writer, statement.PublicKeys);
        SecdsaCbor.WriteByteString(writer, secondaryDigest.GetBytes());
        SecdsaCbor.WriteByteString(writer, statement.AdditionalAuthenticatedData.GetBytes());
    }


    /// <summary>Encodes <c>response-scope</c>.</summary>
    private static void EncodeResponseScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, ProofDigest primaryDigest, LayoutWriter writer)
    {
        SecdsaCbor.WriteArrayHead(writer, ResponseScopeElements);
        SecdsaCbor.WriteUnsigned(writer, ResponseScopeKind);
        SecdsaCbor.WriteByteString(writer, ephemeralPublicKey.AsReadOnlySpan());
        WritePoints(writer, statement.Generators);
        WritePoints(writer, statement.PublicKeys);
        SecdsaCbor.WriteByteString(writer, secondaryDigest.GetBytes());
        SecdsaCbor.WriteByteString(writer, statement.AdditionalAuthenticatedData.GetBytes());
        SecdsaCbor.WriteByteString(writer, primaryDigest.GetBytes());
    }


    /// <summary>Encodes <c>seed-payload</c>.</summary>
    private static void EncodeSeedPayload(ProofSeed seed, AdditionalData additionalSecretData, LayoutWriter writer)
    {
        SecdsaCbor.WriteArrayHead(writer, SeedPayloadElements);
        SecdsaCbor.WriteUnsigned(writer, SeedPayloadKind);
        SecdsaCbor.WriteByteString(writer, seed.GetBytes());
        SecdsaCbor.WriteByteString(writer, additionalSecretData.GetBytes());
    }


    /// <summary>Decodes a <c>seed-payload</c>.</summary>
    private static bool DecodeSeedPayload(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out ProofSeed? seed, out AdditionalData? additionalSecretData)
    {
        seed = null;
        additionalSecretData = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!SecdsaCbor.TryOpenStructure(ref rest, SeedPayloadElements, SeedPayloadKind)
            || !SecdsaCbor.TryReadByteString(ref rest, ProofSeed.SizeBytes, out ReadOnlySpan<byte> seedBytes)
            || !SecdsaCbor.TryReadByteString(ref rest, out ReadOnlySpan<byte> asd)
            || !rest.IsEmpty)
        {
            return false;
        }

        seed = ProofSeed.FromCanonical(seedBytes, pool);
        additionalSecretData = AdditionalData.FromCanonical(asd, AdditionalDataRole.Secret, pool);

        return true;
    }


    /// <summary>Encodes <c>ciphertext</c>.</summary>
    private static void EncodeCiphertext(EciesCiphertext ciphertext, LayoutWriter writer)
    {
        SecdsaCbor.WriteArrayHead(writer, CiphertextElements);
        SecdsaCbor.WriteUnsigned(writer, CiphertextKind);
        SecdsaCbor.WriteByteString(writer, ciphertext.GetEphemeralPublicKeyBytes());
        SecdsaCbor.WriteByteString(writer, ciphertext.GetAuthenticationTagBytes());
        SecdsaCbor.WriteByteString(writer, ciphertext.GetEncryptedBytes());
    }


    /// <summary>Decodes a <c>ciphertext</c>; the tag must have the length of the parameter set.</summary>
    private static bool DecodeCiphertext(ReadOnlySpan<byte> encoded, EciesParameterSet parameters, BaseMemoryPool pool, out EciesCiphertext? ciphertext)
    {
        ciphertext = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!SecdsaCbor.TryOpenStructure(ref rest, CiphertextElements, CiphertextKind)
            || !SecdsaCbor.TryReadByteString(ref rest, PointSizeBytes, out ReadOnlySpan<byte> ephemeral)
            || !HasFinitePointShape(ephemeral)
            || !SecdsaCbor.TryReadByteString(ref rest, parameters.TagSizeBytes, out ReadOnlySpan<byte> tag)
            || !SecdsaCbor.TryReadByteString(ref rest, out ReadOnlySpan<byte> encrypted)
            || !rest.IsEmpty)
        {
            return false;
        }

        ciphertext = EciesCiphertext.FromParts(ephemeral, tag, encrypted, parameters, pool);

        return true;
    }


    /// <summary>Encodes <c>challenge</c>.</summary>
    private static void EncodeChallenge(TransferableChallenge challenge, LayoutWriter writer)
    {
        Span<byte> id = stackalloc byte[MaxProfileIdBytes];
        SecdsaCbor.WriteArrayHead(writer, ChallengeElements);
        SecdsaCbor.WriteUnsigned(writer, ChallengeKind);
        SecdsaCbor.WriteTextString(writer, ProfileIdBytes(challenge.Profile, id));
        SecdsaCbor.WriteByteString(writer, challenge.GetEphemeralPublicKeyBytes());
        SecdsaCbor.WriteByteString(writer, challenge.GetSecondaryDigestBytes());
        SecdsaCbor.WriteByteString(writer, challenge.GetAdditionalAuthenticatedDataBytes());
        SecdsaCbor.WriteByteString(writer, challenge.GetSignatureBytes());
    }


    /// <summary>Decodes a <c>challenge</c>, restoring the profile identifier it was signed under.</summary>
    private static bool DecodeChallenge(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableChallenge? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!SecdsaCbor.TryOpenStructure(ref rest, ChallengeElements, ChallengeKind)
            || !SecdsaCbor.TryReadTextString(ref rest, MaxProfileIdBytes, out string profile)
            || !SecdsaCbor.TryReadByteString(ref rest, PointSizeBytes, out ReadOnlySpan<byte> ephemeral)
            || !HasFinitePointShape(ephemeral)
            || !SecdsaCbor.TryReadByteString(ref rest, DigestSizeBytes, out ReadOnlySpan<byte> secondary)
            || !SecdsaCbor.TryReadByteString(ref rest, out ReadOnlySpan<byte> aad)
            || !SecdsaCbor.TryReadByteString(ref rest, out ReadOnlySpan<byte> signature)
            || !rest.IsEmpty
            || signature.IsEmpty
            || signature.Length > TransferableProofAlgorithm.MaxSignatureSizeBytes)
        {
            return false;
        }

        using G1Point point = G1Point.FromCanonical(ephemeral, CurveParameterSet.P256, pool);
        using ProofDigest digest = ProofDigest.FromCanonical(secondary, ProofDigestKind.Secondary, pool);
        using AdditionalData data = AdditionalData.FromCanonical(aad, AdditionalDataRole.Authenticated, pool);
        value = TransferableChallenge.FromParts(point, digest, data, signature, new SecdsaLayoutProfileId(profile), pool);

        return true;
    }


    /// <summary>Encodes <c>response</c>.</summary>
    private static void EncodeResponse(TransferableResponse response, LayoutWriter writer)
    {
        Span<byte> id = stackalloc byte[MaxProfileIdBytes];
        SecdsaCbor.WriteArrayHead(writer, ResponseElements);
        SecdsaCbor.WriteUnsigned(writer, ResponseKind);
        SecdsaCbor.WriteTextString(writer, ProfileIdBytes(response.Profile, id));
        SecdsaCbor.WriteByteString(writer, response.GetPrimaryDigestBytes());
        SecdsaCbor.WriteByteString(writer, response.GetSignatureBytes());
    }


    /// <summary>Decodes a <c>response</c>, restoring the profile identifier it was signed under.</summary>
    private static bool DecodeResponse(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableResponse? value)
    {
        value = null;
        ReadOnlySpan<byte> rest = encoded;
        if(!SecdsaCbor.TryOpenStructure(ref rest, ResponseElements, ResponseKind)
            || !SecdsaCbor.TryReadTextString(ref rest, MaxProfileIdBytes, out string profile)
            || !SecdsaCbor.TryReadByteString(ref rest, DigestSizeBytes, out ReadOnlySpan<byte> primary)
            || !SecdsaCbor.TryReadByteString(ref rest, out ReadOnlySpan<byte> signature)
            || !rest.IsEmpty
            || signature.IsEmpty
            || signature.Length > TransferableProofAlgorithm.MaxSignatureSizeBytes)
        {
            return false;
        }

        using ProofDigest digest = ProofDigest.FromCanonical(primary, ProofDigestKind.Primary, pool);
        value = TransferableResponse.FromParts(digest, signature, new SecdsaLayoutProfileId(profile), pool);

        return true;
    }


    /// <summary>Appends a point vector as an array of byte strings.</summary>
    private static void WritePoints(LayoutWriter writer, P256PointVector vector)
    {
        SecdsaCbor.WriteArrayHead(writer, vector.Count);
        for(int index = 0; index < vector.Count; index++)
        {
            SecdsaCbor.WriteByteString(writer, vector.GetPointBytes(index));
        }
    }


    /// <summary>Appends a scalar vector as an array of byte strings.</summary>
    private static void WriteScalars(LayoutWriter writer, P256ScalarVector vector)
    {
        SecdsaCbor.WriteArrayHead(writer, vector.Count);
        for(int index = 0; index < vector.Count; index++)
        {
            SecdsaCbor.WriteByteString(writer, vector.GetScalarBytes(index));
        }
    }


    /// <summary>Reads the head of a vector array and requires a non-empty count that the remaining input can hold.</summary>
    private static bool TryReadVectorHead(ref ReadOnlySpan<byte> rest, int itemSize, out int count)
    {
        count = 0;
        if(!SecdsaCbor.TryReadHead(ref rest, SecdsaCbor.ArrayMajor, out uint elements) || elements == 0 || elements > (uint)(rest.Length / itemSize))
        {
            return false;
        }

        count = (int)elements;

        return true;
    }


    /// <summary>Reads equally sized byte strings into a contiguous buffer, checking every head and length.</summary>
    private static bool TryCollect(ref ReadOnlySpan<byte> rest, int valueSize, Span<byte> destination)
    {
        for(int offset = 0; offset < destination.Length; offset += valueSize)
        {
            if(!SecdsaCbor.TryReadByteString(ref rest, valueSize, out ReadOnlySpan<byte> value))
            {
                return false;
            }

            value.CopyTo(destination[offset..]);
        }

        return true;
    }


    /// <summary>Checks that every point in a contiguous run has the shape of a finite compressed point.</summary>
    private static bool AllFinitePoints(ReadOnlySpan<byte> points)
    {
        for(int offset = 0; offset < points.Length; offset += PointSizeBytes)
        {
            if(!HasFinitePointShape(points.Slice(offset, PointSizeBytes)))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Encodes a profile identifier as UTF-8 into the buffer, requiring one to <see cref="MaxProfileIdBytes"/> bytes.</summary>
    private static ReadOnlySpan<byte> ProfileIdBytes(SecdsaLayoutProfileId profile, Span<byte> buffer)
    {
        int length = Encoding.UTF8.GetByteCount(profile.Identifier);
        if(length == 0 || length > MaxProfileIdBytes)
        {
            throw new ArgumentException($"A profile identifier must be between 1 and {MaxProfileIdBytes} UTF-8 bytes.", nameof(profile));
        }

        Encoding.UTF8.GetBytes(profile.Identifier, buffer);

        return buffer[..length];
    }
}
