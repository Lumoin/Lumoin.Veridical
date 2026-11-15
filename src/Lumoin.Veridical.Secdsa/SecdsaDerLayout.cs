using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Text;
using static Lumoin.Veridical.Secdsa.P256PointValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// A <see cref="SecdsaLayoutProfile"/> that writes every structure as ASN.1 DER (ITU-T X.690, distinguished
/// encoding rules): definite lengths in the minimal form, SEQUENCE for structures and vectors, OCTET STRING for
/// points, scalars, digests, seeds, additional data and signatures, and INTEGER for the index and for the structure
/// discriminator.
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
/// <b>Structure definitions.</b> Points are SEC 1 compressed (33 octets), scalars are 32 octets big-endian, digests
/// are 32 octets, the seed is 32 octets.
/// </para>
/// <code>
/// SecdsaDerLayout DEFINITIONS ::= BEGIN
///   PointVector  ::= SEQUENCE SIZE (1..MAX) OF OCTET STRING (SIZE (33))
///   ScalarVector ::= SEQUENCE SIZE (1..MAX) OF OCTET STRING (SIZE (32))
///
///   PointVectorStructure  ::= SEQUENCE { kind INTEGER (8), points PointVector }
///   ScalarVectorStructure ::= SEQUENCE { kind INTEGER (9), scalars ScalarVector }
///
///   DerivationInput ::= SEQUENCE { kind INTEGER (1), index INTEGER (0..2147483647),
///                                  generators PointVector, publicKeys PointVector, aad OCTET STRING }
///   ChallengeScope  ::= SEQUENCE { kind INTEGER (2), e OCTET STRING (SIZE (33)),
///                                  generators PointVector, publicKeys PointVector,
///                                  h2 OCTET STRING (SIZE (32)), aad OCTET STRING }
///   ResponseScope   ::= SEQUENCE { kind INTEGER (3), e OCTET STRING (SIZE (33)),
///                                  generators PointVector, publicKeys PointVector,
///                                  h2 OCTET STRING (SIZE (32)), aad OCTET STRING,
///                                  h1 OCTET STRING (SIZE (32)) }
///   SeedPayload     ::= SEQUENCE { kind INTEGER (4), seed OCTET STRING (SIZE (32)), asd OCTET STRING }
///   Ciphertext      ::= SEQUENCE { kind INTEGER (5), e OCTET STRING (SIZE (33)),
///                                  tag OCTET STRING, encrypted OCTET STRING }
///   Challenge       ::= SEQUENCE { kind INTEGER (6), profile UTF8String (SIZE (1..256)),
///                                  e OCTET STRING (SIZE (33)), h2 OCTET STRING (SIZE (32)),
///                                  aad OCTET STRING, sig OCTET STRING (SIZE (1..65536)) }
///   Response        ::= SEQUENCE { kind INTEGER (7), profile UTF8String (SIZE (1..256)),
///                                  h1 OCTET STRING (SIZE (32)), sig OCTET STRING (SIZE (1..65536)) }
/// END
/// </code>
/// <para>
/// The generators <c>Ḡ</c>, the public keys <c>D̄</c>, the ephemeral public key <c>E</c>, the hashes <c>H1</c> and
/// <c>H2</c> and the additional authenticated data <c>AAD</c> of the scopes are the paper's names. The ciphertext
/// tag length is fixed by the ECIES parameter set the receiver is configured with. The scalar vector, the derivation
/// input and the seed payload carry secrets, so their encoders write only into the pooled
/// <see cref="LayoutWriter"/>, which clears its buffer.
/// </para>
/// <para>
/// <b>Injective.</b> Every element is self-delimiting with a definite length, so moving a boundary between adjacent
/// variable-length fields changes a length octet; the leading <c>kind</c> integer differs for every structure, so
/// two different structure kinds never encode to the same bytes. The decoders are strict: they reject a non-minimal
/// length or integer, an indefinite length, a wrong tag, a length beyond the input, an invalid point, a negative
/// integer and every trailing byte.
/// </para>
/// <para>
/// <b>Profile identity.</b> A challenge or response container carries the identifier of the profile its signature
/// was formed under, as the <c>profile</c> field, whichever profile wrote the container. Decoding it with this
/// profile therefore restores the signing profile in the value's tag, and the signed scope bytes are rebuilt with
/// that profile.
/// </para>
/// </remarks>
public static class SecdsaDerLayout
{
    /// <summary>The identifier of this profile.</summary>
    public static SecdsaLayoutProfileId ProfileId { get; } = new("secdsa-layout-der-x690");

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

    private static int PointElementSize { get; } = SecdsaDer.ElementSize(PointSizeBytes);

    private static int ScalarElementSize { get; } = SecdsaDer.ElementSize(ScalarSizeBytes);


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


    /// <summary>Encodes a point vector as <c>PointVectorStructure</c>.</summary>
    private static void EncodePointVector(P256PointVector vector, LayoutWriter writer)
    {
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, SecdsaDer.IntegerSize(PointVectorKind) + PointsSize(vector));
        SecdsaDer.WriteInteger(writer, PointVectorKind);
        WritePoints(writer, vector);
    }


    /// <summary>Decodes a <c>PointVectorStructure</c>.</summary>
    private static bool DecodePointVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256PointVector? value)
    {
        value = null;
        if(!SecdsaDer.TryOpenStructure(encoded, PointVectorKind, out ReadOnlySpan<byte> content)
            || !TryReadVector(ref content, PointElementSize, out ReadOnlySpan<byte> elements)
            || !content.IsEmpty)
        {
            return false;
        }

        int count = elements.Length / PointElementSize;
        using IMemoryOwner<byte> points = pool.Rent(count * PointSizeBytes);
        Span<byte> destination = points.Memory.Span[..(count * PointSizeBytes)];
        if(!TryCollect(elements, PointElementSize, PointSizeBytes, destination) || !AllFinitePoints(destination))
        {
            return false;
        }

        value = P256PointVector.FromCanonical(destination, pool);

        return true;
    }


    /// <summary>Encodes a scalar vector as <c>ScalarVectorStructure</c>.</summary>
    private static void EncodeScalarVector(P256ScalarVector vector, LayoutWriter writer)
    {
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, SecdsaDer.IntegerSize(ScalarVectorKind) + ScalarsSize(vector));
        SecdsaDer.WriteInteger(writer, ScalarVectorKind);
        WriteScalars(writer, vector);
    }


    /// <summary>Decodes a <c>ScalarVectorStructure</c>, rejecting a scalar that is not in the range of valid scalars.</summary>
    private static bool DecodeScalarVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256ScalarVector? value)
    {
        value = null;
        if(!SecdsaDer.TryOpenStructure(encoded, ScalarVectorKind, out ReadOnlySpan<byte> content)
            || !TryReadVector(ref content, ScalarElementSize, out ReadOnlySpan<byte> elements)
            || !content.IsEmpty)
        {
            return false;
        }

        int count = elements.Length / ScalarElementSize;
        using IMemoryOwner<byte> scalars = pool.Rent(count * ScalarSizeBytes);
        Span<byte> destination = scalars.Memory.Span[..(count * ScalarSizeBytes)];
        try
        {
            if(!TryCollect(elements, ScalarElementSize, ScalarSizeBytes, destination))
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


    /// <summary>Encodes <c>DerivationInput</c>.</summary>
    private static void EncodeDerivationInput(int index, ProofStatement statement, LayoutWriter writer)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ReadOnlySpan<byte> aad = statement.AdditionalAuthenticatedData.GetBytes();
        int content = SecdsaDer.IntegerSize(DerivationKind)
            + SecdsaDer.IntegerSize((uint)index)
            + PointsSize(statement.Generators)
            + PointsSize(statement.PublicKeys)
            + SecdsaDer.ElementSize(aad.Length);
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, content);
        SecdsaDer.WriteInteger(writer, DerivationKind);
        SecdsaDer.WriteInteger(writer, (uint)index);
        WritePoints(writer, statement.Generators);
        WritePoints(writer, statement.PublicKeys);
        SecdsaDer.WriteOctetString(writer, aad);
    }


    /// <summary>Encodes <c>ChallengeScope</c>.</summary>
    private static void EncodeChallengeScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, LayoutWriter writer)
    {
        ReadOnlySpan<byte> aad = statement.AdditionalAuthenticatedData.GetBytes();
        int content = SecdsaDer.IntegerSize(ChallengeScopeKind)
            + PointElementSize
            + PointsSize(statement.Generators)
            + PointsSize(statement.PublicKeys)
            + SecdsaDer.ElementSize(DigestSizeBytes)
            + SecdsaDer.ElementSize(aad.Length);
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, content);
        SecdsaDer.WriteInteger(writer, ChallengeScopeKind);
        SecdsaDer.WriteOctetString(writer, ephemeralPublicKey.AsReadOnlySpan());
        WritePoints(writer, statement.Generators);
        WritePoints(writer, statement.PublicKeys);
        SecdsaDer.WriteOctetString(writer, secondaryDigest.GetBytes());
        SecdsaDer.WriteOctetString(writer, aad);
    }


    /// <summary>Encodes <c>ResponseScope</c>.</summary>
    private static void EncodeResponseScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, ProofDigest primaryDigest, LayoutWriter writer)
    {
        ReadOnlySpan<byte> aad = statement.AdditionalAuthenticatedData.GetBytes();
        int content = SecdsaDer.IntegerSize(ResponseScopeKind)
            + PointElementSize
            + PointsSize(statement.Generators)
            + PointsSize(statement.PublicKeys)
            + SecdsaDer.ElementSize(DigestSizeBytes)
            + SecdsaDer.ElementSize(aad.Length)
            + SecdsaDer.ElementSize(DigestSizeBytes);
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, content);
        SecdsaDer.WriteInteger(writer, ResponseScopeKind);
        SecdsaDer.WriteOctetString(writer, ephemeralPublicKey.AsReadOnlySpan());
        WritePoints(writer, statement.Generators);
        WritePoints(writer, statement.PublicKeys);
        SecdsaDer.WriteOctetString(writer, secondaryDigest.GetBytes());
        SecdsaDer.WriteOctetString(writer, aad);
        SecdsaDer.WriteOctetString(writer, primaryDigest.GetBytes());
    }


    /// <summary>Encodes <c>SeedPayload</c>.</summary>
    private static void EncodeSeedPayload(ProofSeed seed, AdditionalData additionalSecretData, LayoutWriter writer)
    {
        ReadOnlySpan<byte> asd = additionalSecretData.GetBytes();
        int content = SecdsaDer.IntegerSize(SeedPayloadKind) + SecdsaDer.ElementSize(ProofSeed.SizeBytes) + SecdsaDer.ElementSize(asd.Length);
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, content);
        SecdsaDer.WriteInteger(writer, SeedPayloadKind);
        SecdsaDer.WriteOctetString(writer, seed.GetBytes());
        SecdsaDer.WriteOctetString(writer, asd);
    }


    /// <summary>Decodes a <c>SeedPayload</c>.</summary>
    private static bool DecodeSeedPayload(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out ProofSeed? seed, out AdditionalData? additionalSecretData)
    {
        seed = null;
        additionalSecretData = null;
        if(!SecdsaDer.TryOpenStructure(encoded, SeedPayloadKind, out ReadOnlySpan<byte> content)
            || !SecdsaDer.TryReadOctetString(ref content, ProofSeed.SizeBytes, out ReadOnlySpan<byte> seedBytes)
            || !SecdsaDer.TryReadOctetString(ref content, out ReadOnlySpan<byte> asd)
            || !content.IsEmpty)
        {
            return false;
        }

        seed = ProofSeed.FromCanonical(seedBytes, pool);
        additionalSecretData = AdditionalData.FromCanonical(asd, AdditionalDataRole.Secret, pool);

        return true;
    }


    /// <summary>Encodes <c>Ciphertext</c>.</summary>
    private static void EncodeCiphertext(EciesCiphertext ciphertext, LayoutWriter writer)
    {
        ReadOnlySpan<byte> tag = ciphertext.GetAuthenticationTagBytes();
        ReadOnlySpan<byte> encrypted = ciphertext.GetEncryptedBytes();
        int content = SecdsaDer.IntegerSize(CiphertextKind)
            + PointElementSize
            + SecdsaDer.ElementSize(tag.Length)
            + SecdsaDer.ElementSize(encrypted.Length);
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, content);
        SecdsaDer.WriteInteger(writer, CiphertextKind);
        SecdsaDer.WriteOctetString(writer, ciphertext.GetEphemeralPublicKeyBytes());
        SecdsaDer.WriteOctetString(writer, tag);
        SecdsaDer.WriteOctetString(writer, encrypted);
    }


    /// <summary>Decodes a <c>Ciphertext</c>; the tag must have the length of the parameter set.</summary>
    private static bool DecodeCiphertext(ReadOnlySpan<byte> encoded, EciesParameterSet parameters, BaseMemoryPool pool, out EciesCiphertext? ciphertext)
    {
        ciphertext = null;
        if(!SecdsaDer.TryOpenStructure(encoded, CiphertextKind, out ReadOnlySpan<byte> content)
            || !SecdsaDer.TryReadOctetString(ref content, PointSizeBytes, out ReadOnlySpan<byte> ephemeral)
            || !HasFinitePointShape(ephemeral)
            || !SecdsaDer.TryReadOctetString(ref content, parameters.TagSizeBytes, out ReadOnlySpan<byte> tag)
            || !SecdsaDer.TryReadOctetString(ref content, out ReadOnlySpan<byte> encrypted)
            || !content.IsEmpty)
        {
            return false;
        }

        ciphertext = EciesCiphertext.FromParts(ephemeral, tag, encrypted, parameters, pool);

        return true;
    }


    /// <summary>Encodes <c>Challenge</c>.</summary>
    private static void EncodeChallenge(TransferableChallenge challenge, LayoutWriter writer)
    {
        Span<byte> id = stackalloc byte[MaxProfileIdBytes];
        ReadOnlySpan<byte> utf8 = ProfileIdBytes(challenge.Profile, id);
        ReadOnlySpan<byte> aad = challenge.GetAdditionalAuthenticatedDataBytes();
        ReadOnlySpan<byte> signature = challenge.GetSignatureBytes();
        int content = SecdsaDer.IntegerSize(ChallengeKind)
            + SecdsaDer.ElementSize(utf8.Length)
            + PointElementSize
            + SecdsaDer.ElementSize(DigestSizeBytes)
            + SecdsaDer.ElementSize(aad.Length)
            + SecdsaDer.ElementSize(signature.Length);
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, content);
        SecdsaDer.WriteInteger(writer, ChallengeKind);
        SecdsaDer.WriteUtf8String(writer, utf8);
        SecdsaDer.WriteOctetString(writer, challenge.GetEphemeralPublicKeyBytes());
        SecdsaDer.WriteOctetString(writer, challenge.GetSecondaryDigestBytes());
        SecdsaDer.WriteOctetString(writer, aad);
        SecdsaDer.WriteOctetString(writer, signature);
    }


    /// <summary>Decodes a <c>Challenge</c>, restoring the profile identifier it was signed under.</summary>
    private static bool DecodeChallenge(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableChallenge? value)
    {
        value = null;
        if(!SecdsaDer.TryOpenStructure(encoded, ChallengeKind, out ReadOnlySpan<byte> content)
            || !SecdsaDer.TryReadUtf8String(ref content, MaxProfileIdBytes, out string profile)
            || !SecdsaDer.TryReadOctetString(ref content, PointSizeBytes, out ReadOnlySpan<byte> ephemeral)
            || !HasFinitePointShape(ephemeral)
            || !SecdsaDer.TryReadOctetString(ref content, DigestSizeBytes, out ReadOnlySpan<byte> secondary)
            || !SecdsaDer.TryReadOctetString(ref content, out ReadOnlySpan<byte> aad)
            || !SecdsaDer.TryReadOctetString(ref content, out ReadOnlySpan<byte> signature)
            || !content.IsEmpty
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


    /// <summary>Encodes <c>Response</c>.</summary>
    private static void EncodeResponse(TransferableResponse response, LayoutWriter writer)
    {
        Span<byte> id = stackalloc byte[MaxProfileIdBytes];
        ReadOnlySpan<byte> utf8 = ProfileIdBytes(response.Profile, id);
        ReadOnlySpan<byte> signature = response.GetSignatureBytes();
        int content = SecdsaDer.IntegerSize(ResponseKind)
            + SecdsaDer.ElementSize(utf8.Length)
            + SecdsaDer.ElementSize(DigestSizeBytes)
            + SecdsaDer.ElementSize(signature.Length);
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, content);
        SecdsaDer.WriteInteger(writer, ResponseKind);
        SecdsaDer.WriteUtf8String(writer, utf8);
        SecdsaDer.WriteOctetString(writer, response.GetPrimaryDigestBytes());
        SecdsaDer.WriteOctetString(writer, signature);
    }


    /// <summary>Decodes a <c>Response</c>, restoring the profile identifier it was signed under.</summary>
    private static bool DecodeResponse(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableResponse? value)
    {
        value = null;
        if(!SecdsaDer.TryOpenStructure(encoded, ResponseKind, out ReadOnlySpan<byte> content)
            || !SecdsaDer.TryReadUtf8String(ref content, MaxProfileIdBytes, out string profile)
            || !SecdsaDer.TryReadOctetString(ref content, DigestSizeBytes, out ReadOnlySpan<byte> primary)
            || !SecdsaDer.TryReadOctetString(ref content, out ReadOnlySpan<byte> signature)
            || !content.IsEmpty
            || signature.IsEmpty
            || signature.Length > TransferableProofAlgorithm.MaxSignatureSizeBytes)
        {
            return false;
        }

        using ProofDigest digest = ProofDigest.FromCanonical(primary, ProofDigestKind.Primary, pool);
        value = TransferableResponse.FromParts(digest, signature, new SecdsaLayoutProfileId(profile), pool);

        return true;
    }


    /// <summary>Returns the size of a point vector as a SEQUENCE OF OCTET STRING, header included.</summary>
    private static int PointsSize(P256PointVector vector) => SecdsaDer.ElementSize(vector.Count * PointElementSize);


    /// <summary>Returns the size of a scalar vector as a SEQUENCE OF OCTET STRING, header included.</summary>
    private static int ScalarsSize(P256ScalarVector vector) => SecdsaDer.ElementSize(vector.Count * ScalarElementSize);


    /// <summary>Appends a point vector as a SEQUENCE OF OCTET STRING.</summary>
    private static void WritePoints(LayoutWriter writer, P256PointVector vector)
    {
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, vector.Count * PointElementSize);
        for(int index = 0; index < vector.Count; index++)
        {
            SecdsaDer.WriteOctetString(writer, vector.GetPointBytes(index));
        }
    }


    /// <summary>Appends a scalar vector as a SEQUENCE OF OCTET STRING.</summary>
    private static void WriteScalars(LayoutWriter writer, P256ScalarVector vector)
    {
        SecdsaDer.WriteHeader(writer, SecdsaDer.SequenceTag, vector.Count * ScalarElementSize);
        for(int index = 0; index < vector.Count; index++)
        {
            SecdsaDer.WriteOctetString(writer, vector.GetScalarBytes(index));
        }
    }


    /// <summary>Reads the SEQUENCE of a vector and requires a non-empty whole number of elements of the given encoded size.</summary>
    private static bool TryReadVector(ref ReadOnlySpan<byte> content, int elementSize, out ReadOnlySpan<byte> elements)
    {
        return SecdsaDer.TryReadElement(ref content, SecdsaDer.SequenceTag, out elements)
            && !elements.IsEmpty
            && elements.Length % elementSize == 0;
    }


    /// <summary>Strips the OCTET STRING headers of equally sized elements into a contiguous buffer, checking every tag and length.</summary>
    private static bool TryCollect(ReadOnlySpan<byte> elements, int elementSize, int valueSize, Span<byte> destination)
    {
        ReadOnlySpan<byte> rest = elements;
        for(int offset = 0; offset < destination.Length; offset += valueSize)
        {
            if(!SecdsaDer.TryReadOctetString(ref rest, valueSize, out ReadOnlySpan<byte> value))
            {
                return false;
            }

            value.CopyTo(destination[offset..]);
        }

        return rest.IsEmpty && elements.Length == elementSize * (destination.Length / valueSize);
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
