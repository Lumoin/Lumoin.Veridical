using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veritas.Cbor;
using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using static Lumoin.Veridical.Secdsa.P256PointValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// A <see cref="SecdsaLayoutProfile"/> that writes every structure as CBOR (RFC 8949) in the core deterministic
/// encoding of section 4.2, produced and read by Lumoin.Veritas.Cbor in its deterministic conformance mode: definite
/// lengths and shortest-form heads, arrays for structures and vectors, byte
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
/// different structure kinds never encode to the same bytes. The decoders are strict: they reject a wrong major type
/// or element count, a length beyond the input, an invalid point and every trailing byte, and, because the
/// Lumoin.Veritas.Cbor reader does not itself refuse a head that is not the shortest form of its value, each decoder
/// re-encodes what it decoded and accepts the input only when the bytes are identical, which rules out every
/// non-shortest head and every other non-deterministic form.
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

    private const int SmallByteStringHeadBytes = 2;

    private const int PointItemBytes = SmallByteStringHeadBytes + PointSizeBytes;

    private const int ScalarItemBytes = SmallByteStringHeadBytes + ScalarSizeBytes;


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
        CborWriter cbor = SecdsaCbor.CreateWriter(writer);
        cbor.WriteStartArray(VectorStructureElements);
        cbor.WriteUInt64(PointVectorKind);
        WritePoints(cbor, vector);
        cbor.WriteEndArray();
    }


    /// <summary>Decodes a <c>point-vector-structure</c>.</summary>
    private static bool DecodePointVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256PointVector? value)
    {
        value = null;
        using IMemoryOwner<byte> input = SecdsaCbor.Rent(encoded, pool);
        try
        {
            CborReader reader = SecdsaCbor.CreateReader(input.Memory[..encoded.Length]);
            if(!SecdsaCbor.TryOpenStructure(reader, VectorStructureElements, PointVectorKind)
                || !SecdsaCbor.TryReadVectorHead(reader, encoded.Length / PointItemBytes, out int count))
            {
                return false;
            }

            using IMemoryOwner<byte> points = pool.Rent(count * PointSizeBytes);
            Span<byte> destination = points.Memory.Span[..(count * PointSizeBytes)];
            if(!TryCollect(reader, PointSizeBytes, destination)
                || !SecdsaCbor.TryCloseStructure(reader, encoded.Length)
                || !AllFinitePoints(destination))
            {
                return false;
            }

            value = P256PointVector.FromCanonical(destination, pool);
            using LayoutWriter canonical = new(pool);
            EncodePointVector(value, canonical);
            if(!CryptographicOperations.FixedTimeEquals(canonical.WrittenBytes, encoded))
            {
                value.Dispose();
                value = null;

                return false;
            }

            return true;
        }
        catch(Exception exception) when(SecdsaCbor.IsMalformation(exception))
        {
            return false;
        }
    }


    /// <summary>Encodes a scalar vector as <c>scalar-vector-structure</c>.</summary>
    private static void EncodeScalarVector(P256ScalarVector vector, LayoutWriter writer)
    {
        CborWriter cbor = SecdsaCbor.CreateWriter(writer);
        cbor.WriteStartArray(VectorStructureElements);
        cbor.WriteUInt64(ScalarVectorKind);
        WriteScalars(cbor, vector);
        cbor.WriteEndArray();
    }


    /// <summary>Decodes a <c>scalar-vector-structure</c>, rejecting a scalar that is not in the range of valid scalars.</summary>
    private static bool DecodeScalarVector(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out P256ScalarVector? value)
    {
        value = null;
        using IMemoryOwner<byte> input = SecdsaCbor.Rent(encoded, pool);
        try
        {
            CborReader reader = SecdsaCbor.CreateReader(input.Memory[..encoded.Length]);
            if(!SecdsaCbor.TryOpenStructure(reader, VectorStructureElements, ScalarVectorKind)
                || !SecdsaCbor.TryReadVectorHead(reader, encoded.Length / ScalarItemBytes, out int count))
            {
                return false;
            }

            using IMemoryOwner<byte> scalars = pool.Rent(count * ScalarSizeBytes);
            Span<byte> destination = scalars.Memory.Span[..(count * ScalarSizeBytes)];
            try
            {
                if(!TryCollect(reader, ScalarSizeBytes, destination) || !SecdsaCbor.TryCloseStructure(reader, encoded.Length))
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
                using LayoutWriter canonical = new(pool);
                EncodeScalarVector(value, canonical);
                if(!CryptographicOperations.FixedTimeEquals(canonical.WrittenBytes, encoded))
                {
                    value.Dispose();
                    value = null;

                    return false;
                }

                return true;
            }
            finally
            {
                destination.Clear();
            }
        }
        catch(Exception exception) when(SecdsaCbor.IsMalformation(exception))
        {
            return false;
        }
        finally
        {
            input.Memory.Span.Clear();
        }
    }


    /// <summary>Encodes <c>derivation-input</c>.</summary>
    private static void EncodeDerivationInput(int index, ProofStatement statement, LayoutWriter writer)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        CborWriter cbor = SecdsaCbor.CreateWriter(writer);
        cbor.WriteStartArray(DerivationElements);
        cbor.WriteUInt64(DerivationKind);
        cbor.WriteUInt64((ulong)index);
        WritePoints(cbor, statement.Generators);
        WritePoints(cbor, statement.PublicKeys);
        cbor.WriteByteString(statement.AdditionalAuthenticatedData.GetBytes());
        cbor.WriteEndArray();
    }


    /// <summary>Encodes <c>challenge-scope</c>.</summary>
    private static void EncodeChallengeScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, LayoutWriter writer)
    {
        CborWriter cbor = SecdsaCbor.CreateWriter(writer);
        cbor.WriteStartArray(ChallengeScopeElements);
        cbor.WriteUInt64(ChallengeScopeKind);
        cbor.WriteByteString(ephemeralPublicKey.AsReadOnlySpan());
        WritePoints(cbor, statement.Generators);
        WritePoints(cbor, statement.PublicKeys);
        cbor.WriteByteString(secondaryDigest.GetBytes());
        cbor.WriteByteString(statement.AdditionalAuthenticatedData.GetBytes());
        cbor.WriteEndArray();
    }


    /// <summary>Encodes <c>response-scope</c>.</summary>
    private static void EncodeResponseScope(G1Point ephemeralPublicKey, ProofStatement statement, ProofDigest secondaryDigest, ProofDigest primaryDigest, LayoutWriter writer)
    {
        CborWriter cbor = SecdsaCbor.CreateWriter(writer);
        cbor.WriteStartArray(ResponseScopeElements);
        cbor.WriteUInt64(ResponseScopeKind);
        cbor.WriteByteString(ephemeralPublicKey.AsReadOnlySpan());
        WritePoints(cbor, statement.Generators);
        WritePoints(cbor, statement.PublicKeys);
        cbor.WriteByteString(secondaryDigest.GetBytes());
        cbor.WriteByteString(statement.AdditionalAuthenticatedData.GetBytes());
        cbor.WriteByteString(primaryDigest.GetBytes());
        cbor.WriteEndArray();
    }


    /// <summary>Encodes <c>seed-payload</c>.</summary>
    private static void EncodeSeedPayload(ProofSeed seed, AdditionalData additionalSecretData, LayoutWriter writer)
    {
        CborWriter cbor = SecdsaCbor.CreateWriter(writer);
        cbor.WriteStartArray(SeedPayloadElements);
        cbor.WriteUInt64(SeedPayloadKind);
        cbor.WriteByteString(seed.GetBytes());
        cbor.WriteByteString(additionalSecretData.GetBytes());
        cbor.WriteEndArray();
    }


    /// <summary>Decodes a <c>seed-payload</c>.</summary>
    private static bool DecodeSeedPayload(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out ProofSeed? seed, out AdditionalData? additionalSecretData)
    {
        seed = null;
        additionalSecretData = null;
        using IMemoryOwner<byte> input = SecdsaCbor.Rent(encoded, pool);
        try
        {
            CborReader reader = SecdsaCbor.CreateReader(input.Memory[..encoded.Length]);
            if(!SecdsaCbor.TryOpenStructure(reader, SeedPayloadElements, SeedPayloadKind)
                || !SecdsaCbor.TryReadByteString(reader, ProofSeed.SizeBytes, out ReadOnlySpan<byte> seedBytes)
                || !SecdsaCbor.TryReadByteString(reader, out ReadOnlySpan<byte> asd)
                || !SecdsaCbor.TryCloseStructure(reader, encoded.Length))
            {
                return false;
            }

            seed = ProofSeed.FromCanonical(seedBytes, pool);
            additionalSecretData = AdditionalData.FromCanonical(asd, AdditionalDataRole.Secret, pool);
            using LayoutWriter canonical = new(pool);
            EncodeSeedPayload(seed, additionalSecretData, canonical);
            if(!CryptographicOperations.FixedTimeEquals(canonical.WrittenBytes, encoded))
            {
                seed.Dispose();
                additionalSecretData.Dispose();
                seed = null;
                additionalSecretData = null;

                return false;
            }

            return true;
        }
        catch(Exception exception) when(SecdsaCbor.IsMalformation(exception))
        {
            return false;
        }
        finally
        {
            input.Memory.Span.Clear();
        }
    }


    /// <summary>Encodes <c>ciphertext</c>.</summary>
    private static void EncodeCiphertext(EciesCiphertext ciphertext, LayoutWriter writer)
    {
        CborWriter cbor = SecdsaCbor.CreateWriter(writer);
        cbor.WriteStartArray(CiphertextElements);
        cbor.WriteUInt64(CiphertextKind);
        cbor.WriteByteString(ciphertext.GetEphemeralPublicKeyBytes());
        cbor.WriteByteString(ciphertext.GetAuthenticationTagBytes());
        cbor.WriteByteString(ciphertext.GetEncryptedBytes());
        cbor.WriteEndArray();
    }


    /// <summary>Decodes a <c>ciphertext</c>; the tag must have the length of the parameter set.</summary>
    private static bool DecodeCiphertext(ReadOnlySpan<byte> encoded, EciesParameterSet parameters, BaseMemoryPool pool, out EciesCiphertext? ciphertext)
    {
        ciphertext = null;
        using IMemoryOwner<byte> input = SecdsaCbor.Rent(encoded, pool);
        try
        {
            CborReader reader = SecdsaCbor.CreateReader(input.Memory[..encoded.Length]);
            if(!SecdsaCbor.TryOpenStructure(reader, CiphertextElements, CiphertextKind)
                || !SecdsaCbor.TryReadByteString(reader, PointSizeBytes, out ReadOnlySpan<byte> ephemeral)
                || !HasFinitePointShape(ephemeral)
                || !SecdsaCbor.TryReadByteString(reader, parameters.TagSizeBytes, out ReadOnlySpan<byte> tag)
                || !SecdsaCbor.TryReadByteString(reader, out ReadOnlySpan<byte> encrypted)
                || !SecdsaCbor.TryCloseStructure(reader, encoded.Length))
            {
                return false;
            }

            ciphertext = EciesCiphertext.FromParts(ephemeral, tag, encrypted, parameters, pool);
            using LayoutWriter canonical = new(pool);
            EncodeCiphertext(ciphertext, canonical);
            if(!CryptographicOperations.FixedTimeEquals(canonical.WrittenBytes, encoded))
            {
                ciphertext.Dispose();
                ciphertext = null;

                return false;
            }

            return true;
        }
        catch(Exception exception) when(SecdsaCbor.IsMalformation(exception))
        {
            return false;
        }
    }


    /// <summary>Encodes <c>challenge</c>.</summary>
    private static void EncodeChallenge(TransferableChallenge challenge, LayoutWriter writer)
    {
        CborWriter cbor = SecdsaCbor.CreateWriter(writer);
        cbor.WriteStartArray(ChallengeElements);
        cbor.WriteUInt64(ChallengeKind);
        cbor.WriteTextString(CheckedProfileId(challenge.Profile));
        cbor.WriteByteString(challenge.GetEphemeralPublicKeyBytes());
        cbor.WriteByteString(challenge.GetSecondaryDigestBytes());
        cbor.WriteByteString(challenge.GetAdditionalAuthenticatedDataBytes());
        cbor.WriteByteString(challenge.GetSignatureBytes());
        cbor.WriteEndArray();
    }


    /// <summary>Decodes a <c>challenge</c>, restoring the profile identifier it was signed under.</summary>
    private static bool DecodeChallenge(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableChallenge? value)
    {
        value = null;
        using IMemoryOwner<byte> input = SecdsaCbor.Rent(encoded, pool);
        try
        {
            CborReader reader = SecdsaCbor.CreateReader(input.Memory[..encoded.Length]);
            if(!SecdsaCbor.TryOpenStructure(reader, ChallengeElements, ChallengeKind)
                || !SecdsaCbor.TryReadTextString(reader, MaxProfileIdBytes, out string profile)
                || !SecdsaCbor.TryReadByteString(reader, PointSizeBytes, out ReadOnlySpan<byte> ephemeral)
                || !HasFinitePointShape(ephemeral)
                || !SecdsaCbor.TryReadByteString(reader, DigestSizeBytes, out ReadOnlySpan<byte> secondary)
                || !SecdsaCbor.TryReadByteString(reader, out ReadOnlySpan<byte> aad)
                || !SecdsaCbor.TryReadByteString(reader, out ReadOnlySpan<byte> signature)
                || !SecdsaCbor.TryCloseStructure(reader, encoded.Length)
                || signature.IsEmpty
                || signature.Length > TransferableProofAlgorithm.MaxSignatureSizeBytes)
            {
                return false;
            }

            using G1Point point = G1Point.FromCanonical(ephemeral, CurveParameterSet.P256, pool);
            using ProofDigest digest = ProofDigest.FromCanonical(secondary, ProofDigestKind.Secondary, pool);
            using AdditionalData data = AdditionalData.FromCanonical(aad, AdditionalDataRole.Authenticated, pool);
            value = TransferableChallenge.FromParts(point, digest, data, signature, new SecdsaLayoutProfileId(profile), pool);
            using LayoutWriter canonical = new(pool);
            EncodeChallenge(value, canonical);
            if(!CryptographicOperations.FixedTimeEquals(canonical.WrittenBytes, encoded))
            {
                value.Dispose();
                value = null;

                return false;
            }

            return true;
        }
        catch(Exception exception) when(SecdsaCbor.IsMalformation(exception))
        {
            return false;
        }
    }


    /// <summary>Encodes <c>response</c>.</summary>
    private static void EncodeResponse(TransferableResponse response, LayoutWriter writer)
    {
        CborWriter cbor = SecdsaCbor.CreateWriter(writer);
        cbor.WriteStartArray(ResponseElements);
        cbor.WriteUInt64(ResponseKind);
        cbor.WriteTextString(CheckedProfileId(response.Profile));
        cbor.WriteByteString(response.GetPrimaryDigestBytes());
        cbor.WriteByteString(response.GetSignatureBytes());
        cbor.WriteEndArray();
    }


    /// <summary>Decodes a <c>response</c>, restoring the profile identifier it was signed under.</summary>
    private static bool DecodeResponse(ReadOnlySpan<byte> encoded, BaseMemoryPool pool, out TransferableResponse? value)
    {
        value = null;
        using IMemoryOwner<byte> input = SecdsaCbor.Rent(encoded, pool);
        try
        {
            CborReader reader = SecdsaCbor.CreateReader(input.Memory[..encoded.Length]);
            if(!SecdsaCbor.TryOpenStructure(reader, ResponseElements, ResponseKind)
                || !SecdsaCbor.TryReadTextString(reader, MaxProfileIdBytes, out string profile)
                || !SecdsaCbor.TryReadByteString(reader, DigestSizeBytes, out ReadOnlySpan<byte> primary)
                || !SecdsaCbor.TryReadByteString(reader, out ReadOnlySpan<byte> signature)
                || !SecdsaCbor.TryCloseStructure(reader, encoded.Length)
                || signature.IsEmpty
                || signature.Length > TransferableProofAlgorithm.MaxSignatureSizeBytes)
            {
                return false;
            }

            using ProofDigest digest = ProofDigest.FromCanonical(primary, ProofDigestKind.Primary, pool);
            value = TransferableResponse.FromParts(digest, signature, new SecdsaLayoutProfileId(profile), pool);
            using LayoutWriter canonical = new(pool);
            EncodeResponse(value, canonical);
            if(!CryptographicOperations.FixedTimeEquals(canonical.WrittenBytes, encoded))
            {
                value.Dispose();
                value = null;

                return false;
            }

            return true;
        }
        catch(Exception exception) when(SecdsaCbor.IsMalformation(exception))
        {
            return false;
        }
    }


    /// <summary>Writes a point vector as an array of byte strings.</summary>
    private static void WritePoints(CborWriter cbor, P256PointVector vector)
    {
        cbor.WriteStartArray(vector.Count);
        for(int index = 0; index < vector.Count; index++)
        {
            cbor.WriteByteString(vector.GetPointBytes(index));
        }

        cbor.WriteEndArray();
    }


    /// <summary>Writes a scalar vector as an array of byte strings.</summary>
    private static void WriteScalars(CborWriter cbor, P256ScalarVector vector)
    {
        cbor.WriteStartArray(vector.Count);
        for(int index = 0; index < vector.Count; index++)
        {
            cbor.WriteByteString(vector.GetScalarBytes(index));
        }

        cbor.WriteEndArray();
    }


    /// <summary>Reads the byte strings of an open vector array into a contiguous buffer and closes the array.</summary>
    private static bool TryCollect(CborReader reader, int valueSize, Span<byte> destination)
    {
        for(int offset = 0; offset < destination.Length; offset += valueSize)
        {
            if(!SecdsaCbor.TryReadByteString(reader, valueSize, out ReadOnlySpan<byte> value))
            {
                return false;
            }

            value.CopyTo(destination[offset..]);
        }

        reader.ReadEndArray();

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


    /// <summary>Returns the identifier text after requiring one to <see cref="MaxProfileIdBytes"/> UTF-8 bytes.</summary>
    private static string CheckedProfileId(SecdsaLayoutProfileId profile)
    {
        int length = Encoding.UTF8.GetByteCount(profile.Identifier);
        if(length == 0 || length > MaxProfileIdBytes)
        {
            throw new ArgumentException($"A profile identifier must be between 1 and {MaxProfileIdBytes} UTF-8 bytes.", nameof(profile));
        }

        return profile.Identifier;
    }
}
