using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// One attribute the verifier requires the prover to disclose, a faithful port of the reference's
/// host-side <c>OpenedAttribute</c> (<c>circuits/tests/jwt/jwt_witness.h</c>): the identifier and
/// string value whose quoted <c>"id":"value"</c> pattern must occur in the decoded payload.
/// </summary>
internal sealed class LongfellowJwtOpenedAttribute
{
    /// <summary>The identifier capacity in bytes (the reference's <c>id[32]</c>).</summary>
    public const int MaxIdLength = 32;

    /// <summary>The value capacity in bytes (the reference's <c>value[64]</c>).</summary>
    public const int MaxValueLength = 64;

    /// <summary>The attribute identifier bytes.</summary>
    public ReadOnlyMemory<byte> Id { get; }

    /// <summary>The attribute value bytes.</summary>
    public ReadOnlyMemory<byte> Value { get; }

    /// <summary>The quoted pattern's byte length, including four quotes and one colon.</summary>
    public int PatternLength => checked(Id.Length + Value.Length + PatternFramingLength);

    /// <summary>Four quotes and one colon frame the identifier and value.</summary>
    private const int PatternFramingLength = 5;


    /// <summary>
    /// Constructs the attribute from raw bytes.
    /// </summary>
    /// <param name="id">The identifier bytes.</param>
    /// <param name="value">The value bytes.</param>
    /// <exception cref="ArgumentException">When either side exceeds its capacity.</exception>
    public LongfellowJwtOpenedAttribute(ReadOnlyMemory<byte> id, ReadOnlyMemory<byte> value)
    {
        if(id.Length > MaxIdLength || value.Length > MaxValueLength)
        {
            throw new ArgumentException($"An attribute holds at most {MaxIdLength} identifier bytes and {MaxValueLength} value bytes.");
        }

        Id = id;
        Value = value;
    }


    /// <summary>
    /// Constructs the attribute from strings, encoded as UTF-8 — the encoding JSON payloads carry,
    /// so a claim value with non-ASCII text matches the decoded payload byte for byte (JOSE claim
    /// names themselves are ASCII, where the two encodings coincide).
    /// </summary>
    /// <param name="id">The identifier.</param>
    /// <param name="value">The value.</param>
    /// <returns>The attribute.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static LongfellowJwtOpenedAttribute FromStrings(string id, string value)
    {
        ArgumentNullException.ThrowIfNull(id);
        ArgumentNullException.ThrowIfNull(value);

        return new LongfellowJwtOpenedAttribute(Encoding.UTF8.GetBytes(id), Encoding.UTF8.GetBytes(value));
    }


    /// <summary>
    /// The quoted search pattern <c>"id":"value"</c> the statement discloses and the witness
    /// generator locates in the payload (the reference's <c>fill_attribute</c> and
    /// <c>compute_witness</c> both build exactly this byte string).
    /// </summary>
    /// <param name="pattern">Receives <see cref="PatternLength"/> pattern bytes.</param>
    public void BuildPattern(Span<byte> pattern)
    {
        int cursor = 0;
        pattern[cursor++] = (byte)'"';
        Id.Span.CopyTo(pattern[cursor..]);
        cursor += Id.Length;
        pattern[cursor++] = (byte)'"';
        pattern[cursor++] = (byte)':';
        pattern[cursor++] = (byte)'"';
        Value.Span.CopyTo(pattern[cursor..]);
        cursor += Value.Length;
        pattern[cursor] = (byte)'"';
    }
}


/// <summary>
/// Computes the private witness column for the JWT statement, a faithful port of
/// google/longfellow-zk's <c>JWTWitness&lt;EC, ScalarField, SHABlocks&gt;</c>
/// (<c>circuits/tests/jwt/jwt_witness.h</c>): splits the token at its tilde into the issuer JWS
/// and the key-binding JWS, hashes and pads the signing preimage, computes both ECDSA advice
/// bundles, decodes the payload, locates every disclosed attribute and the <c>cnf</c> device key,
/// and emits the whole column in the order <see cref="LongfellowJwtCircuit.InputWitness"/>
/// declares wires in.
/// </summary>
/// <remarks>
/// <para>
/// The base64url decoding here reproduces the reference's host-side <c>base64_decode_url</c>
/// exactly: the URL-safe unpadded alphabet, failure on any character outside it, and three output
/// bytes per input group including a zero-padded trailing partial group — the circuit's decoder
/// gadget asserts the same convention, so the witness and circuit agree byte for byte.
/// </para>
/// <para>
/// Witness generation is variable-time over the prover's own token and payload bytes (the JWS
/// splitting, the attribute and device-key substring searches, and the base64url decoding are all
/// data-dependent scans), exactly as the reference's <c>compute_witness</c> is; it runs prover-side
/// over the prover's own credential. A malformed or non-matching token makes
/// <see cref="ComputeWitness"/> return <see langword="false"/> rather than throwing.
/// </para>
/// </remarks>
internal sealed class LongfellowJwtWitness: IDisposable
{
    /// <summary>The base64url alphabet (unpadded, URL-safe) the reference's host-side decoder accepts.</summary>
    private const string Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>The JSON fragment immediately preceding the device key's x-coordinate in the <c>cnf.jwk</c> claim.</summary>
    private const string DeviceKeyPrefix = "\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"";

    /// <summary>The JSON fragment between the device key's x- and y-coordinates in the <c>cnf.jwk</c> claim.</summary>
    private const string DeviceKeySeparator = "\",\"y\":\"";

    /// <summary>One base64url-encoded P-256 coordinate's character count (43 unpadded characters carry 32 bytes).</summary>
    private const int CoordinateCharacterCount = 43;

    /// <summary>A parsed JWS retains its digest and both signature scalars while the witness consumes them.</summary>
    private const int JwsScalarCount = 3;

    /// <summary>One SHA-256 block's byte width.</summary>
    private const int BytesPerBlock = 64;

    /// <summary>The words one SHA-256 block's advice records: the schedule extension, both per-round registers, and the final state.</summary>
    private const int WordsPerBlock = 48 + 64 + 64 + 8;

    /// <summary>Owns all retained byte buffers through the field's caller pool.</summary>
    private LongfellowCircuitStorage Storage { get; }

    /// <summary>The base-field bundle and pool this generator borrows and keeps alive until disposal.</summary>
    private LongfellowLogicFieldOperations Field { get; }

    /// <summary>The curve constants borrowed until this generator is disposed.</summary>
    private LongfellowEllipticCurveParameters Curve { get; }

    /// <summary>The nested ECDSA advice owner, released with this generator.</summary>
    private LongfellowEcdsaVerifyWitness JwtSignature { get; }

    /// <summary>The nested ECDSA advice owner, released with this generator.</summary>
    private LongfellowEcdsaVerifyWitness KbSignature { get; }

    /// <summary>The plucker encoder packing each SHA-256 advice word into field elements.</summary>
    private LongfellowBitPluckerEncoder Encoder { get; }

    /// <summary>The canonical base prime, borrowed from this generator's storage.</summary>
    private Memory<byte> BasePrime { get; }

    /// <summary>The preimage capacity in SHA-256 blocks.</summary>
    private int MaxBlocks { get; }

    /// <summary>The reduced issuer digest, borrowed from this generator's storage.</summary>
    private Memory<byte> IssuerDigest { get; }

    /// <summary>The device key's x coordinate, borrowed from this generator's storage.</summary>
    private Memory<byte> DeviceKeyX { get; }

    /// <summary>The device key's y coordinate, borrowed from this generator's storage.</summary>
    private Memory<byte> DeviceKeyY { get; }

    /// <summary>The reduced key-binding digest, borrowed from this generator's storage.</summary>
    private Memory<byte> KbDigestBuffer { get; }

    /// <summary>The padded signing preimage, borrowed from this generator's storage.</summary>
    private Memory<byte> Preimage { get; }

    /// <summary>The raw issuer digest bits, borrowed from this generator's storage.</summary>
    private Memory<byte> EBits { get; }

    /// <summary>Per-block SHA-256 advice, one entry per block up to <see cref="MaxBlocks"/>.</summary>
    private LongfellowFlatSha256BlockWitness[] Blocks { get; }

    /// <summary>The number of blocks the signing preimage actually occupies.</summary>
    private byte occupiedBlockCount;

    /// <summary>The byte index of each disclosed attribute's pattern within the decoded payload, in the order <see cref="ComputeWitness"/> was given the attributes.</summary>
    private List<int> AttributeIndices { get; } = [];

    /// <summary>The decoded payload's start index within the issuer JWS.</summary>
    private int payloadIndex;

    /// <summary>The decoded payload's byte length within the issuer JWS.</summary>
    private int payloadLength;

    /// <summary>The key-binding digest, borrowed until disposal, as a canonical base-field element — the public <c>e2</c> input the verifier recomputes from the presented key-binding JWT.</summary>
    public ReadOnlyMemory<byte> KbDigest => KbDigestBuffer;


    /// <summary>
    /// Constructs the generator over the same field bundles and curve the statement circuit uses.
    /// </summary>
    /// <param name="field">The borrowed base-field bundle and originating pool, both kept alive until this generator is disposed.</param>
    /// <param name="orderMultiply">The order-field multiplication, canonical in and out.</param>
    /// <param name="orderSubtract">The order-field subtraction, canonical in and out.</param>
    /// <param name="orderInvert">The order-field inversion, canonical in and out.</param>
    /// <param name="orderCurve">The curve parameter set the order-field delegates dispatch on.</param>
    /// <param name="curve">The curve constants borrowed until this generator is disposed.</param>
    /// <param name="maxShaBlocks">The preimage capacity in SHA-256 blocks.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maxShaBlocks"/> is outside the statement circuit's own shape bounds.</exception>
    public LongfellowJwtWitness(
        LongfellowLogicFieldOperations field,
        ScalarMultiplyDelegate orderMultiply,
        ScalarSubtractDelegate orderSubtract,
        ScalarInvertDelegate orderInvert,
        CurveParameterSet orderCurve,
        LongfellowEllipticCurveParameters curve,
        int maxShaBlocks)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(curve);

        //Mirror the statement circuit's shape bounds so a capacity the paired circuit would refuse
        //fails here identically instead of silently truncating index bits at fill time.
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxShaBlocks, LongfellowJwtConstants.ReservedTailBlocks);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxShaBlocks, LongfellowJwtConstants.MaxShaBlocks);

        if((1 << LongfellowJwtConstants.JwtIndexBits) <= (maxShaBlocks * BytesPerBlock) - 9)
        {
            throw new ArgumentOutOfRangeException(nameof(maxShaBlocks), "The JWT index bit width cannot address the block capacity.");
        }

        this.Field = field;
        this.Curve = curve;
        MaxBlocks = maxShaBlocks;
        LongfellowCircuitStorage? storageOwner = new LongfellowCircuitStorage(field.Pool);
        LongfellowEcdsaVerifyWitness? jwtSignatureOwner = null;
        LongfellowEcdsaVerifyWitness? kbSignatureOwner = null;
        try
        {
            jwtSignatureOwner = new LongfellowEcdsaVerifyWitness(field, orderMultiply, orderSubtract, orderInvert, orderCurve, curve);
            kbSignatureOwner = new LongfellowEcdsaVerifyWitness(field, orderMultiply, orderSubtract, orderInvert, orderCurve, curve);
            Encoder = new LongfellowBitPluckerEncoder(field, LongfellowJwtConstants.ShaJwtPluckerBits);
            BasePrime = storageOwner.Allocate(Scalar.SizeBytes);
            LongfellowEcdsaVerifyWitness.DeriveBasePrime(field, BasePrime.Span);

            IssuerDigest = storageOwner.Allocate(Scalar.SizeBytes);
            DeviceKeyX = storageOwner.Allocate(Scalar.SizeBytes);
            DeviceKeyY = storageOwner.Allocate(Scalar.SizeBytes);
            KbDigestBuffer = storageOwner.Allocate(Scalar.SizeBytes);
            Preimage = storageOwner.Allocate(maxShaBlocks * BytesPerBlock);
            EBits = storageOwner.Allocate(LongfellowLogic.BitWidth256);
            Blocks = new LongfellowFlatSha256BlockWitness[maxShaBlocks];
            for(int i = 0; i < maxShaBlocks; i++)
            {
                Blocks[i] = new LongfellowFlatSha256BlockWitness();
            }

            JwtSignature = jwtSignatureOwner;
            jwtSignatureOwner = null;
            KbSignature = kbSignatureOwner;
            kbSignatureOwner = null;
            Storage = storageOwner;
            storageOwner = null;
        }
        finally
        {
            kbSignatureOwner?.Dispose();
            jwtSignatureOwner?.Dispose();
            storageOwner?.Dispose();
        }
    }


    /// <summary>
    /// The column length in elements for a given disclosed attribute count.
    /// </summary>
    /// <param name="attributeCount">The disclosed attribute count.</param>
    /// <returns>The element count.</returns>
    public int GetElementCount(int attributeCount)
    {
        int packedPerWord = Encoder.PackedV32ElementCount;

        return 3
            + (2 * JwtSignature.ElementCount)
            + (MaxBlocks * BytesPerBlock * LongfellowLogic.BitWidth8)
            + LongfellowLogic.BitWidth256
            + (MaxBlocks * WordsPerBlock * packedPerWord)
            + LongfellowLogic.BitWidth8
            + (attributeCount * LongfellowJwtConstants.JwtIndexBits)
            + (2 * LongfellowJwtConstants.JwtIndexBits);
    }


    /// <summary>
    /// The reference's <c>compute_witness</c>: parses the <c>issuer~kb</c> token, verifies both
    /// signatures witness-side, and records every value the circuit's advice wires consume. A
    /// malformed token, an oversized preimage, a failed signature, a missing attribute or a missing
    /// device key all return <see langword="false"/>.
    /// </summary>
    /// <param name="token">The token's raw bytes in the <c>header.payload.signature~kb</c> shape.</param>
    /// <param name="pkX">The issuer public key's x coordinate, canonical big-endian.</param>
    /// <param name="pkY">The issuer public key's y coordinate, canonical big-endian.</param>
    /// <param name="attributes">The attributes the verifier requires disclosed.</param>
    /// <returns>Whether a complete witness was produced.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="attributes"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a key coordinate is not exactly <see cref="Scalar.SizeBytes"/> bytes.</exception>
    public bool ComputeWitness(ReadOnlySpan<byte> token, ReadOnlySpan<byte> pkX, ReadOnlySpan<byte> pkY, IReadOnlyList<LongfellowJwtOpenedAttribute> attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);

        if(pkX.Length != Scalar.SizeBytes || pkY.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"Key coordinates are canonical {Scalar.SizeBytes}-byte scalars.");
        }

        int tilde = token.IndexOf((byte)'~');
        if(tilde < 0)
        {
            return false;
        }

        ReadOnlySpan<byte> issuerJws = token[..tilde];
        ReadOnlySpan<byte> kbJws = token[(tilde + 1)..];

        using IMemoryOwner<byte> issuerOwner = Field.Pool.Rent(JwsScalarCount * Scalar.SizeBytes);
        if(!TryParseJws(issuerJws, Field.Pool, issuerOwner.Memory[..(JwsScalarCount * Scalar.SizeBytes)], out JwsParts issuer))
        {
            return false;
        }

        if(issuer.MessageLength > (MaxBlocks * BytesPerBlock) - 9)
        {
            return false;
        }

        LongfellowFlatSha256Witness.TransformAndWitnessMessage(issuerJws[..issuer.MessageLength], MaxBlocks, out occupiedBlockCount, Preimage.Span, Blocks);

        CanonicalScalarReduction.ReduceOnce(issuer.Digest.Span, BasePrime.Span, IssuerDigest.Span);
        payloadIndex = issuer.PayloadIndex;
        payloadLength = issuer.PayloadLength;

        if(!JwtSignature.ComputeWitness(pkX, pkY, issuer.Digest.Span, issuer.R.Span, issuer.S.Span))
        {
            return false;
        }

        for(int i = 0; i < LongfellowLogic.BitWidth256; i++)
        {
            EBits.Span[i] = (byte)((issuer.Digest.Span[Scalar.SizeBytes - 1 - (i / 8)] >> (i % 8)) & 1);
        }

        //Locate each disclosed attribute in the decoded payload.
        int payloadCapacity = GetDecodedLength(issuer.PayloadLength);
        using IMemoryOwner<byte>? payloadOwner = payloadCapacity == 0 ? null : Field.Pool.Rent(payloadCapacity);
        Span<byte> payloadBuffer = payloadOwner is null ? Span<byte>.Empty : payloadOwner.Memory.Span[..payloadCapacity];
        if(!TryBase64UrlDecode(issuerJws.Slice(issuer.PayloadIndex, issuer.PayloadLength), payloadBuffer, out int decodedPayloadLength))
        {
            return false;
        }

        ReadOnlySpan<byte> payload = payloadBuffer[..decodedPayloadLength];
        AttributeIndices.Clear();
        for(int i = 0; i < attributes.Count; i++)
        {
            LongfellowJwtOpenedAttribute attribute = attributes[i];
            using IMemoryOwner<byte> patternOwner = Field.Pool.Rent(attribute.PatternLength);
            Span<byte> pattern = patternOwner.Memory.Span[..attribute.PatternLength];
            attribute.BuildPattern(pattern);
            int index = payload.IndexOf(pattern);
            if(index < 0)
            {
                return false;
            }

            AttributeIndices.Add(index);
        }

        if(!TryExtractDeviceKey(payload))
        {
            return false;
        }

        //The key-binding portion: parse, and verify under the payload-carried device key.
        using IMemoryOwner<byte> kbOwner = Field.Pool.Rent(JwsScalarCount * Scalar.SizeBytes);
        if(kbJws.IsEmpty || !TryParseJws(kbJws, Field.Pool, kbOwner.Memory[..(JwsScalarCount * Scalar.SizeBytes)], out JwsParts kb))
        {
            return false;
        }

        if(!KbSignature.ComputeWitness(DeviceKeyX.Span, DeviceKeyY.Span, kb.Digest.Span, kb.R.Span, kb.S.Span))
        {
            return false;
        }

        CanonicalScalarReduction.ReduceOnce(kb.Digest.Span, BasePrime.Span, KbDigestBuffer.Span);

        return true;
    }


    /// <summary>
    /// The reference's <c>fill_witness</c>: writes the private witness region in declaration order.
    /// </summary>
    /// <param name="destination">Receives <see cref="GetElementCount"/> elements of <see cref="Scalar.SizeBytes"/> bytes each.</param>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is not exactly the column's byte length.</exception>
    public void FillWitness(Span<byte> destination)
    {
        int elementCount = GetElementCount(AttributeIndices.Count);
        if(destination.Length != elementCount * Scalar.SizeBytes)
        {
            throw new ArgumentException($"The column is exactly {elementCount} elements of {Scalar.SizeBytes} bytes.", nameof(destination));
        }

        int cursor = 0;
        WriteElement(destination, ref cursor, IssuerDigest.Span);
        WriteElement(destination, ref cursor, DeviceKeyX.Span);
        WriteElement(destination, ref cursor, DeviceKeyY.Span);

        JwtSignature.FillWitness(destination.Slice(cursor * Scalar.SizeBytes, JwtSignature.ElementCount * Scalar.SizeBytes));
        cursor += JwtSignature.ElementCount;
        KbSignature.FillWitness(destination.Slice(cursor * Scalar.SizeBytes, KbSignature.ElementCount * Scalar.SizeBytes));
        cursor += KbSignature.ElementCount;

        for(int i = 0; i < Preimage.Length; i++)
        {
            WriteBits(destination, ref cursor, Preimage.Span[i], LongfellowLogic.BitWidth8);
        }

        for(int i = 0; i < EBits.Length; i++)
        {
            WriteBits(destination, ref cursor, EBits.Span[i], 1);
        }

        for(int j = 0; j < MaxBlocks; j++)
        {
            FillShaBlock(destination, ref cursor, Blocks[j]);
        }

        WriteBits(destination, ref cursor, occupiedBlockCount, LongfellowLogic.BitWidth8);

        for(int i = 0; i < AttributeIndices.Count; i++)
        {
            WriteBits(destination, ref cursor, (ulong)AttributeIndices[i], LongfellowJwtConstants.JwtIndexBits);
        }

        WriteBits(destination, ref cursor, (ulong)payloadIndex, LongfellowJwtConstants.JwtIndexBits);
        WriteBits(destination, ref cursor, (ulong)payloadLength, LongfellowJwtConstants.JwtIndexBits);
    }


    /// <summary>
    /// The reference's <c>fill_attribute</c>: writes one disclosed attribute's public inputs — the
    /// quoted pattern padded to its fixed width as per-byte bit elements, then the pattern length.
    /// </summary>
    /// <param name="field">The field bundle supplying the bit elements.</param>
    /// <param name="attribute">The attribute to write.</param>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor, advanced past the attribute.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="field"/> or <paramref name="attribute"/> is <see langword="null"/>.</exception>
    public static void FillAttribute(LongfellowLogicFieldOperations field, LongfellowJwtOpenedAttribute attribute, Span<byte> destination, ref int cursor)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(attribute);

        using IMemoryOwner<byte> owner = field.Pool.Rent(attribute.PatternLength);
        Span<byte> pattern = owner.Memory.Span[..attribute.PatternLength];
        attribute.BuildPattern(pattern);
        for(int i = 0; i < LongfellowJwtOpenedAttributeWires.PatternLength; i++)
        {
            byte value = i < pattern.Length ? pattern[i] : (byte)0;
            WriteValueBits(field, destination, ref cursor, value, LongfellowLogic.BitWidth8);
        }

        WriteValueBits(field, destination, ref cursor, (ulong)pattern.Length, LongfellowLogic.BitWidth8);
    }


    /// <summary>The parsed pieces of one JWS compact serialization, borrowing the caller's scalar workspace.</summary>
    /// <param name="MessageLength">The signed message's byte length (<c>header.payload</c>).</param>
    /// <param name="PayloadIndex">The payload's start index in the token.</param>
    /// <param name="PayloadLength">The payload's byte length.</param>
    /// <param name="Digest">The SHA-256 digest of the signed message.</param>
    /// <param name="R">The signature's <c>r</c>, big-endian.</param>
    /// <param name="S">The signature's <c>s</c>, big-endian.</param>
    private readonly record struct JwsParts(int MessageLength, int PayloadIndex, int PayloadLength, ReadOnlyMemory<byte> Digest, ReadOnlyMemory<byte> R, ReadOnlyMemory<byte> S);


    /// <summary>
    /// The reference's <c>parse_jws</c>: splits <c>header.payload.signature</c>, hashes the signed
    /// message, and decodes the signature into its scalar pair.
    /// </summary>
    /// <param name="jws">The JWS bytes.</param>
    /// <param name="pool">The caller pool supplying temporary signature decoding bytes.</param>
    /// <param name="scalars">The caller-owned digest and signature scalar slots, kept alive while the parsed pieces are used.</param>
    /// <param name="parts">Receives the parsed pieces borrowing <paramref name="scalars"/>.</param>
    /// <returns>Whether the JWS parsed.</returns>
    private static bool TryParseJws(ReadOnlySpan<byte> jws, BaseMemoryPool pool, Memory<byte> scalars, out JwsParts parts)
    {
        parts = default;

        int dot = jws.IndexOf((byte)'.');
        if(dot < 0)
        {
            return false;
        }

        int secondDot = jws[(dot + 1)..].IndexOf((byte)'.');
        if(secondDot < 0)
        {
            return false;
        }

        secondDot += dot + 1;

        ReadOnlySpan<byte> signature = jws[(secondDot + 1)..];
        Memory<byte> digest = scalars[..Scalar.SizeBytes];
        SHA256.HashData(jws[..secondDot], digest.Span);

        int signatureCapacity = GetDecodedLength(signature.Length);
        using IMemoryOwner<byte>? signatureOwner = signatureCapacity == 0 ? null : pool.Rent(signatureCapacity);
        Span<byte> signatureBytes = signatureOwner is null ? Span<byte>.Empty : signatureOwner.Memory.Span[..signatureCapacity];
        if(!TryBase64UrlDecode(signature, signatureBytes, out int signatureLength) || signatureLength < 2 * Scalar.SizeBytes)
        {
            return false;
        }

        signatureBytes[..(2 * Scalar.SizeBytes)].CopyTo(scalars.Span[Scalar.SizeBytes..]);
        parts = new JwsParts(
            secondDot,
            dot + 1,
            secondDot - dot - 1,
            digest,
            scalars.Slice(Scalar.SizeBytes, Scalar.SizeBytes),
            scalars.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes));

        return true;
    }


    /// <summary>
    /// The reference's <c>compute_witness</c> device-key extraction: locates the <c>cnf</c> claim's
    /// JWK, decodes its base64url coordinates, and stores them as base-field elements.
    /// </summary>
    /// <param name="payload">The decoded payload.</param>
    /// <returns>Whether the device key was found.</returns>
    private bool TryExtractDeviceKey(ReadOnlySpan<byte> payload)
    {
        byte[] prefix = Encoding.ASCII.GetBytes(DeviceKeyPrefix);
        int xIndex = payload.IndexOf(prefix);
        if(xIndex < 0)
        {
            return false;
        }

        int xStart = xIndex + prefix.Length;
        byte[] separator = Encoding.ASCII.GetBytes(DeviceKeySeparator);
        int yIndex = payload[xStart..].IndexOf(separator);
        if(yIndex < 0)
        {
            return false;
        }

        int yStart = xStart + yIndex + separator.Length;
        if(xStart + CoordinateCharacterCount > payload.Length || yStart + CoordinateCharacterCount > payload.Length)
        {
            return false;
        }

        int coordinateCapacity = GetDecodedLength(CoordinateCharacterCount);
        using IMemoryOwner<byte> xOwner = Field.Pool.Rent(coordinateCapacity);
        Span<byte> xBytes = xOwner.Memory.Span[..coordinateCapacity];
        using IMemoryOwner<byte> yOwner = Field.Pool.Rent(coordinateCapacity);
        Span<byte> yBytes = yOwner.Memory.Span[..coordinateCapacity];
        if(!TryBase64UrlDecode(payload.Slice(xStart, CoordinateCharacterCount), xBytes, out int xLength)
            || !TryBase64UrlDecode(payload.Slice(yStart, CoordinateCharacterCount), yBytes, out int yLength))
        {
            return false;
        }

        CanonicalScalarReduction.ReduceOnce(xBytes[..xLength][..Scalar.SizeBytes], BasePrime.Span, DeviceKeyX.Span);
        CanonicalScalarReduction.ReduceOnce(yBytes[..yLength][..Scalar.SizeBytes], BasePrime.Span, DeviceKeyY.Span);

        return true;
    }


    /// <summary>
    /// The reference's host-side <c>base64_decode_url</c> (<c>decode_util.cc</c>): the URL-safe
    /// unpadded alphabet, failure on any other character, and three output bytes per group with a
    /// zero-padded trailing partial group.
    /// </summary>
    /// <param name="input">The encoded bytes.</param>
    /// <param name="decoded">Receives three bytes per input group, including partial groups; empty input accepts an empty span.</param>
    /// <param name="written">Receives the decoded length, or zero on failure.</param>
    /// <returns>Whether every character was in the alphabet.</returns>
    private static bool TryBase64UrlDecode(ReadOnlySpan<byte> input, Span<byte> decoded, out int written)
    {
        written = 0;
        int cursor = 0;
        Span<int> group = stackalloc int[4];
        for(int i = 0; i < input.Length; i += 4)
        {
            group.Clear();
            for(int j = 0; j < 4 && i + j < input.Length; j++)
            {
                int symbol = Base64UrlAlphabet.IndexOf((char)input[i + j], StringComparison.Ordinal);
                if(symbol < 0)
                {
                    return false;
                }

                group[j] = symbol;
            }

            decoded[cursor++] = (byte)((group[0] << 2) | (group[1] >> 4));
            decoded[cursor++] = (byte)(((group[1] << 4) | (group[2] >> 2)) & 0xFF);
            decoded[cursor++] = (byte)(((group[2] << 6) | group[3]) & 0xFF);
        }

        written = cursor;

        return true;
    }


    /// <summary>The decoder's three-byte capacity per four-character group, including a partial group.</summary>
    /// <param name="inputLength">The encoded byte length.</param>
    /// <returns>The decoded byte length, including zero for empty input.</returns>
    /// <exception cref="OverflowException">When the padded input length exceeds the signed length range.</exception>
    private static int GetDecodedLength(int inputLength)
    {
        return checked(((inputLength + 3) / 4) * 3);
    }


    /// <summary>
    /// The reference's <c>fill_sha</c>: one block's advice as plucker-packed words — the schedule
    /// extension, the per-round register pairs interleaved, then the final state.
    /// </summary>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="block">The block advice.</param>
    private void FillShaBlock(Span<byte> destination, ref int cursor, in LongfellowFlatSha256BlockWitness block)
    {
        for(int k = 0; k < block.ScheduleExtension.Length; k++)
        {
            WritePackedWord(destination, ref cursor, block.ScheduleExtension[k]);
        }

        for(int k = 0; k < block.RegisterEWitness.Length; k++)
        {
            WritePackedWord(destination, ref cursor, block.RegisterEWitness[k]);
            WritePackedWord(destination, ref cursor, block.RegisterAWitness[k]);
        }

        for(int k = 0; k < block.FinalState.Length; k++)
        {
            WritePackedWord(destination, ref cursor, block.FinalState[k]);
        }
    }


    /// <summary>Writes one 32-bit word directly into the column as its plucker-packed elements.</summary>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="word">The word to pack.</param>
    private void WritePackedWord(Span<byte> destination, ref int cursor, uint word)
    {
        Encoder.MakePackedV32(word, destination.Slice(cursor * Scalar.SizeBytes, Encoder.PackedV32ElementCount * Scalar.SizeBytes));
        cursor += Encoder.PackedV32ElementCount;
    }


    /// <summary>Writes a value's bits, least significant first, one field element per bit (the reference filler's <c>push_back(x, bits, F)</c>).</summary>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="value">The value.</param>
    /// <param name="bitCount">The bit count.</param>
    private void WriteBits(Span<byte> destination, ref int cursor, ulong value, int bitCount)
    {
        WriteValueBits(Field, destination, ref cursor, value, bitCount);
    }


    /// <summary>The shared bit-element writer behind <see cref="WriteBits"/> and <see cref="FillAttribute"/>.</summary>
    /// <param name="field">The field bundle supplying the bit elements.</param>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="value">The value.</param>
    /// <param name="bitCount">The bit count.</param>
    private static void WriteValueBits(LongfellowLogicFieldOperations field, Span<byte> destination, ref int cursor, ulong value, int bitCount)
    {
        for(int i = 0; i < bitCount; i++)
        {
            ReadOnlyMemory<byte> element = ((value >> i) & 1UL) != 0UL ? field.Compiler.One : field.Compiler.Zero;
            element.Span.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
            cursor++;
        }
    }


    /// <summary>Writes one element into the column and advances the cursor.</summary>
    /// <param name="destination">The column.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="element">The element to write.</param>
    private static void WriteElement(Span<byte> destination, ref int cursor, ReadOnlySpan<byte> element)
    {
        element.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
        cursor++;
    }


    /// <summary>Clears and releases retained bytes and nested signature advice. Repeated disposal has no effect.</summary>
    public void Dispose()
    {
        KbSignature.Dispose();
        JwtSignature.Dispose();
        Storage.Dispose();
    }
}
