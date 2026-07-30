using System;
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
    /// <returns>The pattern bytes.</returns>
    public byte[] BuildPattern()
    {
        //Four quotes and one colon frame the identifier and value.
        var pattern = new byte[Id.Length + Value.Length + 5];
        int cursor = 0;
        pattern[cursor++] = (byte)'"';
        Id.Span.CopyTo(pattern.AsSpan(cursor));
        cursor += Id.Length;
        pattern[cursor++] = (byte)'"';
        pattern[cursor++] = (byte)':';
        pattern[cursor++] = (byte)'"';
        Value.Span.CopyTo(pattern.AsSpan(cursor));
        cursor += Value.Length;
        pattern[cursor] = (byte)'"';

        return pattern;
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
internal sealed class LongfellowJwtWitness
{
    private const string Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private const string DeviceKeyPrefix = "\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"";
    private const string DeviceKeySeparator = "\",\"y\":\"";

    /// <summary>One base64url-encoded P-256 coordinate's character count (43 unpadded characters carry 32 bytes).</summary>
    private const int CoordinateCharacterCount = 43;

    /// <summary>One SHA-256 block's byte width.</summary>
    private const int BytesPerBlock = 64;

    /// <summary>The words one SHA-256 block's advice records: the schedule extension, both per-round registers, and the final state.</summary>
    private const int WordsPerBlock = 48 + 64 + 64 + 8;

    private readonly LongfellowLogicFieldOperations field;
    private readonly LongfellowEllipticCurveParameters curve;
    private readonly LongfellowEcdsaVerifyWitness jwtSignature;
    private readonly LongfellowEcdsaVerifyWitness kbSignature;
    private readonly LongfellowBitPluckerEncoder encoder;
    private readonly byte[] basePrime;
    private readonly int maxBlocks;

    private readonly byte[] issuerDigest;
    private readonly byte[] deviceKeyX;
    private readonly byte[] deviceKeyY;
    private readonly byte[] kbDigest;
    private readonly byte[] preimage;
    private readonly byte[] eBits;
    private readonly LongfellowFlatSha256BlockWitness[] blocks;
    private byte occupiedBlockCount;
    private readonly List<int> attributeIndices = [];
    private int payloadIndex;
    private int payloadLength;

    /// <summary>The key-binding digest as a canonical base-field element — the public <c>e2</c> input the verifier recomputes from the presented key-binding JWT.</summary>
    public ReadOnlyMemory<byte> KbDigest => kbDigest;


    /// <summary>
    /// Constructs the generator over the same field bundles and curve the statement circuit uses.
    /// </summary>
    /// <param name="field">The base-field bundle.</param>
    /// <param name="orderMultiply">The order-field multiplication, canonical in and out.</param>
    /// <param name="orderSubtract">The order-field subtraction, canonical in and out.</param>
    /// <param name="orderInvert">The order-field inversion, canonical in and out.</param>
    /// <param name="orderCurve">The curve parameter set the order-field delegates dispatch on.</param>
    /// <param name="curve">The curve constants.</param>
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

        this.field = field;
        this.curve = curve;
        maxBlocks = maxShaBlocks;
        jwtSignature = new LongfellowEcdsaVerifyWitness(field, orderMultiply, orderSubtract, orderInvert, orderCurve, curve);
        kbSignature = new LongfellowEcdsaVerifyWitness(field, orderMultiply, orderSubtract, orderInvert, orderCurve, curve);
        encoder = new LongfellowBitPluckerEncoder(field, LongfellowJwtConstants.ShaJwtPluckerBits);
        basePrime = LongfellowEcdsaVerifyWitness.DeriveBasePrime(field);

        issuerDigest = new byte[Scalar.SizeBytes];
        deviceKeyX = new byte[Scalar.SizeBytes];
        deviceKeyY = new byte[Scalar.SizeBytes];
        kbDigest = new byte[Scalar.SizeBytes];
        preimage = new byte[maxShaBlocks * BytesPerBlock];
        eBits = new byte[LongfellowLogic.BitWidth256];
        blocks = new LongfellowFlatSha256BlockWitness[maxShaBlocks];
        for(int i = 0; i < maxShaBlocks; i++)
        {
            blocks[i] = new LongfellowFlatSha256BlockWitness();
        }
    }


    /// <summary>
    /// The column length in elements for a given disclosed attribute count.
    /// </summary>
    /// <param name="attributeCount">The disclosed attribute count.</param>
    /// <returns>The element count.</returns>
    public int GetElementCount(int attributeCount)
    {
        int packedPerWord = encoder.PackedV32ElementCount;

        return 3
            + (2 * jwtSignature.ElementCount)
            + (maxBlocks * BytesPerBlock * LongfellowLogic.BitWidth8)
            + LongfellowLogic.BitWidth256
            + (maxBlocks * WordsPerBlock * packedPerWord)
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

        if(!TryParseJws(issuerJws, out JwsParts issuer))
        {
            return false;
        }

        if(issuer.MessageLength > (maxBlocks * BytesPerBlock) - 9)
        {
            return false;
        }

        LongfellowFlatSha256Witness.TransformAndWitnessMessage(issuerJws[..issuer.MessageLength], maxBlocks, out occupiedBlockCount, preimage, blocks);

        ReduceOnce(issuer.Digest, basePrime, issuerDigest);
        payloadIndex = issuer.PayloadIndex;
        payloadLength = issuer.PayloadLength;

        if(!jwtSignature.ComputeWitness(pkX, pkY, issuer.Digest, issuer.R, issuer.S))
        {
            return false;
        }

        for(int i = 0; i < LongfellowLogic.BitWidth256; i++)
        {
            eBits[i] = (byte)((issuer.Digest[Scalar.SizeBytes - 1 - (i / 8)] >> (i % 8)) & 1);
        }

        //Locate each disclosed attribute in the decoded payload.
        if(!TryBase64UrlDecode(issuerJws.Slice(issuer.PayloadIndex, issuer.PayloadLength), out byte[] payload))
        {
            return false;
        }

        attributeIndices.Clear();
        for(int i = 0; i < attributes.Count; i++)
        {
            int index = payload.AsSpan().IndexOf(attributes[i].BuildPattern());
            if(index < 0)
            {
                return false;
            }

            attributeIndices.Add(index);
        }

        if(!TryExtractDeviceKey(payload))
        {
            return false;
        }

        //The key-binding portion: parse, and verify under the payload-carried device key.
        if(kbJws.IsEmpty || !TryParseJws(kbJws, out JwsParts kb))
        {
            return false;
        }

        if(!kbSignature.ComputeWitness(deviceKeyX, deviceKeyY, kb.Digest, kb.R, kb.S))
        {
            return false;
        }

        ReduceOnce(kb.Digest, basePrime, kbDigest);

        return true;
    }


    /// <summary>
    /// The reference's <c>fill_witness</c>: writes the private witness region in declaration order.
    /// </summary>
    /// <param name="destination">Receives <see cref="GetElementCount"/> elements of <see cref="Scalar.SizeBytes"/> bytes each.</param>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is not exactly the column's byte length.</exception>
    public void FillWitness(Span<byte> destination)
    {
        int elementCount = GetElementCount(attributeIndices.Count);
        if(destination.Length != elementCount * Scalar.SizeBytes)
        {
            throw new ArgumentException($"The column is exactly {elementCount} elements of {Scalar.SizeBytes} bytes.", nameof(destination));
        }

        int cursor = 0;
        WriteElement(destination, ref cursor, issuerDigest);
        WriteElement(destination, ref cursor, deviceKeyX);
        WriteElement(destination, ref cursor, deviceKeyY);

        jwtSignature.FillWitness(destination.Slice(cursor * Scalar.SizeBytes, jwtSignature.ElementCount * Scalar.SizeBytes));
        cursor += jwtSignature.ElementCount;
        kbSignature.FillWitness(destination.Slice(cursor * Scalar.SizeBytes, kbSignature.ElementCount * Scalar.SizeBytes));
        cursor += kbSignature.ElementCount;

        for(int i = 0; i < preimage.Length; i++)
        {
            WriteBits(destination, ref cursor, preimage[i], LongfellowLogic.BitWidth8);
        }

        for(int i = 0; i < eBits.Length; i++)
        {
            WriteBits(destination, ref cursor, eBits[i], 1);
        }

        for(int j = 0; j < maxBlocks; j++)
        {
            FillShaBlock(destination, ref cursor, blocks[j]);
        }

        WriteBits(destination, ref cursor, occupiedBlockCount, LongfellowLogic.BitWidth8);

        for(int i = 0; i < attributeIndices.Count; i++)
        {
            WriteBits(destination, ref cursor, (ulong)attributeIndices[i], LongfellowJwtConstants.JwtIndexBits);
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

        byte[] pattern = attribute.BuildPattern();
        for(int i = 0; i < LongfellowJwtOpenedAttributeWires.PatternLength; i++)
        {
            byte value = i < pattern.Length ? pattern[i] : (byte)0;
            WriteValueBits(field, destination, ref cursor, value, LongfellowLogic.BitWidth8);
        }

        WriteValueBits(field, destination, ref cursor, (ulong)pattern.Length, LongfellowLogic.BitWidth8);
    }


    /// <summary>The parsed pieces of one JWS compact serialization.</summary>
    /// <param name="MessageLength">The signed message's byte length (<c>header.payload</c>).</param>
    /// <param name="PayloadIndex">The payload's start index in the token.</param>
    /// <param name="PayloadLength">The payload's byte length.</param>
    /// <param name="Digest">The SHA-256 digest of the signed message.</param>
    /// <param name="R">The signature's <c>r</c>, big-endian.</param>
    /// <param name="S">The signature's <c>s</c>, big-endian.</param>
    private readonly record struct JwsParts(int MessageLength, int PayloadIndex, int PayloadLength, byte[] Digest, byte[] R, byte[] S);


    /// <summary>
    /// The reference's <c>parse_jws</c>: splits <c>header.payload.signature</c>, hashes the signed
    /// message, and decodes the signature into its scalar pair.
    /// </summary>
    /// <param name="jws">The JWS bytes.</param>
    /// <param name="parts">Receives the parsed pieces.</param>
    /// <returns>Whether the JWS parsed.</returns>
    private static bool TryParseJws(ReadOnlySpan<byte> jws, out JwsParts parts)
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
        byte[] digest = SHA256.HashData(jws[..secondDot]);

        if(!TryBase64UrlDecode(signature, out byte[] signatureBytes) || signatureBytes.Length < 2 * Scalar.SizeBytes)
        {
            return false;
        }

        parts = new JwsParts(
            secondDot,
            dot + 1,
            secondDot - dot - 1,
            digest,
            signatureBytes[..Scalar.SizeBytes],
            signatureBytes[Scalar.SizeBytes..(2 * Scalar.SizeBytes)]);

        return true;
    }


    /// <summary>
    /// The reference's <c>compute_witness</c> device-key extraction: locates the <c>cnf</c> claim's
    /// JWK, decodes its base64url coordinates, and stores them as base-field elements.
    /// </summary>
    /// <param name="payload">The decoded payload.</param>
    /// <returns>Whether the device key was found.</returns>
    private bool TryExtractDeviceKey(byte[] payload)
    {
        byte[] prefix = Encoding.ASCII.GetBytes(DeviceKeyPrefix);
        int xIndex = payload.AsSpan().IndexOf(prefix);
        if(xIndex < 0)
        {
            return false;
        }

        int xStart = xIndex + prefix.Length;
        byte[] separator = Encoding.ASCII.GetBytes(DeviceKeySeparator);
        int yIndex = payload.AsSpan(xStart).IndexOf(separator);
        if(yIndex < 0)
        {
            return false;
        }

        int yStart = xStart + yIndex + separator.Length;
        if(xStart + CoordinateCharacterCount > payload.Length || yStart + CoordinateCharacterCount > payload.Length)
        {
            return false;
        }

        if(!TryBase64UrlDecode(payload.AsSpan(xStart, CoordinateCharacterCount), out byte[] xBytes)
            || !TryBase64UrlDecode(payload.AsSpan(yStart, CoordinateCharacterCount), out byte[] yBytes))
        {
            return false;
        }

        ReduceOnce(xBytes.AsSpan(0, Scalar.SizeBytes), basePrime, deviceKeyX);
        ReduceOnce(yBytes.AsSpan(0, Scalar.SizeBytes), basePrime, deviceKeyY);

        return true;
    }


    /// <summary>
    /// The reference's host-side <c>base64_decode_url</c> (<c>decode_util.cc</c>): the URL-safe
    /// unpadded alphabet, failure on any other character, and three output bytes per group with a
    /// zero-padded trailing partial group.
    /// </summary>
    /// <param name="input">The encoded bytes.</param>
    /// <param name="output">Receives the decoded bytes.</param>
    /// <returns>Whether every character was in the alphabet.</returns>
    private static bool TryBase64UrlDecode(ReadOnlySpan<byte> input, out byte[] output)
    {
        var decoded = new byte[((input.Length + 3) / 4) * 3];
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
                    output = [];

                    return false;
                }

                group[j] = symbol;
            }

            decoded[cursor++] = (byte)((group[0] << 2) | (group[1] >> 4));
            decoded[cursor++] = (byte)(((group[1] << 4) | (group[2] >> 2)) & 0xFF);
            decoded[cursor++] = (byte)(((group[2] << 6) | group[3]) & 0xFF);
        }

        output = decoded;

        return true;
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


    /// <summary>Writes one 32-bit word as its plucker-packed elements.</summary>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="word">The word to pack.</param>
    private void WritePackedWord(Span<byte> destination, ref int cursor, uint word)
    {
        ReadOnlyMemory<byte>[] packed = encoder.MakePackedV32(word);
        for(int i = 0; i < packed.Length; i++)
        {
            packed[i].Span.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
            cursor++;
        }
    }


    /// <summary>Writes a value's bits, least significant first, one field element per bit (the reference filler's <c>push_back(x, bits, F)</c>).</summary>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor.</param>
    /// <param name="value">The value.</param>
    /// <param name="bitCount">The bit count.</param>
    private void WriteBits(Span<byte> destination, ref int cursor, ulong value, int bitCount)
    {
        WriteValueBits(field, destination, ref cursor, value, bitCount);
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
    private static void WriteElement(Span<byte> destination, ref int cursor, byte[] element)
    {
        element.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
        cursor++;
    }


    /// <summary>Reduces a raw 256-bit value once modulo <paramref name="modulus"/> (the same single conditional subtraction the ECDSA witness generator uses); shared with the facade's verifier-side key-binding digest computation, which must reduce identically.</summary>
    /// <param name="value">The raw big-endian value.</param>
    /// <param name="modulus">The modulus.</param>
    /// <param name="destination">Receives the reduced value.</param>
    internal static void ReduceOnce(ReadOnlySpan<byte> value, ReadOnlySpan<byte> modulus, Span<byte> destination)
    {
        bool subtract = true;
        for(int i = 0; i < Scalar.SizeBytes; i++)
        {
            if(value[i] != modulus[i])
            {
                subtract = value[i] > modulus[i];

                break;
            }
        }

        if(!subtract)
        {
            value.CopyTo(destination);

            return;
        }

        int borrow = 0;
        for(int i = Scalar.SizeBytes - 1; i >= 0; i--)
        {
            int difference = value[i] - modulus[i] - borrow;
            borrow = difference < 0 ? 1 : 0;
            destination[i] = (byte)(difference & 0xFF);
        }
    }
}
