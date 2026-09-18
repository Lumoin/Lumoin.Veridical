using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veritas.Cbor;
using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The ISO/IEC 18013-5 device-authentication message and its hash <c>e2</c>, the public wire the mdoc SIG
/// circuit verifies the device signature against: the <c>DeviceAuthentication</c> array
/// <c>["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]</c> (ISO/IEC 18013-5
/// §9.1.3.4), its <c>DeviceAuthenticationBytes</c> wrapping <c>#6.24(bstr .cbor DeviceAuthentication)</c>, and
/// the COSE_Sign1 <c>Sig_structure</c> (RFC 9052 §4.4) the device key signs with that wrapping as the detached
/// payload. <c>e2</c> is the SHA-256 of the <c>Sig_structure</c>, read big-endian and reduced into the P-256
/// base field — the reference's <c>compute_transcript_hash</c> (<c>lib/circuits/mdoc/mdoc_witness.h</c>)
/// before its Montgomery lift.
/// </summary>
/// <remarks>
/// <para>
/// Every self-contained item is encoded by <see cref="CborWriter"/>. The session transcript is already an
/// encoded CBOR item and enters the array verbatim, so the array header is placed by hand and the writer never
/// opens the enclosing array: a writer that had opened it would count the elements it wrote itself and refuse
/// to close an array of four after seeing three.
/// </para>
/// <para>
/// The device name spaces are the empty map, as in every credential the reference circuits prove; a non-empty
/// <c>DeviceNameSpaces</c> would change <c>DeviceNameSpacesBytes</c> and with it <c>e2</c>. The protected
/// header is <c>{1: -7}</c>, ES256, the only device-signature algorithm the P-256 circuit admits.
/// </para>
/// </remarks>
internal static class MdocDeviceAuthentication
{
    /// <summary>The ISO/IEC 18013-5 mobile driving licence document type.</summary>
    public const string MdlDocType = "org.iso.18013.5.1.mDL";

    /// <summary>The element count of <c>DeviceAuthentication</c>; the <c>Sig_structure</c> has the same count.</summary>
    private const int ElementCount = 4;

    /// <summary>The CBOR major-type-4 header of a definite-length array of <see cref="ElementCount"/> elements.</summary>
    private const byte ArrayHeader = 0x80 | ElementCount;

    /// <summary>CBOR tag 24: the tagged byte string holds an encoded CBOR data item (RFC 8949 §3.4.5.1).</summary>
    private const ulong EncodedCborDataItemTag = 24;

    /// <summary>The COSE header label <c>alg</c> (RFC 9052 §3.1).</summary>
    private const long AlgorithmHeaderLabel = 1;

    /// <summary>The COSE algorithm identifier of ES256, ECDSA over P-256 with SHA-256 (RFC 9053 §2.1).</summary>
    private const long Es256Algorithm = -7;

    /// <summary>The first element of <c>DeviceAuthentication</c>, naming the structure.</summary>
    private const string DeviceAuthenticationLabel = "DeviceAuthentication";

    /// <summary>The first element of a COSE_Sign1 <c>Sig_structure</c>, naming the context.</summary>
    private const string Signature1Context = "Signature1";

    /// <summary>The encoded empty <c>DeviceNameSpaces</c> map, the content <c>DeviceNameSpacesBytes</c> wraps.</summary>
    private static ReadOnlySpan<byte> EmptyDeviceNameSpaces => [0xA0];

    /// <summary>The shared test-side encoder options.</summary>
    private static CborSerializerOptions Options => CborNavigation.Options;


    /// <summary>
    /// Writes the encoded <c>DeviceAuthentication</c> array for <paramref name="sessionTranscript"/> (an
    /// already-encoded CBOR <c>SessionTranscript</c>, spliced verbatim) and <paramref name="docType"/>.
    /// </summary>
    /// <param name="sessionTranscript">The encoded <c>SessionTranscript</c> item.</param>
    /// <param name="docType">The credential's document type.</param>
    /// <param name="destination">Receives the encoded array.</param>
    public static void WriteDeviceAuthentication(ReadOnlySpan<byte> sessionTranscript, string docType, IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(docType);
        ArgumentNullException.ThrowIfNull(destination);

        destination.GetSpan(1)[0] = ArrayHeader;
        destination.Advance(1);

        var writer = new CborWriter(destination, Options);
        writer.WriteTextString(DeviceAuthenticationLabel);
        destination.Write(sessionTranscript);
        writer.WriteTextString(docType);
        writer.WriteTag(EncodedCborDataItemTag);
        writer.WriteByteString(EmptyDeviceNameSpaces);
    }


    /// <summary>
    /// Writes <c>DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)</c>, the detached payload of
    /// the device's COSE_Sign1.
    /// </summary>
    /// <param name="sessionTranscript">The encoded <c>SessionTranscript</c> item.</param>
    /// <param name="docType">The credential's document type.</param>
    /// <param name="destination">Receives the tagged byte string.</param>
    /// <param name="pool">The pool the intermediate encoding is rented from.</param>
    public static void WriteDeviceAuthenticationBytes(ReadOnlySpan<byte> sessionTranscript, string docType, IBufferWriter<byte> destination, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(pool);

        using var deviceAuthentication = new SlabBufferWriter(pool);
        WriteDeviceAuthentication(sessionTranscript, docType, deviceAuthentication);
        int length = deviceAuthentication.BytesWritten;
        using IMemoryOwner<byte> encoded = deviceAuthentication.Detach();

        var writer = new CborWriter(destination, Options);
        writer.WriteTag(EncodedCborDataItemTag);
        writer.WriteByteString(encoded.Memory.Span[..length]);
    }


    /// <summary>
    /// Writes the COSE_Sign1 <c>Sig_structure</c> <c>["Signature1", protected, external_aad, payload]</c> the
    /// device key signs: the protected header <c>{1: -7}</c> as an encoded byte string, an empty
    /// <c>external_aad</c>, and <c>DeviceAuthenticationBytes</c> as the payload byte string.
    /// </summary>
    /// <param name="sessionTranscript">The encoded <c>SessionTranscript</c> item.</param>
    /// <param name="docType">The credential's document type.</param>
    /// <param name="destination">Receives the encoded <c>Sig_structure</c>.</param>
    /// <param name="pool">The pool the intermediate encodings are rented from.</param>
    public static void WriteSignatureStructure(ReadOnlySpan<byte> sessionTranscript, string docType, IBufferWriter<byte> destination, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(pool);

        using var payload = new SlabBufferWriter(pool);
        WriteDeviceAuthenticationBytes(sessionTranscript, docType, payload, pool);
        int payloadLength = payload.BytesWritten;
        using IMemoryOwner<byte> payloadBytes = payload.Detach();

        using var protectedHeader = new SlabBufferWriter(pool);
        var headerWriter = new CborWriter(protectedHeader, Options);
        headerWriter.WriteStartMap(1);
        headerWriter.WriteInt64(AlgorithmHeaderLabel);
        headerWriter.WriteInt64(Es256Algorithm);
        headerWriter.WriteEndMap();
        int headerLength = protectedHeader.BytesWritten;
        using IMemoryOwner<byte> headerBytes = protectedHeader.Detach();

        var writer = new CborWriter(destination, Options);
        writer.WriteStartArray(ElementCount);
        writer.WriteTextString(Signature1Context);
        writer.WriteByteString(headerBytes.Memory.Span[..headerLength]);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        writer.WriteByteString(payloadBytes.Memory.Span[..payloadLength]);
        writer.WriteEndArray();
    }


    /// <summary>
    /// The device-authentication hash <c>e2</c>: SHA-256 over the <c>Sig_structure</c>, read big-endian and
    /// reduced modulo the P-256 base-field order — the canonical value the SIG circuit's public wire 3 carries.
    /// </summary>
    /// <param name="sessionTranscript">The encoded <c>SessionTranscript</c> item.</param>
    /// <param name="docType">The credential's document type.</param>
    /// <param name="pool">The pool the encodings are rented from.</param>
    /// <returns>The canonical <c>e2</c>.</returns>
    public static BigInteger ComputeDeviceHash(ReadOnlySpan<byte> sessionTranscript, string docType, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        using var signatureStructure = new SlabBufferWriter(pool);
        WriteSignatureStructure(sessionTranscript, docType, signatureStructure, pool);
        int length = signatureStructure.BytesWritten;
        using IMemoryOwner<byte> encoded = signatureStructure.Detach();

        Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(encoded.Memory.Span[..length], digest);

        return ReduceDigest(digest);
    }


    /// <summary>
    /// Reduces a SHA-256 digest, read big-endian, into the P-256 base field: the canonical form of the value the
    /// reference lifts into Montgomery form. A digest at or above the field order wraps exactly once, since the
    /// order exceeds half of 2^256.
    /// </summary>
    /// <param name="digest">The 32-byte big-endian digest.</param>
    /// <returns>The digest as a base-field element.</returns>
    public static BigInteger ReduceDigest(ReadOnlySpan<byte> digest) =>
        new BigInteger(digest, isUnsigned: true, isBigEndian: true) % P256BaseFieldReference.FieldOrder;
}
