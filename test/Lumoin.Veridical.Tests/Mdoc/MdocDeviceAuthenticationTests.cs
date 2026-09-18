using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// Pins <see cref="MdocDeviceAuthentication"/> against the reference: the device-authentication hash it
/// computes over the real credential's session transcript equals the <c>e2</c> the google/longfellow-zk
/// reference recorded in the anchor fixture's signature template, and the encoded structures carry the byte
/// layout ISO/IEC 18013-5 and RFC 9052 prescribe — including the two-byte length cutover at 256 bytes, where the
/// reference's own encoder once emitted a zero length (TOB-LIBZK-5).
/// </summary>
[TestClass]
internal sealed class MdocDeviceAuthenticationTests
{
    /// <summary>The relative path to the reference anchor file recording the session transcript and signature template these gates read from.</summary>
    private const string AnchorRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-output.txt";

    /// <summary>The byte width of one scalar in this test's canonical scratch buffers, matching the library-wide scalar size.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The signature template is <c>[one, pkX, pkY, e2]</c>; the device hash is its element 3.</summary>
    private const int DeviceHashTemplateIndex = 3;

    /// <summary>
    /// The session-transcript length that makes <c>DeviceAuthentication</c> exactly 256 bytes: the one-byte array
    /// header, the 21-byte "DeviceAuthentication" item and the 22-byte mDL document-type item (each a one-byte
    /// header and its text) and the four-byte empty <c>DeviceNameSpacesBytes</c> account for the other 48.
    /// </summary>
    private const int BoundaryTranscriptLength = 208;

    /// <summary>The two-byte header of the byte string the boundary transcript is shaped as.</summary>
    private const int ByteStringHeaderLength = 2;

    /// <summary>
    /// Where the payload byte string's header starts in the <c>Sig_structure</c>: after the array header, the
    /// eleven-byte "Signature1", the four-byte protected header and the one-byte empty <c>external_aad</c>.
    /// </summary>
    private const int PayloadHeaderOffset = 17;

    /// <summary>
    /// The <c>Sig_structure</c> length at the boundary: the 17 bytes before the payload, its three-byte header,
    /// the tag and the three-byte inner header, and the 256-byte <c>DeviceAuthentication</c>.
    /// </summary>
    private const int BoundarySignatureStructureLength = 281;

    /// <summary>
    /// The <c>Sig_structure</c> over <see cref="ShortTranscript"/> and the mDL document type, byte for byte:
    /// <c>["Signature1", h'A10126', h'', h'D818 5834 84 74"DeviceAuthentication" 83F6F6F6 75"org.iso.18013.5.1.mDL"
    /// D81841A0']</c>.
    /// </summary>
    private const string ShortSignatureStructureHex = "846A5369676E61747572653143A10126405838D8185834847444657669636541757468656E7469636174696F6E83F6F6F6756F72672E69736F2E31383031332E352E312E6D444CD81841A0";

    /// <summary>
    /// A document type other than the mDL: the EU PID, whose 23 characters are the most a one-byte CBOR text-string
    /// header carries the length of.
    /// </summary>
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";

    /// <summary>The longest text whose length fits in the CBOR text-string header byte itself.</summary>
    private const int ShortFormTextLength = 23;

    /// <summary>
    /// Where the document type's header sits in <c>DeviceAuthentication</c> over <see cref="ShortTranscript"/>:
    /// after the array header, the 21-byte "DeviceAuthentication" item and the four transcript bytes.
    /// </summary>
    private const int DocTypeHeaderOffset = 26;

    /// <summary>The length of the empty <c>DeviceNameSpacesBytes</c>: tag 24 and a one-byte byte string holding the empty map.</summary>
    private const int EmptyDeviceNameSpacesBytesLength = 4;

    /// <summary>A minimal stand-in session transcript, the CBOR array <c>[null, null, null]</c>.</summary>
    private static ReadOnlySpan<byte> ShortTranscript => [0x83, 0xF6, 0xF6, 0xF6];

    /// <summary>The stand-in transcript with its last element changed, <c>[null, null, true]</c>.</summary>
    private static ReadOnlySpan<byte> AlteredTranscript => [0x83, 0xF6, 0xF6, 0xF5];

    /// <summary>The payload byte string's header at the boundary: two-byte length 261, the 256 bytes plus the tag and inner header.</summary>
    private static ReadOnlySpan<byte> PayloadHeaderAtBoundary => [0x59, 0x01, 0x05];

    /// <summary>Tag 24 and the inner byte string's header at the boundary: two-byte length 256.</summary>
    private static ReadOnlySpan<byte> InnerHeaderAtBoundary => [0xD8, 0x18, 0x59, 0x01, 0x00];

    /// <summary>The header of a 23-character text string: the length sits in the header byte.</summary>
    private static ReadOnlySpan<byte> ShortFormDocTypeHeader => [0x77];

    /// <summary>The header of a 24-character text string: the length moves to a one-byte extension.</summary>
    private static ReadOnlySpan<byte> ExtendedFormDocTypeHeader => [0x78, 0x18];


    /// <summary>Verifies that the device-authentication hash computed over the real credential's recorded session transcript equals the reference's own e2 from the anchor fixture's signature template.</summary>
    [TestMethod]
    public void TheDeviceHashReproducesTheReferenceTranscriptHashOverTheRealCredential()
    {
        //The anchor fixture holds the 117-byte ISO session transcript the reference proved mdoc-00 under and the
        //signature template whose element 3 is the e2 its compute_transcript_hash produced for it.
        byte[] transcript = Convert.FromHexString(FixtureValue("transcript"));
        BigInteger expected = ReferenceDeviceHash();

        BigInteger e2 = MdocDeviceAuthentication.ComputeDeviceHash(transcript, MdocDeviceAuthentication.MdlDocType, BaseMemoryPool.Shared);

        Assert.AreEqual(expected, e2, "The device-authentication hash must equal the reference's e2 for the real session transcript.");
    }


    /// <summary>Verifies that the encoded Sig_structure over a short stand-in transcript matches the ISO/IEC 18013-5 and RFC 9052 layout byte for byte.</summary>
    [TestMethod]
    public void TheSignatureStructureIsByteExactOverAShortTranscript()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var structure = new SlabBufferWriter(pool);
        MdocDeviceAuthentication.WriteSignatureStructure(ShortTranscript, MdocDeviceAuthentication.MdlDocType, structure, pool);
        int length = structure.BytesWritten;
        using IMemoryOwner<byte> encoded = structure.Detach();

        byte[] expected = Convert.FromHexString(ShortSignatureStructureHex);
        Assert.IsTrue(encoded.Memory.Span[..length].SequenceEqual(expected), "The Sig_structure must carry the ISO/IEC 18013-5 and RFC 9052 layout byte for byte.");
    }


    /// <summary>Verifies that a transcript making DeviceAuthentication exactly 256 bytes encodes the inner byte string's two-byte length as 256 and the payload's two-byte length as 261, rather than the zero length the reference's serializer once produced at this boundary (TOB-LIBZK-5).</summary>
    [TestMethod]
    public void TheEncodingCrossesTheTwoByteLengthBoundaryCorrectly()
    {
        //TOB-LIBZK-5: the reference's own serializer once encoded a 256-byte DeviceAuthentication with a zero
        //length (`> 256` where `>= 256` was meant). A transcript that makes DeviceAuthentication exactly 256 bytes
        //must give the inner byte string the two-byte length 256 and the payload the two-byte length 261.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> transcriptOwner = pool.Rent(BoundaryTranscriptLength);
        Span<byte> transcript = transcriptOwner.Memory.Span[..BoundaryTranscriptLength];
        FillByteStringTranscript(transcript);

        using var structure = new SlabBufferWriter(pool);
        MdocDeviceAuthentication.WriteSignatureStructure(transcript, MdocDeviceAuthentication.MdlDocType, structure, pool);
        int length = structure.BytesWritten;
        using IMemoryOwner<byte> encoded = structure.Detach();
        ReadOnlySpan<byte> signatureStructure = encoded.Memory.Span[..length];

        Assert.AreEqual(BoundarySignatureStructureLength, length, "The Sig_structure at the boundary has a fixed length.");
        Assert.IsTrue(signatureStructure.Slice(PayloadHeaderOffset, PayloadHeaderAtBoundary.Length).SequenceEqual(PayloadHeaderAtBoundary), "The payload byte string must carry the two-byte length 261.");
        Assert.IsTrue(signatureStructure.Slice(PayloadHeaderOffset + PayloadHeaderAtBoundary.Length, InnerHeaderAtBoundary.Length).SequenceEqual(InnerHeaderAtBoundary), "The tagged DeviceAuthentication byte string must carry the two-byte length 256.");
    }


    /// <summary>Verifies that the device hash is a P-256 base-field element and changes when either the session transcript or the document type changes.</summary>
    [TestMethod]
    public void TheDeviceHashDependsOnTheTranscriptAndTheDocumentType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        BigInteger baseline = MdocDeviceAuthentication.ComputeDeviceHash(ShortTranscript, MdocDeviceAuthentication.MdlDocType, pool);
        BigInteger otherTranscript = MdocDeviceAuthentication.ComputeDeviceHash(AlteredTranscript, MdocDeviceAuthentication.MdlDocType, pool);
        BigInteger otherDocType = MdocDeviceAuthentication.ComputeDeviceHash(ShortTranscript, PidDocType, pool);

        Assert.IsLessThan(P256BaseFieldReference.FieldOrder, baseline, "e2 is a P-256 base-field element.");
        Assert.AreNotEqual(baseline, otherTranscript, "e2 must depend on the session transcript.");
        Assert.AreNotEqual(baseline, otherDocType, "e2 must depend on the document type.");
    }


    /// <summary>Verifies that reducing a digest at or above the P-256 base-field order wraps correctly: the all-ones digest reduces to itself minus the order, and the order itself reduces to zero.</summary>
    [TestMethod]
    public void TheDigestReductionWrapsAValueAtOrAboveTheFieldOrder()
    {
        //A SHA-256 output at or above p occurs with probability near 2^-32, so no fixed transcript exercises the
        //reduction; feed it digests directly. 2^256 - 1 lies between p and 2p, so it reduces to exactly
        //2^256 - 1 - p, and p itself reduces to zero.
        Span<byte> allOnes = stackalloc byte[SHA256.HashSizeInBytes];
        allOnes.Fill(0xFF);
        BigInteger maximal = new BigInteger(allOnes, isUnsigned: true, isBigEndian: true);
        Assert.AreEqual(maximal - P256BaseFieldReference.FieldOrder, MdocDeviceAuthentication.ReduceDigest(allOnes), "A digest above p must wrap once.");

        Span<byte> order = stackalloc byte[SHA256.HashSizeInBytes];
        Assert.IsTrue(P256BaseFieldReference.FieldOrder.TryWriteBytes(order, out _, isUnsigned: true, isBigEndian: true), "p fits 32 bytes.");
        Assert.AreEqual(BigInteger.Zero, MdocDeviceAuthentication.ReduceDigest(order), "A digest equal to p must reduce to zero.");
    }


    /// <summary>Verifies that a 23-character document type keeps its length in the CBOR text-string header byte, while a 24-character document type moves the length into a one-byte extension.</summary>
    [TestMethod]
    public void TheDocumentTypeLengthCrossesTheShortFormCutoverCorrectly()
    {
        //A 23-character document type keeps its length in the text-string header byte; a 24-character one needs
        //the one-byte extension. The EU PID document type sits exactly at the short-form limit.
        Assert.HasCount(ShortFormTextLength, PidDocType, "The EU PID document type is the longest short-form text.");

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        AssertDocTypeHeader(PidDocType, ShortFormDocTypeHeader, pool);
        AssertDocTypeHeader(PidDocType + "x", ExtendedFormDocTypeHeader, pool);
    }


    /// <summary>
    /// Shapes <paramref name="transcript"/> as one CBOR byte string filling its whole length: a two-byte header
    /// and a running byte pattern.
    /// </summary>
    private static void FillByteStringTranscript(Span<byte> transcript)
    {
        int contentLength = transcript.Length - ByteStringHeaderLength;
        transcript[0] = 0x58;
        transcript[1] = (byte)contentLength;
        for(int i = ByteStringHeaderLength; i < transcript.Length; i++)
        {
            transcript[i] = (byte)i;
        }
    }


    /// <summary>
    /// Encodes <c>DeviceAuthentication</c> over <see cref="ShortTranscript"/> and <paramref name="docType"/> and
    /// asserts the document type's text-string header is <paramref name="expectedHeader"/> and the whole encoding
    /// has the length that header implies.
    /// </summary>
    private static void AssertDocTypeHeader(string docType, ReadOnlySpan<byte> expectedHeader, BaseMemoryPool pool)
    {
        using var structure = new SlabBufferWriter(pool);
        MdocDeviceAuthentication.WriteDeviceAuthentication(ShortTranscript, docType, structure);
        int length = structure.BytesWritten;
        using IMemoryOwner<byte> encoded = structure.Detach();

        ReadOnlySpan<byte> header = encoded.Memory.Span.Slice(DocTypeHeaderOffset, expectedHeader.Length);
        Assert.IsTrue(header.SequenceEqual(expectedHeader), $"A {docType.Length}-character document type must carry the header {Convert.ToHexString(expectedHeader)}.");
        Assert.AreEqual(DocTypeHeaderOffset + expectedHeader.Length + docType.Length + EmptyDeviceNameSpacesBytesLength, length, "The encoding must end with the empty DeviceNameSpacesBytes right after the document type.");
    }


    /// <summary>
    /// The reference's <c>e2</c>: signature-template element 3 of the anchor fixture, read from the
    /// little-endian wire order the fixture records.
    /// </summary>
    private static BigInteger ReferenceDeviceHash()
    {
        byte[] signatureTemplate = Convert.FromHexString(FixtureValue("sig_template"));
        ReadOnlySpan<byte> littleEndian = signatureTemplate.AsSpan(DeviceHashTemplateIndex * ScalarSize, ScalarSize);

        return new BigInteger(littleEndian, isUnsigned: true, isBigEndian: false);
    }


    /// <summary>The value of the <c>key=value</c> line for <paramref name="key"/> in the anchor fixture.</summary>
    private static string FixtureValue(string key)
    {
        string prefix = key + "=";
        string line = File.ReadLines($"../../../{AnchorRelativePath}").First(l => l.StartsWith(prefix, StringComparison.Ordinal));

        return line[prefix.Length..];
    }
}
