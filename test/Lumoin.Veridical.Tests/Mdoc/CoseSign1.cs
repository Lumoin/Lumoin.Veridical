using Lumoin.Veritas.Cbor;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The issuer's COSE_Sign1 (<c>issuerAuth</c>) extracted from a real ISO 18013-5 mdoc
/// DeviceResponse: the serialized protected header, the payload (the tagged
/// MobileSecurityObject bytes), the raw signature (r‖s), and the issuer DS certificate from
/// the unprotected header's x5chain. Parsed with <see cref="CborReader"/> — the test project
/// plays the application consuming credentials; the Veridical library stays serialization-free
/// and is fed the parsed bytes and offsets. The bytes the issuer actually signed are the COSE
/// <c>Sig_structure</c>, rebuilt by <see cref="SignatureStructure"/>.
/// </summary>
internal sealed record CoseSign1(byte[] Protected, byte[] Payload, byte[] Signature, byte[] IssuerCertificate)
{
    /// <summary>The COSE x5chain header label (RFC 9360).</summary>
    private const long X5ChainLabel = 33;

    /// <summary>The element count of a COSE_Sign1 and of its <c>Sig_structure</c>.</summary>
    private const int ElementCount = 4;

    /// <summary>The CBOR major-type-4 header of a definite-length array of <see cref="ElementCount"/> elements.</summary>
    private const byte ArrayHeader = 0x80 | ElementCount;

    /// <summary>The first element of a COSE_Sign1 <c>Sig_structure</c>, naming the context.</summary>
    private const string Signature1Context = "Signature1";


    /// <summary>Extracts the first document's <c>issuerAuth</c> from <paramref name="deviceResponse"/>.</summary>
    public static CoseSign1 Extract(ReadOnlyMemory<byte> deviceResponse)
    {
        byte[] documents = CborNavigation.RequireMapValue(deviceResponse, "documents");
        byte[] firstDocument = CborNavigation.ArrayElements(documents)[0];
        byte[] issuerSigned = CborNavigation.RequireMapValue(firstDocument, "issuerSigned");
        byte[] issuerAuth = CborNavigation.RequireMapValue(issuerSigned, "issuerAuth");

        var reader = new CborReader(issuerAuth, CborNavigation.Options);
        reader.ReadStartArray();
        byte[] protectedHeader = CborNavigation.EncodedValue(reader, issuerAuth);
        byte[] unprotected = CborNavigation.EncodedValue(reader, issuerAuth);
        byte[] payload = CborNavigation.EncodedValue(reader, issuerAuth);
        byte[] signature = reader.ReadByteString();
        reader.ReadEndArray();

        return new CoseSign1(protectedHeader, payload, signature, ExtractIssuerCertificate(unprotected));
    }


    /// <summary>
    /// The COSE <c>Sig_structure</c> the issuer signed (and over whose SHA-256 ECDSA is computed):
    /// <c>["Signature1", body_protected, external_aad (empty), payload]</c>. The protected header and payload
    /// are spliced in verbatim as the encoded byte-string items they already are in the COSE_Sign1, so the
    /// reconstruction is byte-exact; because two of the four items bypass the writer, the array header is
    /// placed by hand and the writer never opens the array it would otherwise count.
    /// </summary>
    public byte[] SignatureStructure()
    {
        using var structure = new SlabBufferWriter(BaseMemoryPool.Shared);
        structure.GetSpan(1)[0] = ArrayHeader;
        structure.Advance(1);

        var writer = new CborWriter(structure, CborNavigation.Options);
        writer.WriteTextString(Signature1Context);
        structure.Write(Protected);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        structure.Write(Payload);

        int length = structure.BytesWritten;
        using IMemoryOwner<byte> encoded = structure.Detach();

        return encoded.Memory.Span[..length].ToArray();
    }


    /// <summary>
    /// The issuer DS certificate from the unprotected header's x5chain (label 33): a single bstr certificate,
    /// or the leaf (first) of a bstr array. Header labels are integers.
    /// </summary>
    private static byte[] ExtractIssuerCertificate(ReadOnlyMemory<byte> unprotectedHeader)
    {
        var reader = new CborReader(unprotectedHeader, CborNavigation.Options);
        int count = reader.ReadStartMap() ?? throw new FormatException("Indefinite-length maps are not used by COSE.");
        for(int i = 0; i < count; i++)
        {
            if(reader.PeekState() is not (CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger))
            {
                CborNavigation.SkipValue(reader);
                CborNavigation.SkipValue(reader);

                continue;
            }

            long label = reader.ReadInt64();
            if(label != X5ChainLabel)
            {
                CborNavigation.SkipValue(reader);

                continue;
            }

            if(reader.PeekState() == CborReaderState.StartArray)
            {
                reader.ReadStartArray();

                return reader.ReadByteString();
            }

            return reader.ReadByteString();
        }

        throw new FormatException("The COSE unprotected header has no x5chain (label 33).");
    }
}
