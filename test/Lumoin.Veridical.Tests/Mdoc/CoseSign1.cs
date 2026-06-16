using System;
using System.Formats.Cbor;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The issuer's COSE_Sign1 (<c>issuerAuth</c>) extracted from a real ISO 18013-5 mdoc
/// DeviceResponse: the serialized protected header, the payload (the tagged
/// MobileSecurityObject bytes), the raw signature (r‖s), and the issuer DS certificate from
/// the unprotected header's x5chain. Parsed with <see cref="CborReader"/> — the test project
/// uses the real serialization library (it mimics an application consuming credentials); the
/// Veridical library stays serialization-free and is fed the parsed bytes/offsets. The bytes
/// the issuer actually signed are the COSE <c>Sig_structure</c>, rebuilt by
/// <see cref="SignatureStructure"/>.
/// </summary>
internal sealed record CoseSign1(byte[] Protected, byte[] Payload, byte[] Signature, byte[] IssuerCertificate)
{
    //The COSE x5chain header label (RFC 9360).
    private const long X5ChainLabel = 33;


    public static CoseSign1 Extract(ReadOnlyMemory<byte> deviceResponse)
    {
        byte[] documents = CborNavigation.RequireMapValue(deviceResponse, "documents");
        byte[] firstDocument = CborNavigation.ArrayElements(documents)[0];
        byte[] issuerSigned = CborNavigation.RequireMapValue(firstDocument, "issuerSigned");
        byte[] issuerAuth = CborNavigation.RequireMapValue(issuerSigned, "issuerAuth");

        var reader = new CborReader(issuerAuth);
        reader.ReadStartArray();
        byte[] protectedHeader = reader.ReadEncodedValue().ToArray();
        byte[] unprotected = reader.ReadEncodedValue().ToArray();
        byte[] payload = reader.ReadEncodedValue().ToArray();
        byte[] signature = reader.ReadByteString();
        reader.ReadEndArray();

        return new CoseSign1(protectedHeader, payload, signature, ExtractIssuerCertificate(unprotected));
    }


    //The COSE Sig_structure the issuer signed (and over whose SHA-256 ECDSA is computed):
    //["Signature1", body_protected, external_aad (empty), payload]. The protected header and
    //payload are spliced in verbatim as the encoded byte-string items they already are in the
    //COSE_Sign1, so the reconstruction is byte-exact.
    public byte[] SignatureStructure()
    {
        var writer = new CborWriter();
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteEncodedValue(Protected);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        writer.WriteEncodedValue(Payload);
        writer.WriteEndArray();

        return writer.Encode();
    }


    //The issuer DS certificate from the unprotected header's x5chain (label 33): a single bstr
    //certificate, or the leaf (first) of a bstr array. Header labels are integers.
    private static byte[] ExtractIssuerCertificate(ReadOnlyMemory<byte> unprotectedHeader)
    {
        var reader = new CborReader(unprotectedHeader);
        int count = reader.ReadStartMap() ?? throw new FormatException("Indefinite-length maps are not used by COSE.");
        for(int i = 0; i < count; i++)
        {
            if(reader.PeekState() is not (CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger))
            {
                reader.SkipValue();
                reader.SkipValue();
                continue;
            }

            long label = reader.ReadInt64();
            if(label != X5ChainLabel)
            {
                reader.SkipValue();
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
