using Lumoin.Veritas.Cbor;
using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The public inputs and private witness an in-circuit mdoc disclosure proof needs, extracted
/// from a real ISO 18013-5 DeviceResponse for one disclosed element: the COSE
/// <c>Sig_structure</c> the issuer signed (its SHA-256 is the ECDSA message hash <c>e</c>), the
/// tagged <c>IssuerSignedItemBytes</c> whose SHA-256 the signed MSO holds, the contiguous public
/// disclosure pattern, the byte offsets binding them, the issuer DS public key, and the signature
/// split into <c>r</c> and <c>s</c>. This is exactly the shape
/// <c>AssertVerifiesMdocAttribute</c> consumes — the test/prover side that the
/// serialization-free library would, in production, receive from a parse delegate.
/// </summary>
internal sealed record MdocDisclosure(
    byte[] SignedStructure,
    byte[] IssuerSignedItem,
    int ItemDigestOffset,
    byte[] Attribute,
    int AttributeOffset,
    byte[] IssuerKeyX,
    byte[] IssuerKeyY,
    byte[] SignatureR,
    byte[] SignatureS)
{
    /// <summary>The <c>IssuerSignedItem</c> key whose value is the disclosed element's value.</summary>
    private const string ElementValueKey = "elementValue";

    /// <summary>The <c>IssuerSignedItem</c> key naming the disclosed element.</summary>
    private const string ElementIdentifierKey = "elementIdentifier";

    /// <summary>The width of each of <c>r</c> and <c>s</c> in an ES256 signature: the P-256 scalar size.</summary>
    private const int SignatureComponentSize = 32;


    /// <summary>
    /// Extracts the disclosure of <paramref name="elementIdentifier"/> in <paramref name="namespaceId"/> from
    /// the first document of <paramref name="deviceResponse"/>.
    /// </summary>
    public static MdocDisclosure Extract(ReadOnlyMemory<byte> deviceResponse, string namespaceId, string elementIdentifier)
    {
        CoseSign1 issuerAuth = CoseSign1.Extract(deviceResponse);
        byte[] signedStructure = issuerAuth.SignatureStructure();

        byte[] taggedItem = FindIssuerSignedItem(deviceResponse, namespaceId, elementIdentifier);

        //The MSO's valueDigests holds SHA-256(IssuerSignedItemBytes); the bytes signed are the
        //Sig_structure (whose payload is the MSO), so that digest is a substring of it.
        byte[] digest = SHA256.HashData(taggedItem);
        int itemDigestOffset = signedStructure.AsSpan().IndexOf(digest);
        if(itemDigestOffset < 0)
        {
            throw new InvalidOperationException($"SHA-256 of the '{elementIdentifier}' item is not present in the signed structure.");
        }

        (byte[] attribute, int attributeOffset) = LocateDisclosure(taggedItem, elementIdentifier);

        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(issuerAuth.IssuerCertificate);
        using ECDsa issuerKey = certificate.GetECDsaPublicKey() ?? throw new InvalidOperationException("The issuer certificate has no EC public key.");
        ECParameters parameters = issuerKey.ExportParameters(includePrivateParameters: false);

        return new MdocDisclosure(
            signedStructure,
            taggedItem,
            itemDigestOffset,
            attribute,
            attributeOffset,
            parameters.Q.X!,
            parameters.Q.Y!,
            issuerAuth.Signature[..SignatureComponentSize],
            issuerAuth.Signature[SignatureComponentSize..]);
    }


    /// <summary>
    /// The tagged (#6.24) <c>IssuerSignedItemBytes</c> in <c>nameSpaces[namespaceId]</c> that discloses
    /// <paramref name="elementIdentifier"/> — the exact bytes whose SHA-256 the MSO holds.
    /// </summary>
    private static byte[] FindIssuerSignedItem(ReadOnlyMemory<byte> deviceResponse, string namespaceId, string elementIdentifier)
    {
        byte[] documents = CborNavigation.RequireMapValue(deviceResponse, "documents");
        byte[] firstDocument = CborNavigation.ArrayElements(documents)[0];
        byte[] issuerSigned = CborNavigation.RequireMapValue(firstDocument, "issuerSigned");
        byte[] nameSpaces = CborNavigation.RequireMapValue(issuerSigned, "nameSpaces");
        byte[] items = CborNavigation.RequireMapValue(nameSpaces, namespaceId);

        foreach(byte[] taggedItem in CborNavigation.ArrayElements(items))
        {
            if(ItemElementIdentifier(taggedItem) == elementIdentifier)
            {
                return taggedItem;
            }
        }

        throw new InvalidOperationException($"No IssuerSignedItem in '{namespaceId}' discloses '{elementIdentifier}'.");
    }


    /// <summary>The <c>elementIdentifier</c> inside a tagged (#6.24) <c>IssuerSignedItemBytes</c>.</summary>
    private static string ItemElementIdentifier(byte[] taggedItem)
    {
        var reader = new CborReader(taggedItem, CborNavigation.Options);
        reader.ReadTag();
        byte[] inner = reader.ReadByteString();
        byte[]? identifier = CborNavigation.MapValue(inner, ElementIdentifierKey);

        return identifier is null ? string.Empty : new CborReader(identifier, CborNavigation.Options).ReadTextString();
    }


    /// <summary>
    /// The contiguous disclosure pattern in the tagged item: the <c>elementIdentifier</c> text string immediately
    /// followed by the <c>elementValue</c> entry (its key and value), as the <c>IssuerSignedItem</c> encodes them
    /// adjacently. Proving this substring is in the hashed-and-signed item proves the named element carries the
    /// disclosed value.
    /// </summary>
    private static (byte[] Attribute, int Offset) LocateDisclosure(byte[] taggedItem, string elementIdentifier)
    {
        var reader = new CborReader(taggedItem, CborNavigation.Options);
        reader.ReadTag();
        byte[] inner = reader.ReadByteString();
        byte[] elementValue = CborNavigation.RequireMapValue(inner, ElementValueKey);

        using var patternWriter = new SlabBufferWriter(BaseMemoryPool.Shared);
        var writer = new CborWriter(patternWriter, CborNavigation.Options);
        writer.WriteTextString(elementIdentifier);
        writer.WriteTextString(ElementValueKey);
        patternWriter.Write(elementValue);
        int length = patternWriter.BytesWritten;
        using IMemoryOwner<byte> encoded = patternWriter.Detach();

        byte[] pattern = encoded.Memory.Span[..length].ToArray();
        int offset = taggedItem.AsSpan().IndexOf(pattern);
        if(offset < 0)
        {
            throw new InvalidOperationException($"The '{elementIdentifier}' identifier is not immediately followed by its elementValue in the item.");
        }

        return (pattern, offset);
    }
}
