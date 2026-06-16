using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// A verifier-supplied attribute claim, the test mirror of google/longfellow-zk's
/// <c>RequestedAttribute</c> (<c>lib/circuits/mdoc/mdoc_zk.h</c>): the namespace, the element identifier
/// and the raw CBOR-encoded value the proof must bind to.
/// </summary>
internal sealed record MdocRequestedAttribute(byte[] NamespaceId, byte[] Id, byte[] CborValue)
{
    public static MdocRequestedAttribute AgeOver18 { get; } = new(
        System.Text.Encoding.ASCII.GetBytes("org.iso.18013.5.1"),
        System.Text.Encoding.ASCII.GetBytes("age_over_18"),
        [0xf5]);
}


/// <summary>
/// One parsed attribute from the DeviceResponse — the byte offsets the reference's <c>FullAttribute</c>
/// records (all relative to the raw document).
/// </summary>
internal sealed record MdocFullAttribute(
    int IdContentPos,
    int IdLength,
    int ValueKeyPos,
    int ValueLength,
    int DigestKeyPos,
    int DigestLength,
    int RandomKeyPos,
    int RandomLength,
    long DigestId,
    int TagHeaderPos,
    int TaggedLength);


/// <summary>
/// The parsed DeviceResponse offsets the GF(2^128) hash witness needs, a faithful port of the parsing in
/// google/longfellow-zk's <c>ParsedMdoc::parse_device_response</c> (<c>lib/circuits/mdoc/mdoc_witness.h</c>):
/// the tagged MSO byte range, the device-key coordinate offsets, the four validity/key/digest CBOR key
/// positions (relative to the MSO body after the 5-byte tag), and the per-attribute offsets.
/// </summary>
internal sealed class MdocParsedDocument
{
    //The 5-byte tag (D8 18 59 <len2>) the reference skips to reach the MSO body.
    private const int MsoTagSkip = 5;

    public required byte[] Document { get; init; }

    public required int TaggedMsoContentPos { get; init; }

    public required int TaggedMsoLength { get; init; }

    public required int SignaturePos { get; init; }

    public required int DeviceKeyPkxPos { get; init; }

    public required int DeviceKeyPkyPos { get; init; }

    public required int ValidFromKeyPos { get; init; }

    public required int ValidUntilKeyPos { get; init; }

    public required int DeviceKeyInfoKeyPos { get; init; }

    public required int ValueDigestsKeyPos { get; init; }

    public required IReadOnlyList<MdocFullAttribute> Attributes { get; init; }

    public required IReadOnlyList<int> AttributeMsoValuePos { get; init; }


    public static MdocParsedDocument Parse(byte[] document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var walker = new MdocCborWalker(document);
        MdocCborItem root = walker.Decode(0);

        MdocCborItem documents = RequireLookup(root, "documents");
        MdocCborItem firstDocument = documents.ArrayRef(0);

        MdocCborItem issuerSigned = RequireLookup(firstDocument, "issuerSigned");
        MdocCborItem issuerAuth = RequireLookup(issuerSigned, "issuerAuth");

        //issuerAuth is the COSE_Sign1 array [protected, unprotected, payload(tagged mso), signature].
        MdocCborItem taggedMso = issuerAuth.ArrayRef(2);
        MdocCborItem signature = issuerAuth.ArrayRef(3);

        var attributes = new List<MdocFullAttribute>();
        MdocCborItem nameSpaces = RequireLookup(issuerSigned, "nameSpaces");
        if(nameSpaces.TryLookup("org.iso.18013.5.1", out _, out MdocCborItem isoNamespace)
            || nameSpaces.TryLookup("eu.europa.ec.av.1", out _, out isoNamespace))
        {
            ParseAttributes(walker, isoNamespace, attributes);
        }

        //The MSO body begins at the tagged-MSO content position plus the 5-byte tag skip; it lives in the
        //same document, so decode it with the same walker (the reference decodes from resp + tmso.pos + 5,
        //and all MSO offsets the witness consumes are then taken relative to that base).
        int msoBody = taggedMso.Position + MsoTagSkip;
        MdocCborItem mso = walker.Decode(msoBody);

        MdocCborItem validityInfo = RequireLookup(mso, "validityInfo");
        MdocCborItem validFromKey = RequireLookup(validityInfo, "validFrom", out _);
        MdocCborItem validUntilKey = RequireLookup(validityInfo, "validUntil", out _);

        MdocCborItem deviceKeyInfoKey = RequireLookup(mso, "deviceKeyInfo", out MdocCborItem deviceKeyInfo);
        MdocCborItem deviceKey = RequireLookup(deviceKeyInfo, "deviceKey");

        if(!deviceKey.TryLookupNegative(-1, out _, out MdocCborItem pkx))
        {
            throw new FormatException("The device key has no -1 (x) coordinate.");
        }

        if(!deviceKey.TryLookupNegative(-2, out _, out MdocCborItem pky))
        {
            throw new FormatException("The device key has no -2 (y) coordinate.");
        }

        MdocCborItem valueDigestsKey = RequireLookup(mso, "valueDigests", out MdocCborItem valueDigests);

        //attr_mso: the digest-id keyed entry's value header position inside valueDigests[namespace].
        var attributeMsoValuePos = new List<int>();
        foreach(MdocFullAttribute attribute in attributes)
        {
            int valuePos = LookupAttributeMso(valueDigests, attribute, msoBody);
            attributeMsoValuePos.Add(valuePos);
        }

        //All MSO-relative positions are header positions minus the MSO body base.
        return new MdocParsedDocument
        {
            Document = document,
            TaggedMsoContentPos = taggedMso.Position,
            TaggedMsoLength = taggedMso.Length,
            SignaturePos = signature.Position,
            DeviceKeyPkxPos = pkx.Position - msoBody,
            DeviceKeyPkyPos = pky.Position - msoBody,
            ValidFromKeyPos = validFromKey.HeaderPos - msoBody,
            ValidUntilKeyPos = validUntilKey.HeaderPos - msoBody,
            DeviceKeyInfoKeyPos = deviceKeyInfoKey.HeaderPos - msoBody,
            ValueDigestsKeyPos = valueDigestsKey.HeaderPos - msoBody,
            Attributes = attributes,
            AttributeMsoValuePos = attributeMsoValuePos,
        };
    }


    private static void ParseAttributes(MdocCborWalker walker, MdocCborItem namespaceArray, List<MdocFullAttribute> attributes)
    {
        int count = (int)namespaceArray.Argument;
        for(int ai = 0; ai < count; ai++)
        {
            MdocCborItem tagged = namespaceArray.ArrayRef(ai);
            MdocCborItem taggedValue = tagged.TaggedValue();

            //The tagged value is a byte string; the IssuerSignedItem map begins at its content position in
            //the same document, so decode it with the same walker.
            MdocCborItem inner = walker.Decode(taggedValue.Position);

            _ = RequireLookup(inner, "elementIdentifier", out MdocCborItem elementIdentifier);
            MdocCborItem elementValueKey = RequireLookup(inner, "elementValue", out MdocCborItem elementValue);
            MdocCborItem digestIdKey = RequireLookup(inner, "digestID", out MdocCborItem digestId);
            MdocCborItem randomKey = RequireLookup(inner, "random", out MdocCborItem randomValue);

            //rand_len = rand.key->length() (content) + rand.val->length() (content) + 1 + (val<24 ? 1 : 2).
            int randomValueLength = randomValue.Length;
            int randLen = randomKey.Length + randomValueLength + 1 + (randomValueLength < 24 ? 1 : 2);

            //dig_len = digid.key->length() (content) + digid.val->length() (the unsigned width) + 1.
            int digestLength = digestIdKey.Length + UnsignedValueLength(digestId.Unsigned) + 1;

            //The attribute offsets use the reference's position() (content position) for the element
            //identifier value and for the elementValue / digestID / random key texts.
            attributes.Add(new MdocFullAttribute(
                IdContentPos: elementIdentifier.Position,
                IdLength: elementIdentifier.Length,
                ValueKeyPos: elementValueKey.Position,
                ValueLength: elementValue.Length,
                DigestKeyPos: digestIdKey.Position,
                DigestLength: digestLength,
                RandomKeyPos: randomKey.Position,
                RandomLength: randLen,
                DigestId: (long)digestId.Unsigned,
                TagHeaderPos: tagged.HeaderPos,
                TaggedLength: taggedValue.Length + 4));
        }
    }


    //The reference's CborDoc::length() for an UNSIGNED value: the encoded byte width of the value (1 for
    //values below 24, 2 below 256, 3 below 65536, otherwise 5).
    private static int UnsignedValueLength(ulong value)
    {
        if(value < 24)
        {
            return 1;
        }

        if(value < 256)
        {
            return 2;
        }

        if(value < 65536)
        {
            return 3;
        }

        return 5;
    }


    private static int LookupAttributeMso(MdocCborItem valueDigests, MdocFullAttribute attribute, int msoBody)
    {
        //valueDigests is a map keyed by namespace; the inner map is keyed by digestID (unsigned).
        foreach(string namespaceName in new[] { "org.iso.18013.5.1", "eu.europa.ec.av.1" })
        {
            if(valueDigests.TryLookup(namespaceName, out _, out MdocCborItem digestMap))
            {
                if(digestMap.TryLookupUnsigned((ulong)attribute.DigestId, out _, out MdocCborItem digestValue))
                {
                    return digestValue.HeaderPos - msoBody;
                }
            }
        }

        throw new FormatException("The valueDigests has no entry for the attribute digest id.");
    }


    private static MdocCborItem RequireLookup(MdocCborItem map, string key)
    {
        if(!map.TryLookup(key, out _, out MdocCborItem value))
        {
            throw new FormatException($"The map has no '{key}' entry.");
        }

        return value;
    }


    private static MdocCborItem RequireLookup(MdocCborItem map, string key, out MdocCborItem value)
    {
        if(!map.TryLookup(key, out MdocCborItem keyItem, out value))
        {
            throw new FormatException($"The map has no '{key}' entry.");
        }

        return keyItem;
    }
}
