using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// One attribute's opening witness — the SHA witnesses and offsets the hash circuit checks for the
/// disclosed element, a port of the per-attribute state in google/longfellow-zk's
/// <c>MdocHashWitness::compute_witness</c> (<c>lib/circuits/mdoc/mdoc_witness.h</c>, version 7).
/// </summary>
internal sealed class MdocAttributeWitness
{
    public required byte[] AttributeBytes { get; init; }

    public required MdocFlatSha256Witness.BlockWitness[] Blocks { get; init; }

    public required int MsoValuePos { get; init; }

    public required int IdentifierOffset { get; init; }

    public required int IdentifierLength { get; init; }

    public required int ValueOffset { get; init; }

    public required int ValueLength { get; init; }

    public required int SaltedI1 { get; init; }

    public required int SaltedI2 { get; init; }

    public required int SaltedI3 { get; init; }

    public required int SaltedL0 { get; init; }

    public required int SaltedL1 { get; init; }

    public required int SaltedL2 { get; init; }

    public required int SaltedL3 { get; init; }

    public required ulong SaltedPermutation { get; init; }
}


/// <summary>
/// The computed hash-witness state for the mdoc proof, a port of
/// <c>MdocHashWitness::compute_witness</c>: the SHA-256 preimage (the COSE1-prefixed tagged MSO), its 40
/// block witnesses and active-block count, the device-key coordinates, the issuer-auth hash <c>e</c>, and
/// the disclosed attribute's opening witness. <c>e</c>/<c>dpkx</c>/<c>dpky</c> are kept as 32 canonical
/// big-endian bytes (the values the MAC messages and the MAC-message bit strings consume).
/// </summary>
internal sealed class MdocHashWitnessState
{
    private const int MaxShaBlocks = 40;

    public required byte[] SignedBytes { get; init; }

    public required byte NumBlocks { get; init; }

    public required MdocFlatSha256Witness.BlockWitness[] MsoBlocks { get; init; }

    //The three MAC messages as to_bytes_field (little-endian) bytes: the reference's buf for the e/dpkx/dpky
    //bit strings and the compute_macs message halves.
    public required byte[] MacMessageE { get; init; }

    public required byte[] MacMessageDpkx { get; init; }

    public required byte[] MacMessageDpky { get; init; }

    public required MdocAttributeWitness AttributeWitness { get; init; }


    public static MdocHashWitnessState Compute(MdocParsedDocument parsed, MdocRequestedAttribute attribute)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        ArgumentNullException.ThrowIfNull(attribute);

        ReadOnlySpan<byte> document = parsed.Document;

        //Construct the SHA preimage: kCose1Prefix + 2-byte tagged-MSO length + the tagged MSO bytes.
        var preimage = new List<byte>();
        preimage.AddRange(MdocHashWitnessFiller.Cose1PrefixBytes.ToArray());
        preimage.Add((byte)((parsed.TaggedMsoLength >> 8) & 0xff));
        preimage.Add((byte)(parsed.TaggedMsoLength & 0xff));
        for(int i = 0; i < parsed.TaggedMsoLength; i++)
        {
            preimage.Add(document[parsed.TaggedMsoContentPos + i]);
        }

        (byte[] signedBytes, byte numBlocks, MdocFlatSha256Witness.BlockWitness[] msoBlocks) =
            MdocFlatSha256Witness.TransformAndWitnessMessage(preimage.ToArray(), MaxShaBlocks);

        //The three MAC messages are to_bytes_field(element), the LITTLE-endian bytes of the field element
        //(the reference's buf for fill_bit_string and compute_macs). e = nat_from_u32(h1) has the digest's
        //big-endian value, so its to_bytes_field is the digest reversed; dpkx/dpky = nat_from_be(coord) has
        //the coordinate's big-endian value, so their to_bytes_field is the coordinate reversed.
        byte[] macMessageE = ReverseBytes(WordsToBigEndian(msoBlocks[numBlocks - 1].H1));

        int msoBody = parsed.TaggedMsoContentPos + 5;
        byte[] macMessageDpkx = ReverseBytes(document.Slice(msoBody + parsed.DeviceKeyPkxPos, 32).ToArray());
        byte[] macMessageDpky = ReverseBytes(document.Slice(msoBody + parsed.DeviceKeyPkyPos, 32).ToArray());

        MdocAttributeWitness attributeWitness = ComputeAttributeWitness(parsed, attribute);

        return new MdocHashWitnessState
        {
            SignedBytes = signedBytes,
            NumBlocks = numBlocks,
            MsoBlocks = msoBlocks,
            MacMessageE = macMessageE,
            MacMessageDpkx = macMessageDpkx,
            MacMessageDpky = macMessageDpky,
            AttributeWitness = attributeWitness,
        };
    }


    private static MdocAttributeWitness ComputeAttributeWitness(MdocParsedDocument parsed, MdocRequestedAttribute attribute)
    {
        ReadOnlySpan<byte> document = parsed.Document;
        MdocFullAttribute fullAttribute = MatchAttribute(parsed, attribute);
        int msoValuePos = parsed.AttributeMsoValuePos[FindAttributeIndex(parsed, fullAttribute)];

        //The attribute's tagged bytes are hashed in exactly 2 SHA blocks.
        ReadOnlySpan<byte> taggedBytes = document.Slice(fullAttribute.TagHeaderPos, fullAttribute.TaggedLength);
        (byte[] attributeBytes, byte _, MdocFlatSha256Witness.BlockWitness[] blocks) =
            MdocFlatSha256Witness.TransformAndWitnessMessage(taggedBytes, 2);

        //attr_ei / attr_ev offsets (version 7).
        int tagInd = fullAttribute.TagHeaderPos;
        int identifierOffset = (fullAttribute.IdContentPos - tagInd) - (fullAttribute.IdLength < 24 ? 1 : 2) - (17 + 1);
        int identifierLength = 17 + 1 + fullAttribute.IdLength + (fullAttribute.IdLength < 24 ? 1 : 2);

        int valueOffset = fullAttribute.ValueKeyPos - tagInd - 1;
        int valueLength = attribute.CborValue.Length + 12 + 1;

        //The salted-hash layout: the four (offset, length, ord) triples sorted by offset then by the
        //original ordinal, exactly as the reference sorts and packs them.
        var triples = new List<(int Offset, int Length, int Ordinal)>
        {
            (fullAttribute.DigestKeyPos - tagInd - 1, fullAttribute.DigestLength, 0),
            (fullAttribute.RandomKeyPos - tagInd - 1, fullAttribute.RandomLength, 1),
            (identifierOffset, identifierLength, 2),
            (valueOffset, valueLength, 3),
        };

        triples.Sort((a, b) => a.Offset.CompareTo(b.Offset));

        int saltedL0 = triples[0].Length;
        int saltedI1 = triples[1].Offset;
        int saltedL1 = triples[1].Length;
        int saltedI2 = triples[2].Offset;
        int saltedL2 = triples[2].Length;
        int saltedI3 = triples[3].Offset;
        int saltedL3 = triples[3].Length;

        //Record the sorted-by-offset position of each original ordinal, then sort by original ordinal to
        //read the permutation (perm[2*slot..] is the offset-sorted index of the original slot).
        var ordered = new List<(int Position, int Ordinal)>
        {
            (0, triples[0].Ordinal),
            (1, triples[1].Ordinal),
            (2, triples[2].Ordinal),
            (3, triples[3].Ordinal),
        };

        ordered.Sort((a, b) => a.Ordinal.CompareTo(b.Ordinal));

        ulong permutation = (uint)ordered[0].Position
            | ((uint)ordered[1].Position << 2)
            | ((uint)ordered[2].Position << 4)
            | ((uint)ordered[3].Position << 6);

        return new MdocAttributeWitness
        {
            AttributeBytes = attributeBytes,
            Blocks = blocks,
            MsoValuePos = msoValuePos,
            IdentifierOffset = identifierOffset,
            IdentifierLength = identifierLength,
            ValueOffset = valueOffset,
            ValueLength = valueLength,
            SaltedI1 = saltedI1,
            SaltedI2 = saltedI2,
            SaltedI3 = saltedI3,
            SaltedL0 = saltedL0,
            SaltedL1 = saltedL1,
            SaltedL2 = saltedL2,
            SaltedL3 = saltedL3,
            SaltedPermutation = permutation,
        };
    }


    private static MdocFullAttribute MatchAttribute(MdocParsedDocument parsed, MdocRequestedAttribute attribute)
    {
        ReadOnlySpan<byte> document = parsed.Document;
        foreach(MdocFullAttribute candidate in parsed.Attributes)
        {
            if(candidate.IdLength == attribute.Id.Length
                && document.Slice(candidate.IdContentPos, candidate.IdLength).SequenceEqual(attribute.Id))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("The requested attribute is not present in the document.");
    }


    private static int FindAttributeIndex(MdocParsedDocument parsed, MdocFullAttribute attribute)
    {
        for(int i = 0; i < parsed.Attributes.Count; i++)
        {
            if(ReferenceEquals(parsed.Attributes[i], attribute))
            {
                return i;
            }
        }

        return 0;
    }


    //The 8 SHA H1 words as 32 big-endian bytes (the natural digest order).
    private static byte[] WordsToBigEndian(uint[] words)
    {
        byte[] bigEndian = new byte[32];
        for(int i = 0; i < 8; i++)
        {
            bigEndian[i * 4] = (byte)(words[i] >> 24);
            bigEndian[i * 4 + 1] = (byte)(words[i] >> 16);
            bigEndian[i * 4 + 2] = (byte)(words[i] >> 8);
            bigEndian[i * 4 + 3] = (byte)words[i];
        }

        return bigEndian;
    }


    private static byte[] ReverseBytes(byte[] bytes)
    {
        byte[] reversed = new byte[bytes.Length];
        for(int i = 0; i < bytes.Length; i++)
        {
            reversed[i] = bytes[bytes.Length - 1 - i];
        }

        return reversed;
    }
}
