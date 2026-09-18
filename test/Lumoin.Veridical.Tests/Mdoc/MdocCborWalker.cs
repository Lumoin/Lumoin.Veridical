using System;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// A byte-offset-tracking CBOR walker over a raw ISO 18013-5 DeviceResponse, a faithful port of the
/// offset semantics of google/longfellow-zk's <c>CborDoc</c> (<c>lib/cbor/host_decoder.h</c>) that the
/// reference witness filler (<c>ParsedMdoc</c> in <c>lib/circuits/mdoc/mdoc_witness.h</c>) relies on.
/// Where <see cref="Lumoin.Veritas.Cbor.CborReader"/> hides absolute offsets, this walker keeps the exact
/// header byte position, content position and content length of every item, because the GF(2^128)
/// hash-circuit witness column is built from those raw byte indices (the cbor-index region and the
/// attribute shift/salted-hash witnesses are positions into the document).
/// </summary>
/// <remarks>
/// The mdoc CBOR is always definite-length; only the major types the credential uses are handled. An item
/// is described by <see cref="MdocCborItem"/>: <c>HeaderPos</c> is the reference's <c>header_pos()</c>,
/// <c>Position</c>/<c>Length</c> are the content offset and length the reference's <c>position()</c> /
/// <c>length()</c> return for strings and byte strings.
/// </remarks>
internal sealed class MdocCborWalker
{
    /// <summary>The CBOR major type for an unsigned integer (RFC 8949 §3.1, major type 0).</summary>
    private const int MajorUnsigned = 0;

    /// <summary>The CBOR major type for a negative integer (RFC 8949 §3.1, major type 1).</summary>
    private const int MajorNegative = 1;

    /// <summary>The CBOR major type for a byte string (RFC 8949 §3.1, major type 2).</summary>
    private const int MajorByteString = 2;

    /// <summary>The CBOR major type for a UTF-8 text string (RFC 8949 §3.1, major type 3).</summary>
    private const int MajorTextString = 3;

    /// <summary>The CBOR major type for an array (RFC 8949 §3.1, major type 4).</summary>
    private const int MajorArray = 4;

    /// <summary>The CBOR major type for a map (RFC 8949 §3.1, major type 5).</summary>
    private const int MajorMap = 5;

    /// <summary>The CBOR major type for a tagged value (RFC 8949 §3.1, major type 6).</summary>
    private const int MajorTag = 6;

    /// <summary>The CBOR major type for a primitive/simple/float value (RFC 8949 §3.1, major type 7).</summary>
    private const int MajorPrimitive = 7;

    /// <summary>The raw ISO 18013-5 DeviceResponse bytes this walker decodes offsets into.</summary>
    private byte[] DocumentBytes { get; }

    /// <summary>Wraps <paramref name="document"/> for offset-tracking decoding.</summary>
    public MdocCborWalker(byte[] document)
    {
        ArgumentNullException.ThrowIfNull(document);
        this.DocumentBytes = document;
    }

    /// <summary>The wrapped document bytes, as a read-only span.</summary>
    public ReadOnlySpan<byte> Document => DocumentBytes;


    /// <summary>Decodes the item whose header begins at <paramref name="headerPos"/>.</summary>
    public MdocCborItem Decode(int headerPos)
    {
        int p = headerPos;
        (int major, ulong argument, int afterHeader) = ReadHeader(p);

        return major switch
        {
            MajorUnsigned or MajorNegative or MajorPrimitive => new MdocCborItem(this, major, argument, headerPos, afterHeader, 0, afterHeader),
            MajorByteString or MajorTextString => new MdocCborItem(this, major, argument, headerPos, afterHeader, (int)argument, afterHeader + (int)argument),
            MajorArray or MajorMap => new MdocCborItem(this, major, argument, headerPos, afterHeader, 0, SkipContainerContents(major, (int)argument, afterHeader)),
            MajorTag => DecodeTag(headerPos, argument, afterHeader),
            _ => throw new FormatException($"Unsupported CBOR major type {major}."),
        };
    }


    /// <summary>The end offset (one past the last byte) of the item whose header begins at <paramref name="headerPos"/>.</summary>
    public int SkipFrom(int headerPos) => Decode(headerPos).EndPos;


    /// <summary>Reads a definite-length CBOR head at <paramref name="p"/>: returns the major type, the integer argument, and the offset after the head bytes.</summary>
    private (int Major, ulong Argument, int AfterHeader) ReadHeader(int p)
    {
        byte initial = DocumentBytes[p];
        int major = initial >> 5;
        int additional = initial & 0x1f;
        p++;

        ulong argument;
        if(additional < 24)
        {
            argument = (ulong)additional;
        }
        else if(additional == 24)
        {
            argument = DocumentBytes[p];
            p += 1;
        }
        else if(additional == 25)
        {
            argument = (ulong)((DocumentBytes[p] << 8) | DocumentBytes[p + 1]);
            p += 2;
        }
        else if(additional == 26)
        {
            argument = ((ulong)DocumentBytes[p] << 24) | ((ulong)DocumentBytes[p + 1] << 16) | ((ulong)DocumentBytes[p + 2] << 8) | DocumentBytes[p + 3];
            p += 4;
        }
        else if(additional == 27)
        {
            argument = 0;
            for(int i = 0; i < 8; i++)
            {
                argument = (argument << 8) | DocumentBytes[p + i];
            }

            p += 8;
        }
        else
        {
            throw new FormatException($"Unsupported CBOR additional-information value {additional}.");
        }

        return (major, argument, p);
    }


    /// <summary>Decodes a tag item at <paramref name="headerPos"/> whose head is already known, then decodes its tagged content item to compute the tag's end offset.</summary>
    private MdocCborItem DecodeTag(int headerPos, ulong tag, int afterHeader)
    {
        MdocCborItem inner = Decode(afterHeader);

        return new MdocCborItem(this, MajorTag, tag, headerPos, afterHeader, 0, inner.EndPos);
    }


    /// <summary>Skips over an array's or map's contents (a map's pairs counted twice) starting at <paramref name="afterHeader"/>, returning the offset one past the last element.</summary>
    private int SkipContainerContents(int major, int count, int afterHeader)
    {
        int p = afterHeader;
        int pairs = major == MajorMap ? count * 2 : count;
        for(int i = 0; i < pairs; i++)
        {
            p = SkipFrom(p);
        }

        return p;
    }
}


/// <summary>
/// A decoded CBOR item with the exact byte offsets the reference witness filler consumes.
/// </summary>
internal readonly struct MdocCborItem
{
    /// <summary>The CBOR major type for a UTF-8 text string (RFC 8949 §3.1, major type 3).</summary>
    private const int MajorTextString = 3;

    /// <summary>The CBOR major type for an array (RFC 8949 §3.1, major type 4).</summary>
    private const int MajorArray = 4;

    /// <summary>The CBOR major type for a map (RFC 8949 §3.1, major type 5).</summary>
    private const int MajorMap = 5;

    /// <summary>The CBOR major type for a tagged value (RFC 8949 §3.1, major type 6).</summary>
    private const int MajorTag = 6;

    /// <summary>The CBOR major type for an unsigned integer (RFC 8949 §3.1, major type 0).</summary>
    private const int MajorUnsigned = 0;

    /// <summary>The walker this item was decoded from, backing <see cref="TaggedValue"/>, <see cref="ArrayRef"/> and the map lookups.</summary>
    private MdocCborWalker Walker { get; }

    /// <summary>Wraps one decoded CBOR item's shape and byte offsets.</summary>
    public MdocCborItem(MdocCborWalker walker, int major, ulong argument, int headerPos, int contentPos, int length, int endPos)
    {
        this.Walker = walker;
        Major = major;
        Argument = argument;
        HeaderPos = headerPos;
        Position = contentPos;
        Length = length;
        EndPos = endPos;
    }

    /// <summary>The CBOR major type.</summary>
    public int Major { get; }

    /// <summary>The integer argument (string length, unsigned value, array/map count, tag value).</summary>
    public ulong Argument { get; }

    /// <summary>The reference's <c>header_pos()</c>: the byte offset of this item's header byte.</summary>
    public int HeaderPos { get; }

    /// <summary>The reference's <c>position()</c>: for strings, the content offset (after the header).</summary>
    public int Position { get; }

    /// <summary>The reference's <c>length()</c>: for strings, the content length in bytes.</summary>
    public int Length { get; }

    /// <summary>The offset one past this item's last byte.</summary>
    public int EndPos { get; }


    /// <summary>The value of an unsigned item.</summary>
    public ulong Unsigned => Argument;


    /// <summary>The value of the tag content item.</summary>
    public MdocCborItem TaggedValue()
    {
        if(Major != MajorTag)
        {
            throw new InvalidOperationException("The item is not a tag.");
        }

        //The tag head occupies HeaderPos..Position; the tagged value's header starts at Position.
        return Walker.Decode(Position);
    }


    /// <summary>The element at index <paramref name="index"/> of an array.</summary>
    public MdocCborItem ArrayRef(int index)
    {
        if(Major != MajorArray)
        {
            throw new InvalidOperationException("The item is not an array.");
        }

        int p = Position;
        for(int i = 0; i < index; i++)
        {
            p = Walker.SkipFrom(p);
        }

        return Walker.Decode(p);
    }


    /// <summary>Looks up a text key in a map, returning the (key item, value item) pair, or false if absent.</summary>
    public bool TryLookup(string key, out MdocCborItem keyItem, out MdocCborItem valueItem)
    {
        if(Major != MajorMap)
        {
            throw new InvalidOperationException("The item is not a map.");
        }

        int p = Position;
        int count = (int)Argument;
        ReadOnlySpan<byte> document = Walker.Document;
        for(int i = 0; i < count; i++)
        {
            MdocCborItem candidateKey = Walker.Decode(p);
            int valuePos = candidateKey.EndPos;
            if(candidateKey.Major == MajorTextString && candidateKey.Length == key.Length && Matches(document.Slice(candidateKey.Position, candidateKey.Length), key))
            {
                keyItem = candidateKey;
                valueItem = Walker.Decode(valuePos);

                return true;
            }

            p = Walker.SkipFrom(valuePos);
        }

        keyItem = default;
        valueItem = default;

        return false;
    }


    /// <summary>Looks up an unsigned integer key in a map (the digest-id keyed valueDigests entries).</summary>
    public bool TryLookupUnsigned(ulong key, out MdocCborItem keyItem, out MdocCborItem valueItem)
    {
        if(Major != MajorMap)
        {
            throw new InvalidOperationException("The item is not a map.");
        }

        int p = Position;
        int count = (int)Argument;
        for(int i = 0; i < count; i++)
        {
            MdocCborItem candidateKey = Walker.Decode(p);
            int valuePos = candidateKey.EndPos;
            if(candidateKey.Major == MajorUnsigned && candidateKey.Argument == key)
            {
                keyItem = candidateKey;
                valueItem = Walker.Decode(valuePos);

                return true;
            }

            p = Walker.SkipFrom(valuePos);
        }

        keyItem = default;
        valueItem = default;

        return false;
    }


    /// <summary>Looks up a negative-integer key (the device key's -1 / -2 coordinate entries).</summary>
    public bool TryLookupNegative(long key, out MdocCborItem keyItem, out MdocCborItem valueItem)
    {
        if(Major != MajorMap)
        {
            throw new InvalidOperationException("The item is not a map.");
        }

        //The reference's host_decoder stores a negative key as i64 = -argument (an off-by-one from the
        //standard CBOR value -1-argument), and lookup_negative matches that i64. To match i64 == key the
        //argument must therefore be -key.
        ulong encodedArgument = (ulong)(-key);
        int p = Position;
        int count = (int)Argument;
        for(int i = 0; i < count; i++)
        {
            MdocCborItem candidateKey = Walker.Decode(p);
            int valuePos = candidateKey.EndPos;
            if(candidateKey.Major == 1 && candidateKey.Argument == encodedArgument)
            {
                keyItem = candidateKey;
                valueItem = Walker.Decode(valuePos);

                return true;
            }

            p = Walker.SkipFrom(valuePos);
        }

        keyItem = default;
        valueItem = default;

        return false;
    }


    /// <summary>Reports whether <paramref name="bytes"/> equals the ASCII encoding of <paramref name="ascii"/>, byte for byte.</summary>
    private static bool Matches(ReadOnlySpan<byte> bytes, string ascii)
    {
        for(int i = 0; i < ascii.Length; i++)
        {
            if(bytes[i] != (byte)ascii[i])
            {
                return false;
            }
        }

        return true;
    }
}
