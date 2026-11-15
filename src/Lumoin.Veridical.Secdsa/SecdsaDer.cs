using System;
using System.Buffers.Binary;
using System.Text;
using System.Text.Unicode;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The handful of ASN.1 DER constructs (ITU-T X.690, section 10 for the distinguished encoding rules) that
/// <see cref="SecdsaDerLayout"/> uses: SEQUENCE, OCTET STRING, UTF8String and non-negative INTEGER, each with a
/// definite, minimal length. Writing needs the content size before the header, so every structure first sums the
/// sizes of its elements with the size functions here and then appends header and elements to the
/// <see cref="LayoutWriter"/>. Reading is strict: a wrong tag, an indefinite length, a non-minimal length or integer,
/// a length beyond the input and a negative integer are all reported by the return value.
/// </summary>
internal static class SecdsaDer
{
    /// <summary>The universal tag of INTEGER.</summary>
    internal const byte IntegerTag = 0x02;

    /// <summary>The universal tag of OCTET STRING.</summary>
    internal const byte OctetStringTag = 0x04;

    /// <summary>The universal tag of UTF8String.</summary>
    internal const byte Utf8StringTag = 0x0C;

    /// <summary>The universal tag of SEQUENCE, constructed.</summary>
    internal const byte SequenceTag = 0x30;

    /// <summary>The largest length the short form carries; longer lengths use the long form.</summary>
    private const int ShortFormLimit = 0x80;

    /// <summary>The bits in one octet.</summary>
    private const int BitsPerOctet = 8;

    /// <summary>The most significant bit of an octet, which marks a negative two's-complement integer.</summary>
    private const byte SignBit = 0x80;

    /// <summary>The marker bit of the first length octet of the long form.</summary>
    private const byte LongFormFlag = 0x80;

    /// <summary>The most length octets the reader accepts; four reach beyond the largest layout structure.</summary>
    private const int MaxLengthOctets = 4;

    /// <summary>The width of the buffer an unsigned 32-bit integer is expanded into: a sign octet and four value octets.</summary>
    private const int IntegerBufferBytes = sizeof(uint) + 1;


    /// <summary>Returns the number of octets the length field of <paramref name="length"/> takes.</summary>
    /// <param name="length">The content length, not negative.</param>
    /// <returns>The size of the length field.</returns>
    internal static int LengthOctets(int length)
    {
        if(length < ShortFormLimit)
        {
            return 1;
        }

        int count = 1;
        for(uint remaining = (uint)length; remaining != 0; remaining >>= BitsPerOctet)
        {
            count++;
        }

        return count;
    }


    /// <summary>Returns the size of an element with the given content length: tag, length field and content.</summary>
    /// <param name="contentLength">The content length, not negative.</param>
    /// <returns>The encoded size.</returns>
    internal static int ElementSize(int contentLength) => 1 + LengthOctets(contentLength) + contentLength;


    /// <summary>Returns the encoded size of a non-negative INTEGER.</summary>
    /// <param name="value">The value.</param>
    /// <returns>The encoded size.</returns>
    internal static int IntegerSize(uint value)
    {
        Span<byte> buffer = stackalloc byte[IntegerBufferBytes];

        return ElementSize(IntegerContent(value, buffer).Length);
    }


    /// <summary>Appends a tag and a definite length in the minimal form.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="tag">The tag octet.</param>
    /// <param name="length">The content length, not negative.</param>
    internal static void WriteHeader(LayoutWriter writer, byte tag, int length)
    {
        writer.AppendByte(tag);
        if(length < ShortFormLimit)
        {
            writer.AppendByte((byte)length);

            return;
        }

        int octets = LengthOctets(length) - 1;
        writer.AppendByte((byte)(LongFormFlag | octets));
        for(int shift = (octets - 1) * BitsPerOctet; shift >= 0; shift -= BitsPerOctet)
        {
            writer.AppendByte((byte)(length >> shift));
        }
    }


    /// <summary>Appends an OCTET STRING.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="content">The octets.</param>
    internal static void WriteOctetString(LayoutWriter writer, ReadOnlySpan<byte> content)
    {
        WriteHeader(writer, OctetStringTag, content.Length);
        writer.Append(content);
    }


    /// <summary>Appends a non-negative INTEGER in its minimal two's-complement form.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="value">The value.</param>
    internal static void WriteInteger(LayoutWriter writer, uint value)
    {
        Span<byte> buffer = stackalloc byte[IntegerBufferBytes];
        ReadOnlySpan<byte> content = IntegerContent(value, buffer);
        WriteHeader(writer, IntegerTag, content.Length);
        writer.Append(content);
    }


    /// <summary>Appends a UTF8String from a value already encoded as UTF-8.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="utf8">The UTF-8 octets.</param>
    internal static void WriteUtf8String(LayoutWriter writer, ReadOnlySpan<byte> utf8)
    {
        WriteHeader(writer, Utf8StringTag, utf8.Length);
        writer.Append(utf8);
    }


    /// <summary>Reads one element with the given tag, requiring a minimal definite length that lies within the input.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="tag">The required tag octet.</param>
    /// <param name="content">Receives the content octets.</param>
    /// <returns><see langword="true"/> when the element is well formed.</returns>
    internal static bool TryReadElement(scoped ref ReadOnlySpan<byte> rest, byte tag, out ReadOnlySpan<byte> content)
    {
        content = default;
        if(rest.Length < 2 || rest[0] != tag)
        {
            return false;
        }

        int first = rest[1];
        int headerLength = 2;
        long length = first;
        if(first >= ShortFormLimit)
        {
            //A count of zero is the indefinite form, which DER forbids; the minimal form rules out a leading zero octet and a value that fits the short form.
            int octets = first & ~LongFormFlag;
            if(octets == 0 || octets > MaxLengthOctets || rest.Length < headerLength + octets || rest[headerLength] == 0)
            {
                return false;
            }

            length = 0;
            for(int index = 0; index < octets; index++)
            {
                length = (length << BitsPerOctet) | rest[headerLength + index];
            }

            if(length < ShortFormLimit)
            {
                return false;
            }

            headerLength += octets;
        }

        if(length > rest.Length - headerLength)
        {
            return false;
        }

        content = rest.Slice(headerLength, (int)length);
        rest = rest[(headerLength + (int)length)..];

        return true;
    }


    /// <summary>Reads an OCTET STRING of any length.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="content">Receives the octets.</param>
    /// <returns><see langword="true"/> when the element is a well-formed OCTET STRING.</returns>
    internal static bool TryReadOctetString(ref ReadOnlySpan<byte> rest, out ReadOnlySpan<byte> content) => TryReadElement(ref rest, OctetStringTag, out content);


    /// <summary>Reads an OCTET STRING of exactly the given length.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="size">The required length.</param>
    /// <param name="content">Receives the octets.</param>
    /// <returns><see langword="true"/> when the element is a well-formed OCTET STRING of that length.</returns>
    internal static bool TryReadOctetString(ref ReadOnlySpan<byte> rest, int size, out ReadOnlySpan<byte> content)
    {
        return TryReadElement(ref rest, OctetStringTag, out content) && content.Length == size;
    }


    /// <summary>Reads a non-negative INTEGER in its minimal form that fits 31 bits.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="value">Receives the value.</param>
    /// <returns><see langword="true"/> when the element is a minimal, non-negative INTEGER no larger than <see cref="int.MaxValue"/>.</returns>
    internal static bool TryReadInteger(ref ReadOnlySpan<byte> rest, out uint value)
    {
        value = 0;
        if(!TryReadElement(ref rest, IntegerTag, out ReadOnlySpan<byte> content)
            || content.IsEmpty
            || content.Length > IntegerBufferBytes
            || (content[0] & SignBit) != 0
            || (content.Length > 1 && content[0] == 0 && (content[1] & SignBit) == 0))
        {
            return false;
        }

        ulong accumulated = 0;
        foreach(byte octet in content)
        {
            accumulated = (accumulated << BitsPerOctet) | octet;
        }

        if(accumulated > int.MaxValue)
        {
            return false;
        }

        value = (uint)accumulated;

        return true;
    }


    /// <summary>Reads a UTF8String that is valid UTF-8 and returns its text.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="maxBytes">The largest accepted content length.</param>
    /// <param name="text">Receives the text.</param>
    /// <returns><see langword="true"/> when the element is a non-empty, valid UTF8String within the bound.</returns>
    internal static bool TryReadUtf8String(ref ReadOnlySpan<byte> rest, int maxBytes, out string text)
    {
        text = string.Empty;
        if(!TryReadElement(ref rest, Utf8StringTag, out ReadOnlySpan<byte> content)
            || content.IsEmpty
            || content.Length > maxBytes
            || !Utf8.IsValid(content))
        {
            return false;
        }

        text = Encoding.UTF8.GetString(content);

        return true;
    }


    /// <summary>Reads the structure discriminator: an INTEGER that must equal the expected value.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="expected">The expected discriminator.</param>
    /// <returns><see langword="true"/> when the next element is that INTEGER.</returns>
    internal static bool TryReadDiscriminator(ref ReadOnlySpan<byte> rest, uint expected)
    {
        return TryReadInteger(ref rest, out uint value) && value == expected;
    }


    /// <summary>
    /// Opens a discriminated structure: reads the outer SEQUENCE, requires that it spans the whole input, and reads
    /// the leading discriminator.
    /// </summary>
    /// <param name="encoded">The whole encoding.</param>
    /// <param name="discriminator">The expected discriminator.</param>
    /// <param name="content">Receives the content after the discriminator.</param>
    /// <returns><see langword="true"/> when the encoding is one SEQUENCE that starts with the discriminator.</returns>
    internal static bool TryOpenStructure(ReadOnlySpan<byte> encoded, uint discriminator, out ReadOnlySpan<byte> content)
    {
        ReadOnlySpan<byte> rest = encoded;

        return TryReadElement(ref rest, SequenceTag, out content) && rest.IsEmpty && TryReadDiscriminator(ref content, discriminator);
    }


    /// <summary>Expands a value into the minimal two's-complement content octets of a non-negative INTEGER.</summary>
    private static ReadOnlySpan<byte> IntegerContent(uint value, Span<byte> buffer)
    {
        buffer[0] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(buffer[1..], value);
        int start = 0;
        while(start < IntegerBufferBytes - 1 && buffer[start] == 0 && (buffer[start + 1] & SignBit) == 0)
        {
            start++;
        }

        return buffer[start..];
    }
}
