using System;
using System.Buffers.Binary;
using System.Text;
using System.Text.Unicode;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The handful of CBOR constructs (RFC 8949) that <see cref="SecdsaCborLayout"/> uses, written in the core
/// deterministic encoding of section 4.2: unsigned integers, byte strings, text strings and arrays, every head in its
/// shortest form and every length definite. Reading is strict: a head that is not the shortest form of its value,
/// an indefinite length, a reserved additional-information value, a wrong major type and a length beyond the input
/// are all reported by the return value. Values of 2^32 and above never occur in these structures, so the eight-byte
/// head is rejected on reading rather than parsed.
/// </summary>
internal static class SecdsaCbor
{
    /// <summary>The major type of an unsigned integer.</summary>
    internal const byte UnsignedMajor = 0;

    /// <summary>The major type of a byte string.</summary>
    internal const byte ByteStringMajor = 2;

    /// <summary>The major type of a text string.</summary>
    internal const byte TextStringMajor = 3;

    /// <summary>The major type of an array.</summary>
    internal const byte ArrayMajor = 4;

    /// <summary>The bit position of the major type within the initial byte.</summary>
    private const int MajorShift = 5;

    /// <summary>The mask of the additional-information bits of the initial byte.</summary>
    private const byte AdditionalInfoMask = 0x1F;

    /// <summary>The largest value carried directly in the additional-information bits.</summary>
    private const int DirectLimit = 23;

    /// <summary>The additional-information value that announces a one-byte argument.</summary>
    private const byte OneByteInfo = 24;

    /// <summary>The additional-information value that announces a two-byte argument.</summary>
    private const byte TwoByteInfo = 25;

    /// <summary>The additional-information value that announces a four-byte argument.</summary>
    private const byte FourByteInfo = 26;

    /// <summary>The smallest value whose shortest head has a one-byte argument.</summary>
    private const uint OneByteMinimum = DirectLimit + 1;

    /// <summary>The smallest value whose shortest head has a two-byte argument.</summary>
    private const uint TwoByteMinimum = byte.MaxValue + 1;

    /// <summary>The smallest value whose shortest head has a four-byte argument.</summary>
    private const uint FourByteMinimum = ushort.MaxValue + 1;


    /// <summary>Returns the size of the head that carries <paramref name="value"/> in its shortest form.</summary>
    /// <param name="value">The argument.</param>
    /// <returns>The head size in bytes.</returns>
    internal static int HeadSize(uint value)
    {
        if(value <= DirectLimit)
        {
            return 1;
        }

        if(value <= byte.MaxValue)
        {
            return 2;
        }

        return value <= ushort.MaxValue ? 3 : 5;
    }


    /// <summary>Appends a head: the major type and the argument in the shortest form.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="major">The major type.</param>
    /// <param name="value">The argument.</param>
    internal static void WriteHead(LayoutWriter writer, byte major, uint value)
    {
        byte initial = (byte)(major << MajorShift);
        if(value <= DirectLimit)
        {
            writer.AppendByte((byte)(initial | value));
        }
        else if(value <= byte.MaxValue)
        {
            writer.AppendByte((byte)(initial | OneByteInfo));
            writer.AppendByte((byte)value);
        }
        else if(value <= ushort.MaxValue)
        {
            writer.AppendByte((byte)(initial | TwoByteInfo));
            writer.AppendUInt16BigEndian((ushort)value);
        }
        else
        {
            writer.AppendByte((byte)(initial | FourByteInfo));
            writer.AppendUInt32BigEndian(value);
        }
    }


    /// <summary>Appends an unsigned integer.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="value">The value.</param>
    internal static void WriteUnsigned(LayoutWriter writer, uint value) => WriteHead(writer, UnsignedMajor, value);


    /// <summary>Appends a byte string.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="content">The bytes.</param>
    internal static void WriteByteString(LayoutWriter writer, ReadOnlySpan<byte> content)
    {
        WriteHead(writer, ByteStringMajor, (uint)content.Length);
        writer.Append(content);
    }


    /// <summary>Appends a text string from a value already encoded as UTF-8.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="utf8">The UTF-8 bytes.</param>
    internal static void WriteTextString(LayoutWriter writer, ReadOnlySpan<byte> utf8)
    {
        WriteHead(writer, TextStringMajor, (uint)utf8.Length);
        writer.Append(utf8);
    }


    /// <summary>Appends the head of a definite-length array.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="count">The number of elements that follow.</param>
    internal static void WriteArrayHead(LayoutWriter writer, int count) => WriteHead(writer, ArrayMajor, (uint)count);


    /// <summary>Reads a head of the given major type, requiring the shortest form and a definite length.</summary>
    /// <param name="rest">The input; advanced past the head when the function returns <see langword="true"/>.</param>
    /// <param name="major">The required major type.</param>
    /// <param name="value">Receives the argument.</param>
    /// <returns><see langword="true"/> when the head is well formed, in its shortest form and of the required major type.</returns>
    internal static bool TryReadHead(ref ReadOnlySpan<byte> rest, byte major, out uint value)
    {
        value = 0;
        if(rest.IsEmpty || rest[0] >> MajorShift != major)
        {
            return false;
        }

        byte info = (byte)(rest[0] & AdditionalInfoMask);
        int size;
        if(info <= DirectLimit)
        {
            value = info;
            size = 1;
        }
        else if(info == OneByteInfo && rest.Length >= 2 && rest[1] >= OneByteMinimum)
        {
            value = rest[1];
            size = 2;
        }
        else if(info == TwoByteInfo && rest.Length >= 3 && BinaryPrimitives.ReadUInt16BigEndian(rest[1..]) >= TwoByteMinimum)
        {
            value = BinaryPrimitives.ReadUInt16BigEndian(rest[1..]);
            size = 3;
        }
        else if(info == FourByteInfo && rest.Length >= 5 && BinaryPrimitives.ReadUInt32BigEndian(rest[1..]) >= FourByteMinimum)
        {
            value = BinaryPrimitives.ReadUInt32BigEndian(rest[1..]);
            size = 5;
        }
        else
        {
            //Non-shortest heads, the eight-byte head, the reserved values and the indefinite length all end here.
            return false;
        }

        rest = rest[size..];

        return true;
    }


    /// <summary>Reads an unsigned integer in its shortest form that fits 31 bits.</summary>
    /// <param name="rest">The input; advanced past the integer when the function returns <see langword="true"/>.</param>
    /// <param name="value">Receives the value.</param>
    /// <returns><see langword="true"/> when the item is such an unsigned integer.</returns>
    internal static bool TryReadUnsigned(ref ReadOnlySpan<byte> rest, out uint value)
    {
        return TryReadHead(ref rest, UnsignedMajor, out value) && value <= int.MaxValue;
    }


    /// <summary>Reads a byte string of any length.</summary>
    /// <param name="rest">The input; advanced past the item when the function returns <see langword="true"/>.</param>
    /// <param name="content">Receives the bytes.</param>
    /// <returns><see langword="true"/> when the item is a well-formed byte string.</returns>
    internal static bool TryReadByteString(ref ReadOnlySpan<byte> rest, out ReadOnlySpan<byte> content)
    {
        content = default;
        ReadOnlySpan<byte> cursor = rest;
        if(!TryReadHead(ref cursor, ByteStringMajor, out uint length) || length > (uint)cursor.Length)
        {
            return false;
        }

        content = cursor[..(int)length];
        rest = cursor[(int)length..];

        return true;
    }


    /// <summary>Reads a byte string of exactly the given length.</summary>
    /// <param name="rest">The input; advanced past the item when the function returns <see langword="true"/>.</param>
    /// <param name="size">The required length.</param>
    /// <param name="content">Receives the bytes.</param>
    /// <returns><see langword="true"/> when the item is a well-formed byte string of that length.</returns>
    internal static bool TryReadByteString(ref ReadOnlySpan<byte> rest, int size, out ReadOnlySpan<byte> content)
    {
        return TryReadByteString(ref rest, out content) && content.Length == size;
    }


    /// <summary>Reads a text string that is valid UTF-8 and returns its text.</summary>
    /// <param name="rest">The input; advanced past the item when the function returns <see langword="true"/>.</param>
    /// <param name="maxBytes">The largest accepted length in bytes.</param>
    /// <param name="text">Receives the text.</param>
    /// <returns><see langword="true"/> when the item is a non-empty, valid text string within the bound.</returns>
    internal static bool TryReadTextString(ref ReadOnlySpan<byte> rest, int maxBytes, out string text)
    {
        text = string.Empty;
        ReadOnlySpan<byte> cursor = rest;
        if(!TryReadHead(ref cursor, TextStringMajor, out uint length)
            || length == 0
            || length > maxBytes
            || length > (uint)cursor.Length
            || !Utf8.IsValid(cursor[..(int)length]))
        {
            return false;
        }

        text = Encoding.UTF8.GetString(cursor[..(int)length]);
        rest = cursor[(int)length..];

        return true;
    }


    /// <summary>
    /// Opens a discriminated structure: reads the array head, requires the element count, and reads the leading
    /// discriminator.
    /// </summary>
    /// <param name="rest">The input; advanced past the discriminator when the function returns <see langword="true"/>.</param>
    /// <param name="count">The number of array elements, discriminator included.</param>
    /// <param name="discriminator">The expected discriminator.</param>
    /// <returns><see langword="true"/> when the input starts with such an array.</returns>
    internal static bool TryOpenStructure(ref ReadOnlySpan<byte> rest, int count, uint discriminator)
    {
        return TryReadHead(ref rest, ArrayMajor, out uint elements)
            && elements == (uint)count
            && TryReadUnsigned(ref rest, out uint value)
            && value == discriminator;
    }
}
