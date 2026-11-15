using Lumoin.Veritas.Cbor;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The pieces of Lumoin.Veritas.Cbor that <see cref="SecdsaCborLayout"/> shares: the conformance options, a writer
/// that emits into a <see cref="LayoutWriter"/>, a reader over pooled memory, and the field-level reads that turn the
/// reader's exceptions and its leniencies into a plain yes or no. No CBOR is encoded or parsed here by hand.
/// </summary>
internal static class SecdsaCbor
{
    /// <summary>
    /// The conformance options: the core deterministic encoding of RFC 8949 section 4.2, which has the writer emit
    /// shortest-form heads and definite lengths and has the reader refuse anything else.
    /// </summary>
    private static CborSerializerOptions Options { get; } = CborSerializerOptions.Default(CborConformanceMode.Cde);


    /// <summary>Creates a CBOR writer that emits into <paramref name="target"/>.</summary>
    /// <param name="target">The layout writer.</param>
    /// <returns>The writer.</returns>
    internal static CborWriter CreateWriter(LayoutWriter target) => new(new LayoutBufferWriter(target), Options);


    /// <summary>Copies the encoded bytes into pooled memory that a reader can be built over.</summary>
    /// <param name="encoded">The encoding.</param>
    /// <param name="pool">The pool to rent from.</param>
    /// <returns>The owner of the copy, which clears it when disposed.</returns>
    internal static IMemoryOwner<byte> Rent(ReadOnlySpan<byte> encoded, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(encoded.Length, 1));
        encoded.CopyTo(owner.Memory.Span);

        return owner;
    }


    /// <summary>Creates a reader over <paramref name="encoded"/> under the deterministic conformance options.</summary>
    /// <param name="encoded">The encoding, kept alive by the caller while the reader is used.</param>
    /// <returns>The reader.</returns>
    internal static CborReader CreateReader(ReadOnlyMemory<byte> encoded) => new(encoded, Options);


    /// <summary>Opens a discriminated structure: an array of the given length that starts with the given discriminator.</summary>
    /// <param name="reader">The reader.</param>
    /// <param name="count">The number of array elements, discriminator included.</param>
    /// <param name="discriminator">The expected discriminator.</param>
    /// <returns><see langword="true"/> when the next item is such an array.</returns>
    internal static bool TryOpenStructure(CborReader reader, int count, uint discriminator)
    {
        return reader.PeekState() == CborReaderState.StartArray
            && reader.ReadStartArray() == count
            && TryReadUnsigned(reader, out uint value)
            && value == discriminator;
    }


    /// <summary>Closes the structure and requires that nothing follows it.</summary>
    /// <param name="reader">The reader.</param>
    /// <param name="length">The length of the whole encoding.</param>
    /// <returns><see langword="true"/> when the array ends here and the encoding is fully consumed.</returns>
    internal static bool TryCloseStructure(CborReader reader, int length)
    {
        reader.ReadEndArray();

        return reader.BytesConsumed == length;
    }


    /// <summary>Reads an unsigned integer that fits 31 bits.</summary>
    /// <param name="reader">The reader.</param>
    /// <param name="value">Receives the value.</param>
    /// <returns><see langword="true"/> when the next item is such an unsigned integer.</returns>
    internal static bool TryReadUnsigned(CborReader reader, out uint value)
    {
        value = 0;
        if(reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            return false;
        }

        ulong read = reader.ReadUInt64();
        if(read > int.MaxValue)
        {
            return false;
        }

        value = (uint)read;

        return true;
    }


    /// <summary>Reads a byte string of any length.</summary>
    /// <param name="reader">The reader.</param>
    /// <param name="content">Receives the bytes, which alias the memory the reader was built over.</param>
    /// <returns><see langword="true"/> when the next item is a definite-length byte string.</returns>
    internal static bool TryReadByteString(CborReader reader, out ReadOnlySpan<byte> content)
    {
        content = default;
        if(reader.PeekState() != CborReaderState.ByteString)
        {
            return false;
        }

        content = reader.ReadByteStringSpan();

        return true;
    }


    /// <summary>Reads a byte string of exactly the given length.</summary>
    /// <param name="reader">The reader.</param>
    /// <param name="size">The required length.</param>
    /// <param name="content">Receives the bytes.</param>
    /// <returns><see langword="true"/> when the next item is a byte string of that length.</returns>
    internal static bool TryReadByteString(CborReader reader, int size, out ReadOnlySpan<byte> content)
    {
        return TryReadByteString(reader, out content) && content.Length == size;
    }


    /// <summary>Reads a non-empty text string within the bound.</summary>
    /// <param name="reader">The reader.</param>
    /// <param name="maxBytes">The largest accepted length in UTF-8 bytes.</param>
    /// <param name="text">Receives the text.</param>
    /// <returns><see langword="true"/> when the next item is such a text string.</returns>
    internal static bool TryReadTextString(CborReader reader, int maxBytes, out string text)
    {
        text = string.Empty;
        if(reader.PeekState() != CborReaderState.TextString)
        {
            return false;
        }

        string read = reader.ReadTextString();
        if(read.Length == 0 || read.Length > maxBytes || System.Text.Encoding.UTF8.GetByteCount(read) > maxBytes)
        {
            return false;
        }

        text = read;

        return true;
    }


    /// <summary>Reads the head of a vector array and requires a non-empty count that the remaining input can hold.</summary>
    /// <param name="reader">The reader.</param>
    /// <param name="maxCount">The most elements the remaining input could hold, which bounds the allocation a hostile head can cause.</param>
    /// <param name="count">Receives the element count.</param>
    /// <returns><see langword="true"/> when the next item is an array of between one and <paramref name="maxCount"/> elements.</returns>
    internal static bool TryReadVectorHead(CborReader reader, int maxCount, out int count)
    {
        count = 0;
        if(reader.PeekState() != CborReaderState.StartArray)
        {
            return false;
        }

        int length = reader.ReadStartArray() ?? 0;
        if(length < 1 || length > maxCount)
        {
            return false;
        }

        count = length;

        return true;
    }


    /// <summary>
    /// Tells whether an exception is the reader reporting malformed or non-conforming input, which a decoder
    /// answers with <see langword="false"/>, as opposed to a defect that must propagate.
    /// </summary>
    /// <param name="exception">The exception.</param>
    /// <returns><see langword="true"/> when the exception describes bad input.</returns>
    internal static bool IsMalformation(Exception exception) => exception is InvalidOperationException or FormatException;
}
