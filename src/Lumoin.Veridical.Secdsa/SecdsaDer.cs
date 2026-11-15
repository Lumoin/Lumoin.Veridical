using System;
using System.Formats.Asn1;
using System.Text;
using System.Text.Unicode;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The pieces of System.Formats.Asn1 that <see cref="SecdsaDerLayout"/> shares: a DER writer whose output is moved
/// into a <see cref="LayoutWriter"/>, and the field-level reads, done with the span-based
/// <see cref="AsnDecoder"/> under the distinguished encoding rules, that turn the decoder's exceptions into a plain
/// yes or no. No ASN.1 is encoded or parsed here by hand: lengths, minimal integers and the rejection of
/// indefinite and non-minimal forms are the platform's.
/// </summary>
internal static class SecdsaDer
{
    /// <summary>The encoding rules every structure uses.</summary>
    private const AsnEncodingRules Rules = AsnEncodingRules.DER;


    /// <summary>Creates a DER writer.</summary>
    /// <returns>The writer.</returns>
    internal static AsnWriter CreateWriter() => new(Rules);


    /// <summary>
    /// Moves the encoded bytes of <paramref name="asn"/> into <paramref name="target"/> and then resets the writer,
    /// which clears the buffer it encoded into, so a structure that carries a secret does not outlive the call in the
    /// writer's own buffer.
    /// </summary>
    /// <param name="asn">The writer holding one complete value.</param>
    /// <param name="target">The layout writer that receives the bytes.</param>
    internal static void Emit(AsnWriter asn, LayoutWriter target)
    {
        try
        {
            asn.Encode(target, static (destination, encoded) => destination.Append(encoded));
        }
        finally
        {
            asn.Reset();
        }
    }


    /// <summary>Reads a SEQUENCE.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="content">Receives the content of the SEQUENCE.</param>
    /// <returns><see langword="true"/> when the next element is a well-formed DER SEQUENCE.</returns>
    internal static bool TryReadSequence(scoped ref ReadOnlySpan<byte> rest, out ReadOnlySpan<byte> content)
    {
        content = default;
        try
        {
            AsnDecoder.ReadSequence(rest, Rules, out int offset, out int length, out int consumed);
            content = rest.Slice(offset, length);
            rest = rest[consumed..];

            return true;
        }
        catch(AsnContentException)
        {
            return false;
        }
    }


    /// <summary>Reads an OCTET STRING of any length.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="content">Receives the octets, which alias the input.</param>
    /// <returns><see langword="true"/> when the next element is a well-formed primitive OCTET STRING.</returns>
    internal static bool TryReadOctetString(scoped ref ReadOnlySpan<byte> rest, out ReadOnlySpan<byte> content)
    {
        content = default;
        try
        {
            if(!AsnDecoder.TryReadPrimitiveOctetString(rest, Rules, out ReadOnlySpan<byte> value, out int consumed))
            {
                return false;
            }

            content = value;
            rest = rest[consumed..];

            return true;
        }
        catch(AsnContentException)
        {
            return false;
        }
    }


    /// <summary>Reads an OCTET STRING of exactly the given length.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="size">The required length.</param>
    /// <param name="content">Receives the octets.</param>
    /// <returns><see langword="true"/> when the next element is an OCTET STRING of that length.</returns>
    internal static bool TryReadOctetString(scoped ref ReadOnlySpan<byte> rest, int size, out ReadOnlySpan<byte> content)
    {
        ReadOnlySpan<byte> cursor = rest;
        if(!TryReadOctetString(ref cursor, out content) || content.Length != size)
        {
            return false;
        }

        rest = cursor;

        return true;
    }


    /// <summary>Reads a non-negative INTEGER that fits 31 bits.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="value">Receives the value.</param>
    /// <returns><see langword="true"/> when the next element is such an INTEGER in the minimal form.</returns>
    internal static bool TryReadInteger(scoped ref ReadOnlySpan<byte> rest, out uint value)
    {
        value = 0;
        try
        {
            if(!AsnDecoder.TryReadInt32(rest, Rules, out int read, out int consumed) || read < 0)
            {
                return false;
            }

            value = (uint)read;
            rest = rest[consumed..];

            return true;
        }
        catch(AsnContentException)
        {
            return false;
        }
    }


    /// <summary>Reads a non-empty UTF8String within the bound.</summary>
    /// <param name="rest">The input; advanced past the element when the function returns <see langword="true"/>.</param>
    /// <param name="maxBytes">The largest accepted content length.</param>
    /// <param name="text">Receives the text.</param>
    /// <returns><see langword="true"/> when the next element is such a UTF8String holding valid UTF-8.</returns>
    internal static bool TryReadUtf8String(scoped ref ReadOnlySpan<byte> rest, int maxBytes, out string text)
    {
        text = string.Empty;
        try
        {
            if(!AsnDecoder.TryReadPrimitiveCharacterStringBytes(rest, Rules, new Asn1Tag(UniversalTagNumber.UTF8String), out ReadOnlySpan<byte> value, out int consumed)
                || value.IsEmpty
                || value.Length > maxBytes
                || !Utf8.IsValid(value))
            {
                return false;
            }

            text = Encoding.UTF8.GetString(value);
            rest = rest[consumed..];

            return true;
        }
        catch(AsnContentException)
        {
            return false;
        }
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

        return TryReadSequence(ref rest, out content) && rest.IsEmpty && TryReadInteger(ref content, out uint value) && value == discriminator;
    }
}
