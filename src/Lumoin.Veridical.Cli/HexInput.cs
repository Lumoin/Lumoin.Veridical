using System;
using System.Buffers;
using System.Globalization;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// Hex decoding for the command-line subcommands and MCP tools. An optional <c>0x</c> prefix and
/// surrounding whitespace are accepted; every failure names the input it came from.
/// </summary>
internal static class HexInput
{
    private const string Prefix = "0x";

    private const int CharactersPerByte = 2;


    /// <summary>Decodes a hex string of any even length, including the empty string.</summary>
    /// <param name="hex">The hex text.</param>
    /// <param name="name">What the input is, for the error message.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="ArgumentException">The text is not valid hex.</exception>
    public static byte[] Decode(string hex, string name)
    {
        ArgumentNullException.ThrowIfNull(hex);
        ArgumentNullException.ThrowIfNull(name);

        try
        {
            return Convert.FromHexString(Strip(hex));
        }
        catch(FormatException)
        {
            throw new ArgumentException($"The {name} is not a valid hex string (even length, 0-9a-f).", name);
        }
    }


    /// <summary>Decodes a hex string into a buffer of exactly the destination's length.</summary>
    /// <param name="hex">The hex text.</param>
    /// <param name="destination">Receives the decoded bytes; sized by the caller, who clears it when it holds a secret.</param>
    /// <param name="name">What the input is, for the error message.</param>
    /// <exception cref="ArgumentException">The text is not valid hex of exactly the destination's length.</exception>
    public static void DecodeExact(string hex, Span<byte> destination, string name)
    {
        ArgumentNullException.ThrowIfNull(hex);
        ArgumentNullException.ThrowIfNull(name);

        ReadOnlySpan<char> text = Strip(hex);
        if(text.Length != destination.Length * CharactersPerByte
            || Convert.FromHexString(text, destination, out _, out int written) != OperationStatus.Done
            || written != destination.Length)
        {
            throw new ArgumentException($"The {name} is not a valid hex string of {destination.Length.ToString(CultureInfo.InvariantCulture)} bytes.", name);
        }
    }


    private static ReadOnlySpan<char> Strip(string hex)
    {
        ReadOnlySpan<char> text = hex.AsSpan().Trim();
        if(text.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            text = text[Prefix.Length..];
        }

        return text;
    }
}
