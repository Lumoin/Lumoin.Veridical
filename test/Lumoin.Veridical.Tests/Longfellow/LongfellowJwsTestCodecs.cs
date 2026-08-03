using Lumoin.Veridical.Longfellow;
using System;
using System.Buffers;
using System.Buffers.Text;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// The consumer-wired base64url codec exemplars the extractor tests inject: the same
/// <see cref="Base64Url"/>-backed shapes the sibling Verifiable stack's test setup wires, so one
/// implementation demonstrably satisfies both libraries' delegate seams. The decoder rents from
/// the passed pool, right-sizes the result, and rejects any character outside the unpadded
/// base64url alphabet — a literal <c>=</c> included, matching the JWS convention the statement's
/// reference documents.
/// </summary>
internal static class LongfellowJwsTestCodecs
{
    /// <summary>Encodes binary data to its unpadded base64url string form.</summary>
    public static LongfellowBase64UrlEncodeDelegate Encoder { get; } = data => Base64Url.EncodeToString(data);

    /// <summary>Decodes unpadded base64url characters into a right-sized pool-rented buffer the caller disposes.</summary>
    public static LongfellowBase64UrlDecodeDelegate Decoder { get; } = (source, pool) =>
    {
        if(source.Length == 0)
        {
            throw new ArgumentException("Encoded input cannot be empty.", nameof(source));
        }

        //The unpadded convention treats a literal '=' as an invalid character; the pre-check makes
        //that rejection independent of the platform decoder's padding tolerance.
        if(source.IndexOf('=') >= 0)
        {
            throw new FormatException("A padding character is invalid in unpadded base64url.");
        }

        int maxDecodedLength = Base64Url.GetMaxDecodedLength(source.Length);
        IMemoryOwner<byte> buffer = pool.Rent(maxDecodedLength);
        if(!Base64Url.TryDecodeFromChars(source, buffer.Memory.Span, out int bytesWritten))
        {
            buffer.Dispose();

            throw new FormatException("Base64Url decoding failed.");
        }

        if(bytesWritten < maxDecodedLength)
        {
            IMemoryOwner<byte> rightSized = pool.Rent(bytesWritten);
            buffer.Memory.Span[..bytesWritten].CopyTo(rightSized.Memory.Span);
            buffer.Dispose();

            return rightSized;
        }

        return buffer;
    };
}
