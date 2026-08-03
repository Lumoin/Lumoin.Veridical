using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The host-side compact-serialization JWS extractor: structural parsing of
/// <c>header.payload.signature</c> and of the restricted <c>issuerJws~keyBindingJws</c>
/// presentation shape, the verifier-side key-binding digest computation, and segment decoding
/// through the consumer-wired base64url seam. Compact serialization is the whole scope; JSON
/// serialization (single- or multi-signature) and SD-JWT disclosure segments are not processed.
/// </summary>
/// <remarks>
/// <para>
/// The parsing acceptance mirrors the reference's host-side <c>parse_jws</c>: a JWS splits at
/// its first two dots and the signature is the remainder, so empty header or payload segments
/// parse structurally and fail later at the cryptographic checks, exactly as the reference
/// accepts them. The presentation split takes the FIRST tilde, the reference's own rule; a token
/// carrying SD-JWT disclosure segments between tildes is outside the restricted format this
/// statement proves and is not recombined here.
/// </para>
/// <para>
/// Segment content is ASCII by construction in compact serialization, so
/// <see cref="DecodeSegment"/> rejects any byte above <c>0x7F</c> before the consumer-wired
/// decoder runs, making that rejection independent of the wired implementation.
/// </para>
/// </remarks>
public static class LongfellowJwsCompact
{
    /// <summary>The smallest raw ECDSA signature the statement's curve accepts: the fixed-width <c>r ‖ s</c> pair of two 32-byte scalars.</summary>
    public const int MinimumSignatureBytes = 2 * Scalar.SizeBytes;

    //The P-256 base-field prime as a canonical big-endian scalar; the key-binding digest is
    //reduced once below it, matching the witness generator's own reduction of the same value.
    private static byte[] CanonicalBasePrime { get; } = BuildCanonicalBasePrime();


    /// <summary>
    /// Splits one compact-serialization JWS into its segment layout. Structural only: the
    /// acceptance is the reference's — two dots and a non-empty signature remainder.
    /// </summary>
    /// <param name="jws">The JWS bytes.</param>
    /// <param name="segments">Receives the segment layout.</param>
    /// <returns>Whether the JWS parsed.</returns>
    public static bool TryParse(ReadOnlySpan<byte> jws, out LongfellowJwsCompactSegments segments)
    {
        segments = default;

        int firstDot = jws.IndexOf((byte)'.');
        if(firstDot < 0)
        {
            return false;
        }

        int secondDotOffset = jws[(firstDot + 1)..].IndexOf((byte)'.');
        if(secondDotOffset < 0)
        {
            return false;
        }

        int secondDot = firstDot + 1 + secondDotOffset;
        int signatureIndex = secondDot + 1;
        int signatureLength = jws.Length - signatureIndex;
        if(signatureLength <= 0)
        {
            return false;
        }

        segments = new LongfellowJwsCompactSegments(
            HeaderIndex: 0,
            HeaderLength: firstDot,
            PayloadIndex: firstDot + 1,
            PayloadLength: secondDot - firstDot - 1,
            SignatureIndex: signatureIndex,
            SignatureLength: signatureLength);

        return true;
    }


    /// <summary>
    /// Splits the restricted presentation shape <c>issuerJws~keyBindingJws</c> at its FIRST
    /// tilde, the reference's own rule. A missing tilde or an empty key-binding remainder fails,
    /// matching the reference's split and its missing-key-binding rejection.
    /// </summary>
    /// <param name="token">The presentation token bytes.</param>
    /// <param name="issuerJws">Receives the issuer JWS range.</param>
    /// <param name="keyBindingJws">Receives the key-binding JWS range.</param>
    /// <returns>Whether the token split.</returns>
    public static bool TrySplitPresentation(ReadOnlySpan<byte> token, out Range issuerJws, out Range keyBindingJws)
    {
        issuerJws = default;
        keyBindingJws = default;

        int tilde = token.IndexOf((byte)'~');
        if(tilde < 0 || tilde + 1 >= token.Length)
        {
            return false;
        }

        issuerJws = ..tilde;
        keyBindingJws = (tilde + 1)..token.Length;

        return true;
    }


    /// <summary>
    /// Computes the strict unpadded base64url decoded byte length of a character count, without
    /// decoding: a remainder of one character cannot carry data and is invalid. Deliberately
    /// stricter than the reference's zero-padding host decoder on such malformed lengths.
    /// </summary>
    /// <param name="characterCount">The encoded character count.</param>
    /// <returns>The decoded byte length, or <c>-1</c> when the length is not a valid unpadded base64url length.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="characterCount"/> is negative.</exception>
    public static int StrictDecodedLength(int characterCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(characterCount);

        int remainderBytes = (characterCount & 3) switch
        {
            1 => -1,
            2 => 1,
            3 => 2,
            _ => 0
        };

        return remainderBytes < 0 ? -1 : (characterCount / 4 * 3) + remainderBytes;
    }


    /// <summary>
    /// Computes the key-binding digest <c>e2</c> the verifier supplies as a public input: SHA-256
    /// over the presented key-binding JWS's signing input (<c>header.payload</c>), reduced once
    /// below the P-256 base-field prime — the same reduction the witness generator applies, so
    /// the prover's and the verifier's <c>e2</c> agree byte for byte for the same presentation.
    /// </summary>
    /// <param name="keyBindingJws">The presented key-binding JWS bytes.</param>
    /// <param name="digest">Receives the canonical big-endian digest scalar; exactly <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <returns>Whether the key-binding JWS parsed and the digest was written.</returns>
    /// <exception cref="ArgumentException">When <paramref name="digest"/> is not exactly <see cref="Scalar.SizeBytes"/> bytes.</exception>
    public static bool TryComputeKeyBindingDigest(ReadOnlySpan<byte> keyBindingJws, Span<byte> digest)
    {
        if(digest.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"The digest destination is exactly {Scalar.SizeBytes} bytes.", nameof(digest));
        }

        if(!TryParse(keyBindingJws, out LongfellowJwsCompactSegments segments))
        {
            return false;
        }

        Span<byte> raw = stackalloc byte[Scalar.SizeBytes];
        SHA256.HashData(keyBindingJws[..segments.SigningInputLength], raw);
        LongfellowJwtWitness.ReduceOnce(raw, CanonicalBasePrime, digest);
        raw.Clear();

        return true;
    }


    /// <summary>
    /// Decodes one JWS segment through the consumer-wired base64url seam, bridging the ASCII
    /// segment bytes to the decoder's character span through a pool-rented buffer that is cleared
    /// after the call — segment content can carry claim data and rides the pooling discipline.
    /// </summary>
    /// <param name="segment">The segment bytes to decode.</param>
    /// <param name="decode">The consumer-wired base64url decoder.</param>
    /// <param name="pool">The pool the transcoding buffer and the decoded result rent from.</param>
    /// <returns>The decoded bytes; the caller disposes the owner.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="decode"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="segment"/> is empty.</exception>
    /// <exception cref="FormatException">When the segment holds a byte above <c>0x7F</c>, or when the wired decoder rejects the segment's characters.</exception>
    public static IMemoryOwner<byte> DecodeSegment(ReadOnlySpan<byte> segment, LongfellowBase64UrlDecodeDelegate decode, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(decode);
        ArgumentNullException.ThrowIfNull(pool);

        if(segment.IsEmpty)
        {
            throw new ArgumentException("A JWS segment is never empty.", nameof(segment));
        }

        if(segment.ContainsAnyExceptInRange((byte)0x00, (byte)0x7F))
        {
            throw new FormatException("A compact-serialization segment is ASCII; a byte above 0x7F is malformed.");
        }

        int transcodeBytes = 2 * segment.Length;
        using IMemoryOwner<byte> transcodeOwner = pool.Rent(transcodeBytes);
        Span<byte> transcodeSpan = transcodeOwner.Memory.Span[..transcodeBytes];
        Span<char> characters = MemoryMarshal.Cast<byte, char>(transcodeSpan);
        for(int i = 0; i < segment.Length; i++)
        {
            characters[i] = (char)segment[i];
        }

        try
        {
            return decode(characters, pool);
        }
        finally
        {
            transcodeSpan.Clear();
        }
    }


    //The P-256 base-field prime is exactly 32 big-endian bytes, so the minimal unsigned write
    //fills the canonical scalar completely.
    private static byte[] BuildCanonicalBasePrime()
    {
        byte[] canonical = new byte[Scalar.SizeBytes];
        _ = P256BigIntegerG1Reference.BaseFieldPrime.TryWriteBytes(canonical, out _, isUnsigned: true, isBigEndian: true);

        return canonical;
    }
}
