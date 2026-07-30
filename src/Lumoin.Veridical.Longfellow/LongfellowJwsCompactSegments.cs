namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The segment layout of one compact-serialization JWS (<c>header.payload.signature</c>) inside
/// the byte span it was parsed from: each segment as a start index and byte length. Purely
/// structural — no segment content is validated beyond the acceptance
/// <see cref="LongfellowJwsCompact.TryParse"/> documents.
/// </summary>
/// <param name="HeaderIndex">The header segment's start index; always zero in a well-formed parse.</param>
/// <param name="HeaderLength">The header segment's byte length.</param>
/// <param name="PayloadIndex">The payload segment's start index.</param>
/// <param name="PayloadLength">The payload segment's byte length.</param>
/// <param name="SignatureIndex">The signature segment's start index.</param>
/// <param name="SignatureLength">The signature segment's byte length.</param>
public readonly record struct LongfellowJwsCompactSegments(
    int HeaderIndex,
    int HeaderLength,
    int PayloadIndex,
    int PayloadLength,
    int SignatureIndex,
    int SignatureLength)
{
    /// <summary>The signing input's byte length: the <c>header.payload</c> prefix a JWS signature covers, from the start of the JWS up to the second dot.</summary>
    public int SigningInputLength => PayloadIndex + PayloadLength;
}
