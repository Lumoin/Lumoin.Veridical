using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Reports structural facts about a <see cref="G1Point"/>'s
/// canonical compressed encoding without performing curve arithmetic.
/// </summary>
/// <remarks>
/// <para>
/// The inspector is a pure read-only verb: it observes the point through
/// the public read-only span and returns a single
/// <see cref="G1PointInspectionReport"/>. No backend delegates are called,
/// so neither curve arithmetic nor square-root computation runs. Use this
/// when something is wrong and the question is "what do the bytes actually
/// look like?" rather than "is this point algebraically valid?". The
/// latter question is answered by the backend-driven
/// <c>IsOnCurve</c> / <c>IsInPrimeOrderSubgroup</c> extension members on
/// <see cref="G1Point"/>.
/// </para>
/// <para>
/// The three flag bits in the most-significant byte are reported
/// individually because their combinations carry distinct meaning per
/// RFC 9380 Appendix M.5.3.1 (compression flag + infinity flag + y-parity
/// flag), and a malformed encoding typically has the wrong combination.
/// Surfacing each flag separately turns "byte 0 looked wrong" into
/// "compression flag was clear, which is non-conformant".
/// </para>
/// </remarks>
public static class Bls12Curve381G1PointInspector
{
    private const byte CompressionFlagMask = 0x80;
    private const byte InfinityFlagMask = 0x40;
    private const byte YParityFlagMask = 0x20;


    /// <summary>
    /// Inspects <paramref name="point"/> and returns the bundled report.
    /// </summary>
    /// <param name="point">The point to inspect.</param>
    /// <returns>The inspection report.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="point"/> is <see langword="null"/>.</exception>
    public static G1PointInspectionReport Inspect(G1Point point)
    {
        ArgumentNullException.ThrowIfNull(point);

        ReadOnlySpan<byte> bytes = point.AsReadOnlySpan();
        byte flagByte = bytes[0];

        return new G1PointInspectionReport(
            ByteLength: bytes.Length,
            IsIdentity: point.IsIdentity,
            CompressionFlagSet: (flagByte & CompressionFlagMask) != 0,
            InfinityFlagSet: (flagByte & InfinityFlagMask) != 0,
            YParityFlagSet: (flagByte & YParityFlagMask) != 0,
            CanonicalHex: point.ToHexString());
    }
}


/// <summary>
/// Bundled facts about a single <see cref="G1Point"/>.
/// </summary>
/// <param name="ByteLength">Length in bytes of the canonical compressed encoding. Always <see cref="WellKnownCurves.Bls12Curve381G1CompressedSizeBytes"/> for well-formed inputs; reported for explicit safety.</param>
/// <param name="IsIdentity">True when the point is the additive identity, derived from the infinity flag bit in the most-significant byte.</param>
/// <param name="CompressionFlagSet">True when the compression flag bit (<c>0x80</c>) is set. Always true for canonical compressed encodings; a false result is a strong signal of a non-conformant or uncompressed input.</param>
/// <param name="InfinityFlagSet">True when the infinity flag bit (<c>0x40</c>) is set. Indicates the point at infinity.</param>
/// <param name="YParityFlagSet">True when the y-parity flag bit (<c>0x20</c>) is set. Selects between the two square-root candidates of <c>y^2 = x^3 + 4 (mod p)</c>; meaningless when the infinity flag is set.</param>
/// <param name="CanonicalHex">Lowercase hexadecimal rendering of the canonical compressed bytes.</param>
public sealed record G1PointInspectionReport(
    int ByteLength,
    bool IsIdentity,
    bool CompressionFlagSet,
    bool InfinityFlagSet,
    bool YParityFlagSet,
    string CanonicalHex);