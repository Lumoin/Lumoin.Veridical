using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Diagnostics;

/// <summary>
/// Reports structural facts about a <see cref="G2Point"/>'s
/// canonical compressed encoding without performing curve arithmetic.
/// Same shape as <see cref="Bls12Curve381G1PointInspector"/>.
/// </summary>
public static class Bls12Curve381G2PointInspector
{
    private const byte CompressionFlagMask = 0x80;
    private const byte InfinityFlagMask = 0x40;
    private const byte YParityFlagMask = 0x20;


    /// <summary>Inspects <paramref name="point"/> and returns the bundled report.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="point"/> is <see langword="null"/>.</exception>
    public static G2PointInspectionReport Inspect(G2Point point)
    {
        ArgumentNullException.ThrowIfNull(point);

        ReadOnlySpan<byte> bytes = point.AsReadOnlySpan();
        byte flagByte = bytes[0];

        return new G2PointInspectionReport(
            ByteLength: bytes.Length,
            IsIdentity: point.IsIdentity,
            CompressionFlagSet: (flagByte & CompressionFlagMask) != 0,
            InfinityFlagSet: (flagByte & InfinityFlagMask) != 0,
            YParityFlagSet: (flagByte & YParityFlagMask) != 0,
            CanonicalHex: point.ToHexString());
    }
}


/// <summary>Bundled facts about a single <see cref="G2Point"/>.</summary>
public sealed record G2PointInspectionReport(
    int ByteLength,
    bool IsIdentity,
    bool CompressionFlagSet,
    bool InfinityFlagSet,
    bool YParityFlagSet,
    string CanonicalHex);