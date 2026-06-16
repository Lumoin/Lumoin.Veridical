using System;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Converts a ZkInterface field element to Veridical's canonical
/// big-endian scalar layout. ZkInterface stores field elements
/// little-endian and may truncate them shorter than the field width
/// (the missing high bytes are zeros); a longer encoding is tolerated
/// only when its surplus high bytes are zero.
/// </summary>
internal static class ZkInterfaceScalar
{
    /// <summary>
    /// Writes <paramref name="littleEndian"/> as canonical big-endian into
    /// <paramref name="destination"/> (length = the scalar field width),
    /// zero-padding a shorter element and rejecting a longer one whose
    /// surplus high bytes are non-zero.
    /// </summary>
    public static void WriteCanonicalBigEndian(ReadOnlySpan<byte> littleEndian, Span<byte> destination)
    {
        destination.Clear();
        for(int p = 0; p < littleEndian.Length; p++)
        {
            byte value = littleEndian[p];
            if(p >= destination.Length)
            {
                if(value != 0)
                {
                    throw new ArgumentException(
                        $"ZkInterface field element is {littleEndian.Length} bytes with non-zero data beyond the {destination.Length}-byte scalar field.");
                }

                continue;
            }

            //Little-endian byte p maps to big-endian byte (width - 1 - p).
            destination[destination.Length - 1 - p] = value;
        }
    }
}
