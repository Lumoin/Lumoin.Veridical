namespace Lumoin.Veridical.Core;

/// <summary>
/// The byte order used to lay out a multi-byte numeric value in memory or on the wire.
/// </summary>
public enum ByteOrder
{
    /// <summary>
    /// Most significant byte first. Matches IETF wire formats, JOSE, COSE, and the
    /// canonical layout used throughout this library.
    /// </summary>
    BigEndian,

    /// <summary>
    /// Least significant byte first. Matches the in-memory layout of most native
    /// cryptographic libraries and the natural word order on x86 and ARM.
    /// </summary>
    LittleEndian
}