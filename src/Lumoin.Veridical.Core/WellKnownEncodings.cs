namespace Lumoin.Veridical.Core;

/// <summary>
/// Canonical encoding choices that apply across the entire library.
/// </summary>
/// <remarks>
/// <para>
/// The library stores scalars and field elements in big-endian byte order. Every
/// wire format the library serialises to — IETF specifications, JOSE, COSE,
/// multibase did:key encodings, the IETF BBS+ draft, the BLS signature draft —
/// uses big-endian, so the JSON and CBOR serialisation layers do zero conversion
/// when crossing the wire boundary.
/// </para>
/// <para>
/// Native cryptographic libraries such as blst and arkworks use little-endian
/// limb arrays internally for performance reasons that derive from x86 and ARM
/// native word order. A native backend that wraps such a library converts at
/// the FFI boundary. The conversion is one span reverse on a 32-, 48-, or
/// 96-byte buffer, far cheaper than the field operation it surrounds, and it
/// is paid once in the place that knows it is the optimisation point.
/// </para>
/// <para>
/// This choice is named here once and never revisited.
/// </para>
/// </remarks>
public static class WellKnownEncodings
{
    /// <summary>
    /// The canonical byte order for scalar values in the library.
    /// </summary>
    public const ByteOrder CanonicalScalarLayout = ByteOrder.BigEndian;

    /// <summary>
    /// The canonical byte order for base-field and extension-field elements in the library.
    /// </summary>
    public const ByteOrder CanonicalFieldElementLayout = ByteOrder.BigEndian;

    /// <summary>
    /// The canonical byte order for fixed-width integer values that appear
    /// alongside cryptographic material (counters, indices, lengths).
    /// </summary>
    public const ByteOrder CanonicalIntegerLayout = ByteOrder.BigEndian;
}