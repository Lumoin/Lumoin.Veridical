namespace Lumoin.Veridical.Tests.IetfVectors;

/// <summary>
/// A single RFC 9380 Appendix J.9.1 hash-to-curve test vector
/// for the suite <c>BLS12381G1_XMD:SHA-256_SSWU_RO_</c>. Tests
/// decode the hex via <see cref="System.Convert.FromHexString(string)"/>
/// at consumption time so the byte arrays land in pool-rented
/// buffers inside the operation under test.
/// </summary>
/// <param name="Id">A short identifier for the vector (the upstream RFC tag).</param>
/// <param name="Description">Human-readable summary of the input shape.</param>
/// <param name="MsgAscii">The message as a literal ASCII string. The empty string denotes the zero-byte message.</param>
/// <param name="ExpectedCompressed">The 48-byte ZCash-compressed encoding of the published <c>(P.x, P.y)</c> output, as lowercase hex. Derived from the RFC's affine coordinates by applying the ZCash flag convention (bit 7 always set; bit 5 set when <c>y &gt; p - y</c>).</param>
internal sealed record Rfc9380J9_1Vector(
    string Id,
    string Description,
    string MsgAscii,
    string ExpectedCompressed);