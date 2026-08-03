using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// Encodes binary data to its unpadded base64url string form — the host-side coding seam of the
/// JWS extractor surface. The library ships no implementation: the consumer wires one (for
/// example over <c>System.Buffers.Text.Base64Url</c>), and the parameter and return shape is
/// identical to the sibling Verifiable stack's encode delegate, so a single implementation
/// serves both libraries.
/// </summary>
/// <param name="data">The binary data to encode.</param>
/// <returns>The encoded string.</returns>
/// <remarks>
/// This seam is host-side only. It is distinct from the in-circuit base64url decoder gadget,
/// which is a compiled statement component, and from the witness generator's internal decoder,
/// which reproduces the reference's zero-padded partial-group convention that the circuit
/// asserts — neither is swappable without breaking witness and circuit agreement.
/// </remarks>
public delegate string LongfellowBase64UrlEncodeDelegate(ReadOnlySpan<byte> data);
