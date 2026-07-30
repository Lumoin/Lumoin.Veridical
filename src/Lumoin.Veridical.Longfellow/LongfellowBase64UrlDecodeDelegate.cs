using System;
using System.Buffers;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// Decodes unpadded base64url character data into a pool-rented buffer — the host-side coding
/// seam of the JWS extractor surface. The library ships no implementation: the consumer wires one
/// (for example over <c>System.Buffers.Text.Base64Url</c>), and the parameter and return shape is
/// identical to the sibling Verifiable stack's decode delegate, so a single implementation serves
/// both libraries. An implementation rents the result from <paramref name="pool"/>, right-sizes
/// it, and rejects input outside the unpadded base64url alphabet — a literal <c>=</c> included —
/// by throwing <see cref="FormatException"/>; the caller disposes the returned owner.
/// </summary>
/// <param name="source">The encoded character data to decode.</param>
/// <param name="pool">The memory pool the result buffer is rented from.</param>
/// <returns>An owned buffer holding exactly the decoded bytes.</returns>
/// <remarks>
/// This seam is host-side only. It is distinct from the in-circuit base64url decoder gadget,
/// which is a compiled statement component, and from the witness generator's internal decoder,
/// which reproduces the reference's zero-padded partial-group convention that the circuit
/// asserts — neither is swappable without breaking witness and circuit agreement.
/// </remarks>
public delegate IMemoryOwner<byte> LongfellowBase64UrlDecodeDelegate(ReadOnlySpan<char> source, MemoryPool<byte> pool);
