using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// A canonical&lt;-&gt;working-domain conversion over a 32-byte big-endian base-field value, the boundary
/// converter the Montgomery-aware Fp256 profile applies at its seam points. The forward direction lifts a
/// canonical value to its Montgomery residue (<c>to_montgomery</c>); the inverse drops a Montgomery residue
/// back to canonical (<c>from_montgomery</c>). For the canonical working domain the converter is the identity.
/// </summary>
/// <param name="source">The source value (32 bytes, big-endian).</param>
/// <param name="destination">Receives the converted value (32 bytes, big-endian); may alias <paramref name="source"/> only when the converter permits it.</param>
internal delegate void LongfellowDomainConvertDelegate(ReadOnlySpan<byte> source, Span<byte> destination);
