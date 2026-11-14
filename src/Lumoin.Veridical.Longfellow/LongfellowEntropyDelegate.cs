using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// Fills a destination span with plain cryptographically secure random bytes — the seam beneath
/// <see cref="LongfellowProverRandomness"/>. The bytes are unconstrained: the prover maps them to field
/// elements and rejects out-of-range draws itself.
/// </summary>
/// <param name="destination">The span to fill.</param>
public delegate void LongfellowEntropyDelegate(Span<byte> destination);
