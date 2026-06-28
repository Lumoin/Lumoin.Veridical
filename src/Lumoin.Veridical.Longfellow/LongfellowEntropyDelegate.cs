using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// Fills a destination span with cryptographically strong random bytes — the prover entropy seam the
/// dual-field mdoc facade draws blinding and pad material from.
/// </summary>
/// <param name="destination">The span to fill.</param>
public delegate void LongfellowEntropyDelegate(Span<byte> destination);
