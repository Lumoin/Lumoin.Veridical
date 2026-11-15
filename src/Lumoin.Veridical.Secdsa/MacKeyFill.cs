using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>Fills a freshly rented MAC key buffer of the requested length.</summary>
/// <param name="macKey">Receives the derived key bytes.</param>
internal delegate void MacKeyFill(Span<byte> macKey);
