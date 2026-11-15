using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>Fills the two components of a signature being produced: the <c>r</c> span and the <c>s</c> span, each 32 bytes.</summary>
/// <param name="r">Receives the component <c>r</c>.</param>
/// <param name="s">Receives the component <c>s</c>.</param>
internal delegate void SecdsaSignatureFill(Span<byte> r, Span<byte> s);
