using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form product of two Fp2 extension-field
/// elements over the curve identified by <paramref name="curve"/>.
/// </summary>
/// <param name="a">The left operand in canonical <c>[c0][c1]</c> layout.</param>
/// <param name="b">The right operand in the same layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form product into.</param>
/// <param name="curve">Identifies the field.</param>
/// <remarks>
/// Multiplication uses the Fp2 quadratic-extension formula with
/// <c>u² = −1</c>:
/// <c>(a0 + a1·u)(b0 + b1·u) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·u</c>.
/// A correct backend reduces both components modulo the BLS12-381
/// base field prime before writing. Aliasing the input spans with the
/// output span is the caller's responsibility; a conformant backend
/// either supports aliasing or documents that it does not.
/// </remarks>
public delegate void Fp2MultiplyDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);