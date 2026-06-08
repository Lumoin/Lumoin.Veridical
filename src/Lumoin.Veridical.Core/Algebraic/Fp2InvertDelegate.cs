using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form multiplicative inverse of an Fp2
/// extension-field element over the curve identified by
/// <paramref name="curve"/>. The behaviour on the zero element is
/// backend-defined; a correct backend either returns zero or signals
/// failure through a side channel.
/// </summary>
/// <param name="a">The operand in canonical <c>[c0][c1]</c> layout. Must be non-zero for a meaningful result.</param>
/// <param name="result">The destination span the backend writes the inverse into.</param>
/// <param name="curve">Identifies the field.</param>
/// <remarks>
/// The inverse of <c>a = c0 + c1·u</c> is
/// <c>a^(-1) = (c0 − c1·u) / (c0² + c1²)</c> where the denominator
/// reduction is the standard complex-conjugate trick adapted to the
/// quadratic extension with <c>u² = −1</c>. A correct backend reduces
/// both components modulo the BLS12-381 base field prime.
/// </remarks>
public delegate void Fp2InvertDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);