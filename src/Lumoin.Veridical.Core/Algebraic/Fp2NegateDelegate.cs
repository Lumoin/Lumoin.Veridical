using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form additive negation of an Fp2
/// extension-field element over the curve identified by
/// <paramref name="curve"/>.
/// </summary>
/// <param name="a">The operand in canonical <c>[c0][c1]</c> layout.</param>
/// <param name="result">The destination span the backend writes the negation into.</param>
/// <param name="curve">Identifies the field.</param>
/// <remarks>
/// Negation is componentwise: <c>−(c0 + c1·u) = (−c0) + (−c1)·u</c>,
/// each component reduced to the canonical non-negative residue.
/// </remarks>
public delegate void Fp2NegateDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);