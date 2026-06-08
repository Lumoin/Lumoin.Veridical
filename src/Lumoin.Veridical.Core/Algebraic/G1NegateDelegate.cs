using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form additive inverse of a G1 point over the curve
/// identified by <paramref name="curve"/>, writing the result into
/// <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical compressed byte layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form additive inverse into.</param>
/// <param name="curve">Identifies the curve the operand lives over.</param>
/// <remarks>
/// <para>
/// For a Weierstrass-form curve <c>y^2 = x^3 + ax + b</c>, negation maps
/// <c>(x, y)</c> to <c>(x, -y mod p)</c>; in the compressed encoding it flips
/// the y-parity flag bit. The identity point is its own inverse. A correct
/// backend handles the identity case without branching on the y-parity bit so
/// the same code path is safe to reuse on secret material.
/// </para>
/// </remarks>
public delegate void G1NegateDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);