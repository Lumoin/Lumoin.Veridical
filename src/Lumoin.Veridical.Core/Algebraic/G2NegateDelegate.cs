using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form additive negation of a G2 point over
/// the curve identified by <paramref name="curve"/>.
/// </summary>
/// <param name="a">The operand in canonical compressed byte layout.</param>
/// <param name="result">The destination span the backend writes the negation into.</param>
/// <param name="curve">Identifies the curve.</param>
/// <remarks>
/// In short-Weierstrass coordinates negation flips the sign of the
/// y-coordinate. For the BLS12-381 G2 compressed form this is the
/// y-parity flag bit in the most-significant byte; the backend
/// updates that bit while leaving the x-coordinate bytes unchanged
/// for non-identity points.
/// </remarks>
public delegate void G2NegateDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);