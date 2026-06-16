using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form difference of two Fp2 extension-field
/// elements over the curve identified by <paramref name="curve"/>.
/// </summary>
/// <param name="a">The minuend in canonical <c>[c0][c1]</c> layout.</param>
/// <param name="b">The subtrahend in the same layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form difference into.</param>
/// <param name="curve">Identifies the field.</param>
/// <remarks>
/// Subtraction is componentwise: <c>(a0 − b0) + (a1 − b1)·u</c>, each
/// component reduced modulo the BLS12-381 base field prime.
/// </remarks>
public delegate void Fp2SubtractDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);