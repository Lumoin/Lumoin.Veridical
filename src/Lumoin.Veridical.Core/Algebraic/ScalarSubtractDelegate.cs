using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form difference of two scalars over the curve
/// identified by <paramref name="curve"/>, writing the result into
/// <paramref name="result"/>.
/// </summary>
/// <param name="a">The minuend in canonical big-endian byte layout.</param>
/// <param name="b">The subtrahend in canonical big-endian byte layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form difference into.</param>
/// <param name="curve">Identifies the field whose order the result is reduced modulo.</param>
/// <remarks>
/// Same shape and contract as <see cref="ScalarAddDelegate"/>. A backend may
/// implement subtraction as <c>add(a, negate(b))</c> or as a fused operation;
/// applications wire whichever is supplied.
/// </remarks>
public delegate void ScalarSubtractDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);