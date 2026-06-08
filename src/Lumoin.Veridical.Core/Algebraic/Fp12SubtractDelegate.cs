using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form difference <c>a − b</c> of two Fp12
/// extension-field elements over the curve identified by
/// <paramref name="curve"/>, writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The minuend in canonical Fp12 layout.</param>
/// <param name="b">The subtrahend in canonical Fp12 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form difference into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// Subtraction is componentwise on the two Fp6 coefficients.
/// </remarks>
public delegate void Fp12SubtractDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);