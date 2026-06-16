using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form sum of two Fp12 extension-field elements
/// over the curve identified by <paramref name="curve"/>, writing the
/// result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The left operand in canonical <c>[c0 : 288 bytes][c1 : 288 bytes]</c> layout.</param>
/// <param name="b">The right operand in the same layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form sum into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// Addition in Fp12 is componentwise on the two Fp6 coefficients.
/// </remarks>
public delegate void Fp12AddDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);