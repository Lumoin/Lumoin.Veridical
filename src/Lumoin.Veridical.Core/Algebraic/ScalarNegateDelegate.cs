using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form additive inverse of a scalar over the curve
/// identified by <paramref name="curve"/>, writing the result into
/// <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical big-endian byte layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form additive inverse into.</param>
/// <param name="curve">Identifies the field whose order the result is reduced modulo.</param>
/// <remarks>
/// The additive inverse of zero is zero. A correct backend handles this case
/// without branching on the input value, since a zero check would leak
/// information through timing if reused on secret material.
/// </remarks>
public delegate void ScalarNegateDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);