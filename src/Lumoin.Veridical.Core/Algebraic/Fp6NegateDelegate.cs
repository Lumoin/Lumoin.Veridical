using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form additive negation <c>−a</c> of an Fp6
/// extension-field element over the curve identified by
/// <paramref name="curve"/>, writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical Fp6 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form negation into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// Negation is componentwise on the three Fp2 coefficients.
/// </remarks>
public delegate void Fp6NegateDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);