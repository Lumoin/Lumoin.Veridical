using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form multiplicative inverse <c>a^(-1)</c> of
/// an Fp12 extension-field element over the curve identified by
/// <paramref name="curve"/>, writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical Fp12 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form inverse into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// Backends typically compute the norm <c>N(a) = a · ā = c0² − v·c1² ∈ Fp6</c>
/// (using the conjugate <c>ā = c0 − c1·w</c>), invert it in Fp6, then
/// multiply through. Behaviour on the zero element is backend-defined.
/// </remarks>
public delegate void Fp12InvertDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);