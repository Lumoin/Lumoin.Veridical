using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form multiplicative inverse <c>a^(-1)</c> of
/// an Fp6 extension-field element over the curve identified by
/// <paramref name="curve"/>, writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical Fp6 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form inverse into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// Backends typically use the closed-form cubic-extension inverse based
/// on the norm <c>N(a) = a · σ(a) · σ²(a) ∈ Fp2</c>, then one Fp2
/// inversion. Behaviour on the zero element is backend-defined.
/// </remarks>
public delegate void Fp6InvertDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);