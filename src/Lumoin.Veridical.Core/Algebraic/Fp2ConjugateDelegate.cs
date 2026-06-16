using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form complex conjugate of an Fp2
/// extension-field element over the curve identified by
/// <paramref name="curve"/>: <c>conj(c0 + c1·u) = c0 − c1·u</c>.
/// </summary>
/// <param name="a">The operand in canonical <c>[c0][c1]</c> layout.</param>
/// <param name="result">The destination span the backend writes the conjugate into.</param>
/// <param name="curve">Identifies the field.</param>
/// <remarks>
/// Over Fp2 with <c>u² = −1</c> the conjugate equals the Frobenius
/// operator <c>x^p</c> (raising to the base-field prime), which is a
/// degree-1 endomorphism of Fp2 fixing Fp. This delegate is the
/// fundamental building block for higher-degree Frobenius operators
/// used inside Fp6 / Fp12 arithmetic and inside the pairing's final
/// exponentiation.
/// </remarks>
public delegate void Fp2ConjugateDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);