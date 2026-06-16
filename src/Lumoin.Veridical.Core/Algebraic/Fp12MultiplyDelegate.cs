using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form product of two Fp12 extension-field
/// elements over the curve identified by <paramref name="curve"/>,
/// writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The left operand in canonical Fp12 layout.</param>
/// <param name="b">The right operand in canonical Fp12 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form product into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// <para>
/// Multiplication in <c>Fp12 = Fp6[w]/(w² − v)</c> uses Karatsuba on
/// the two Fp6 coefficients, then wraps <c>w² → v</c> via the
/// "multiply by v" operation on Fp6 (which itself wraps
/// <c>v³ → ξ = 1 + u</c>). A correct backend produces a canonical
/// 576-byte result.
/// </para>
/// </remarks>
public delegate void Fp12MultiplyDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);