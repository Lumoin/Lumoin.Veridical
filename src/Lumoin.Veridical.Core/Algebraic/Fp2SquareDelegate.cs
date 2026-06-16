using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form square of an Fp2 extension-field
/// element over the curve identified by <paramref name="curve"/>.
/// </summary>
/// <param name="a">The operand in canonical <c>[c0][c1]</c> layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form square into.</param>
/// <param name="curve">Identifies the field.</param>
/// <remarks>
/// Squaring is mathematically identical to <c>a · a</c> via
/// <see cref="Fp2MultiplyDelegate"/>; the dedicated delegate exists so
/// backends can apply the Karatsuba / complex-squaring identity
/// <c>(a0 + a1·u)² = (a0 + a1)(a0 − a1) + 2·a0·a1·u</c>, which uses two
/// Fp multiplications instead of three. Functionally, the result of
/// <c>Square(a)</c> must equal <c>Multiply(a, a)</c> for every input.
/// </remarks>
public delegate void Fp2SquareDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);