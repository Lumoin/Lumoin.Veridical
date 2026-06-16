using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form product of two Fp6 extension-field
/// elements over the curve identified by <paramref name="curve"/>,
/// writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The left operand in canonical Fp6 layout.</param>
/// <param name="b">The right operand in canonical Fp6 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form product into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// <para>
/// Multiplication in <c>Fp6 = Fp2[v]/(v³ − ξ)</c> with non-residue
/// <c>ξ = 1 + u</c> wraps <c>v³ → ξ</c> after polynomial multiplication.
/// A correct backend produces a canonical 288-byte result; a backend may
/// internally use Karatsuba (6 Fp2 mul) or the schoolbook 9-mul form
/// — the contract is just byte equality with the reference for valid
/// inputs.
/// </para>
/// </remarks>
public delegate void Fp6MultiplyDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);