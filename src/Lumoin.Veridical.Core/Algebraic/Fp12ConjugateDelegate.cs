using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form Fp12 conjugate <c>c0 − c1·w</c> of an
/// element <c>a = c0 + c1·w</c> over the curve identified by
/// <paramref name="curve"/>, writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical Fp12 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form conjugate into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// <para>
/// This is the non-trivial Fp6-automorphism of Fp12: it negates the
/// <c>c1</c> Fp6 component and leaves <c>c0</c> untouched.
/// </para>
/// <para>
/// For elements in the cyclotomic subgroup of <c>Fp12*</c> the
/// conjugate equals the inverse — the easy half of the BLS12-381 final
/// exponentiation <c>x ↦ x^{p^6 − 1}</c> reduces to one conjugation
/// plus one inversion plus one multiplication.
/// </para>
/// </remarks>
public delegate void Fp12ConjugateDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);