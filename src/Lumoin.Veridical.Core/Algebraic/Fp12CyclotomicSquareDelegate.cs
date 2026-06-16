using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Squares an Fp12 element that lies in the cyclotomic subgroup
/// <c>G_{Φ_{12}(p)} ⊂ Fp12*</c>, writing the canonical-form square
/// into <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical Fp12 layout; the caller asserts <paramref name="a"/> is in the cyclotomic subgroup.</param>
/// <param name="result">The destination span the backend writes the canonical-form cyclotomic square into.</param>
/// <param name="curve">Identifies the field.</param>
/// <remarks>
/// <para>
/// Inside the cyclotomic subgroup of <c>Fp12*</c> a specialised squaring
/// (Granger-Scott, Karabina, etc.) computes <c>x²</c> in roughly one-
/// third the cost of the generic Fp12 square; the BLS12-381 final
/// exponentiation runs hundreds of these in its hard-part square-and-
/// multiply, so the speedup is load-bearing for production backends.
/// </para>
/// <para>
/// Behaviour on inputs <em>outside</em> the cyclotomic subgroup is
/// backend-defined and not required to match the generic square. The
/// reference implementation may simply delegate to a generic Fp12
/// squaring routine for correctness; a SIMD or GPU backend will
/// specialise.
/// </para>
/// </remarks>
public delegate void Fp12CyclotomicSquareDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);