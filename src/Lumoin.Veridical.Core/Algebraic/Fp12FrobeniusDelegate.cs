using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Applies the Frobenius endomorphism <c>x ↦ x^p</c> on the BLS12-381
/// Fp12 extension field over the curve identified by
/// <paramref name="curve"/>, writing the canonical-form result into
/// <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical Fp12 layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form Frobenius into.</param>
/// <param name="curve">Identifies the field.</param>
/// <remarks>
/// <para>
/// Frobenius is the load-bearing structural operation of the final
/// exponentiation in BLS12-381 pairings. A correct backend produces
/// the same result as componentwise Fp <c>ModPow(·, p, p)</c> on each
/// of the twelve Fp coordinates — but exploits the tower structure
/// via precomputed Fp2 constants (γ-values) so a single Frobenius is
/// twelve Fp2 multiplications, not twelve Fp exponentiations.
/// </para>
/// <para>
/// Higher Frobenius powers (<c>π²</c>, <c>π³</c>) are obtained by
/// composing this delegate. A backend that wants a specialised
/// <c>π²</c> in the inner loop of final exponentiation surfaces it as
/// a separate delegate when introduced.
/// </para>
/// </remarks>
public delegate void Fp12FrobeniusDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);