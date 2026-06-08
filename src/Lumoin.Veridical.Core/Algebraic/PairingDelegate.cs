using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the optimal-Ate pairing <c>e(P, Q) : G1 × G2 → GT ⊂ Fp12*</c>
/// over the curve identified by <paramref name="curve"/>, writing the
/// canonical-form Fp12 result into <paramref name="result"/>.
/// </summary>
/// <param name="p">The G1 input point in canonical compressed byte layout (48 bytes for BLS12-381).</param>
/// <param name="q">The G2 input point in canonical compressed byte layout (96 bytes for BLS12-381).</param>
/// <param name="result">The destination span the backend writes the canonical-form Fp12 pairing value into (576 bytes).</param>
/// <param name="curve">Identifies the curve.</param>
/// <remarks>
/// <para>
/// The pairing is the composition of two internal steps — the Miller
/// loop over the binary expansion of the BLS12-381 curve parameter
/// <c>|x|</c>, then the final exponentiation
/// <c>f ↦ f^{(p^{12} − 1)/r}</c> that projects into the order-<c>r</c>
/// subgroup <c>GT</c>. A backend is free to specialise either step
/// independently; they are surfaced as separate delegates only when
/// a backend needs to swap them piecewise.
/// </para>
/// <para>
/// When either operand is the identity, the result is the multiplicative
/// identity of Fp12 (one). When both operands are in their canonical
/// prime-order subgroups, the result is in the cyclotomic subgroup
/// <c>GT</c>; the function is bilinear: <c>e([a]P, Q) = e(P, [a]Q) = e(P, Q)^a</c>.
/// </para>
/// </remarks>
public delegate void PairingDelegate(
    ReadOnlySpan<byte> p,
    ReadOnlySpan<byte> q,
    Span<byte> result,
    CurveParameterSet curve);