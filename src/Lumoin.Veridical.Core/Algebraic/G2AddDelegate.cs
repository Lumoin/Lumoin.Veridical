using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form group sum of two G2 points over the
/// curve identified by <paramref name="curve"/>.
/// </summary>
/// <param name="a">The left operand in canonical compressed byte layout (96 bytes for BLS12-381).</param>
/// <param name="b">The right operand in the same layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form sum into.</param>
/// <param name="curve">Identifies the curve.</param>
/// <remarks>
/// Same contract as <see cref="G1AddDelegate"/> with G2 in place of
/// G1. G2 coordinates live in Fp2; the backend handles the
/// compressed-form decoding, the projective-or-Jacobian group law over
/// Fp2, and the canonical-compressed encoding of the result.
/// </remarks>
public delegate void G2AddDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);