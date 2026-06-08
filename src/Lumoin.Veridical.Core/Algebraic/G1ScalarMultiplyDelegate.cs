using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form scalar multiple of a G1 point over the curve
/// identified by <paramref name="curve"/>, writing the result into
/// <paramref name="result"/>.
/// </summary>
/// <param name="point">The G1 point in canonical compressed byte layout.</param>
/// <param name="scalar">The scalar factor in the curve's scalar field, canonical big-endian byte layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form scalar multiple into.</param>
/// <param name="curve">Identifies the curve the point lives over.</param>
/// <remarks>
/// <para>
/// Backends typically implement scalar multiplication via a window method on
/// projective or Jacobian coordinates and convert back to canonical
/// compressed form on output. Constant-time variants are required for secret
/// scalars; the inner-loop dispatch path observes only canonical bytes in,
/// canonical bytes out, leaving the time-channel discipline to the backend.
/// </para>
/// </remarks>
public delegate void G1ScalarMultiplyDelegate(
    ReadOnlySpan<byte> point,
    ReadOnlySpan<byte> scalar,
    Span<byte> result,
    CurveParameterSet curve);