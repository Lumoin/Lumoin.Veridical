using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form scalar multiple <c>k · P</c> in the G2
/// group over the curve identified by <paramref name="curve"/>.
/// </summary>
/// <param name="point">The base point in canonical compressed byte layout (96 bytes for BLS12-381).</param>
/// <param name="scalar">The scalar in canonical big-endian byte order (32 bytes for BLS12-381).</param>
/// <param name="result">The destination span the backend writes the canonical-form product into.</param>
/// <param name="curve">Identifies the curve.</param>
/// <remarks>
/// Same contract as <see cref="G1ScalarMultiplyDelegate"/>. The scalar
/// is reduced modulo the curve's scalar-field order before the
/// multiplication; a backend that requires reduced input documents
/// that requirement separately.
/// </remarks>
public delegate void G2ScalarMultiplyDelegate(
    ReadOnlySpan<byte> point,
    ReadOnlySpan<byte> scalar,
    Span<byte> result,
    CurveParameterSet curve);