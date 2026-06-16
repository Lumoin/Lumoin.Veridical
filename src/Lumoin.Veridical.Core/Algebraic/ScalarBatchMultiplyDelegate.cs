using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form product of <paramref name="count"/> pairs of scalars
/// over the curve identified by <paramref name="curve"/>, writing the results into
/// <paramref name="resultsConcatenated"/>.
/// </summary>
/// <param name="leftOperandsConcatenated">The left operands laid out as one contiguous span: <paramref name="count"/> canonical big-endian scalar encodings appended back to back.</param>
/// <param name="rightOperandsConcatenated">The right operands, in the same layout.</param>
/// <param name="resultsConcatenated">The destination span the backend writes the canonical-form products into, in the same layout.</param>
/// <param name="count">The number of scalar pairs.</param>
/// <param name="curve">Identifies the field whose order the results are reduced modulo.</param>
/// <remarks>
/// <para>
/// The multiplicative counterpart of <see cref="ScalarBatchAddDelegate"/>: flattened
/// buffers plus a count, each buffer of length <c>count * Scalar.SizeBytes</c>; a
/// correct backend validates this and throws on mismatch.
/// </para>
/// <para>
/// Distinct from <see cref="ScalarMultiplyDelegate"/> by allowing the backend to
/// exploit batching — lane-interleaved SIMD running several independent Montgomery
/// multiplications at once, amortised loads — that a single-element delegate cannot.
/// A backend that does not benefit is free to implement this as a loop over the
/// single-element <see cref="ScalarMultiplyDelegate"/>; the observed contract is
/// canonical-bytes-in, canonical-bytes-out for every pair, regardless of strategy.
/// </para>
/// </remarks>
public delegate void ScalarBatchMultiplyDelegate(
    ReadOnlySpan<byte> leftOperandsConcatenated,
    ReadOnlySpan<byte> rightOperandsConcatenated,
    Span<byte> resultsConcatenated,
    int count,
    CurveParameterSet curve);
