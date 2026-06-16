using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form sum of <paramref name="count"/> pairs of
/// scalars over the curve identified by <paramref name="curve"/>, writing
/// the results into <paramref name="resultsConcatenated"/>.
/// </summary>
/// <param name="leftOperandsConcatenated">The left operands laid out as one contiguous span: <paramref name="count"/> canonical big-endian scalar encodings appended back to back.</param>
/// <param name="rightOperandsConcatenated">The right operands, in the same layout.</param>
/// <param name="resultsConcatenated">The destination span the backend writes the canonical-form sums into, in the same layout.</param>
/// <param name="count">The number of scalar pairs.</param>
/// <param name="curve">Identifies the field whose order the results are reduced modulo.</param>
/// <remarks>
/// <para>
/// Same shape as <see cref="G1MultiScalarMultiplyDelegate"/>: flattened
/// buffers plus a count, because spans of spans do not exist in C#. For
/// BLS12-381 each scalar is <c>Scalar.SizeBytes</c> (32)
/// bytes, so the three buffers must each have length
/// <c>count * 32</c>; a correct backend validates this and throws on
/// mismatch.
/// </para>
/// <para>
/// Distinct from <see cref="ScalarAddDelegate"/> by allowing the backend
/// to exploit batching strategies — interleaved-lane SIMD parallelism,
/// batch loads to amortise per-call overhead, lazy reduction across the
/// batch — that a single-element delegate cannot. A backend that does
/// not benefit from batching is free to implement this as a loop over the
/// single-element <see cref="ScalarAddDelegate"/>; the contract observed
/// at this delegate is canonical-bytes-in, canonical-bytes-out for every
/// pair in the batch, regardless of implementation strategy.
/// </para>
/// </remarks>
public delegate void ScalarBatchAddDelegate(
    ReadOnlySpan<byte> leftOperandsConcatenated,
    ReadOnlySpan<byte> rightOperandsConcatenated,
    Span<byte> resultsConcatenated,
    int count,
    CurveParameterSet curve);