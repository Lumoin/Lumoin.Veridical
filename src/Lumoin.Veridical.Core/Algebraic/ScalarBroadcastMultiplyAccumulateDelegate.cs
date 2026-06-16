using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the broadcast-scalar fused multiply-accumulate of <paramref name="count"/> operands
/// over the curve identified by <paramref name="curve"/>: for each <c>i</c>,
/// <c>accumulators[i] += scalar·operands[i]</c> when <paramref name="accumulate"/> is
/// <see langword="true"/>, or <c>accumulators[i] = scalar·operands[i]</c> when it is
/// <see langword="false"/>. The single <paramref name="scalar"/> multiplies every operand.
/// </summary>
/// <param name="scalar">The shared multiplier as one canonical big-endian scalar encoding.</param>
/// <param name="operandsConcatenated">The operands laid out as one contiguous span: <paramref name="count"/> canonical big-endian scalar encodings appended back to back.</param>
/// <param name="accumulatorsConcatenated">The destination span the backend reads (when accumulating) and writes, in the same layout. It must alias neither <paramref name="scalar"/> nor <paramref name="operandsConcatenated"/>.</param>
/// <param name="accumulate">When <see langword="true"/> the products are added into the existing accumulator contents; when <see langword="false"/> the accumulators are overwritten with the products.</param>
/// <param name="count">The number of operands.</param>
/// <param name="curve">Identifies the field whose order the results are reduced modulo.</param>
/// <remarks>
/// <para>
/// The cheap, common case of <see cref="ScalarBatchMultiplyAccumulateDelegate"/> where the left
/// operand is one shared value: the multilinear-extension fold by a challenge <c>r</c>, the LCH14
/// twiddle applied across a butterfly group. The backend loads the broadcast scalar once and
/// reuses it across the whole span — and, for a binary field, broadcasts its two carry-less halves
/// into the SIMD lanes once rather than re-parsing it per element.
/// </para>
/// <para>
/// Flattened buffers plus a count: <paramref name="operandsConcatenated"/> and
/// <paramref name="accumulatorsConcatenated"/> each have length <c>count * Scalar.SizeBytes</c> and
/// <paramref name="scalar"/> has length <c>Scalar.SizeBytes</c>; a correct backend validates this
/// and throws on mismatch. A backend that does not benefit is free to implement this as a loop over
/// the single-element <see cref="ScalarMultiplyDelegate"/>; the observed contract is
/// canonical-bytes-in, canonical-bytes-out.
/// </para>
/// </remarks>
public delegate void ScalarBroadcastMultiplyAccumulateDelegate(
    ReadOnlySpan<byte> scalar,
    ReadOnlySpan<byte> operandsConcatenated,
    Span<byte> accumulatorsConcatenated,
    bool accumulate,
    int count,
    CurveParameterSet curve);
