using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the element-wise fused multiply-accumulate of <paramref name="count"/> pairs of
/// scalars over the curve identified by <paramref name="curve"/>: for each <c>i</c>,
/// <c>accumulators[i] += left[i]·right[i]</c> when <paramref name="accumulate"/> is
/// <see langword="true"/>, or <c>accumulators[i] = left[i]·right[i]</c> when it is
/// <see langword="false"/> (which yields a plain element-wise batch multiply that overwrites the
/// destination).
/// </summary>
/// <param name="leftOperandsConcatenated">The left operands laid out as one contiguous span: <paramref name="count"/> canonical big-endian scalar encodings appended back to back.</param>
/// <param name="rightOperandsConcatenated">The right operands, in the same layout.</param>
/// <param name="accumulatorsConcatenated">The destination span the backend reads (when accumulating) and writes, in the same layout. It must alias neither operand span.</param>
/// <param name="accumulate">When <see langword="true"/> the products are added into the existing accumulator contents; when <see langword="false"/> the accumulators are overwritten with the products.</param>
/// <param name="count">The number of scalar pairs.</param>
/// <param name="curve">Identifies the field whose order the results are reduced modulo.</param>
/// <remarks>
/// <para>
/// This is the dominant prover primitive: the hot loops are dot products — <c>acc += a·b</c>
/// repeated over a data-sized span — not standalone element-wise multiply. Expressing the pattern
/// as a fused delegate (rather than a batch multiply followed by a batch add) lets the backend
/// avoid materialising and re-scanning the product span, and — decisively for a binary field like
/// GF(2^128) — lets it <em>defer reduction</em>: accumulate the unreduced carry-less products and
/// reduce once at the end of the span instead of once per multiply. That deferral is the
/// reference's <c>gf2_128_accum_t</c> / <c>gf2_128_mac</c> trick (longfellow-zk
/// <c>lib/gf2k/sysdep.h</c>) and is mathematically invisible at this seam: the observed contract
/// is canonical-bytes-in, canonical-bytes-out, byte-identical to a naive multiply-then-add loop.
/// </para>
/// <para>
/// Flattened buffers plus a count, each buffer of length <c>count * Scalar.SizeBytes</c>; a
/// correct backend validates this and throws on mismatch. A backend that does not benefit from
/// fusion or deferral is free to implement this as a loop over the single-element
/// <see cref="ScalarMultiplyDelegate"/> and <see cref="ScalarAddDelegate"/>; the contract is the
/// observed result, not the strategy.
/// </para>
/// </remarks>
public delegate void ScalarBatchMultiplyAccumulateDelegate(
    ReadOnlySpan<byte> leftOperandsConcatenated,
    ReadOnlySpan<byte> rightOperandsConcatenated,
    Span<byte> accumulatorsConcatenated,
    bool accumulate,
    int count,
    CurveParameterSet curve);
