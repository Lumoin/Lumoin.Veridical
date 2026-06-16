using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the indexed (gather/scatter) fused multiply-accumulate of <paramref name="count"/>
/// terms over the curve identified by <paramref name="curve"/>: for each <c>k</c>,
/// <c>accumulators[outputIndices[k]] += coefficients[k]·data[inputIndices[k]]</c>. The coefficients
/// are read sequentially; the data operand is gathered at <paramref name="inputIndices"/> and the
/// product is scattered into the accumulator at <paramref name="outputIndices"/>.
/// </summary>
/// <param name="coefficientsConcatenated">The per-term coefficients laid out as one contiguous span: <paramref name="count"/> canonical big-endian scalar encodings appended back to back.</param>
/// <param name="dataConcatenated">The data table the input indices gather from, as canonical big-endian scalar encodings appended back to back.</param>
/// <param name="inputIndices">The element index into <paramref name="dataConcatenated"/> for each term; length <paramref name="count"/>.</param>
/// <param name="outputIndices">The element index into <paramref name="accumulatorsConcatenated"/> each product is added into; length <paramref name="count"/>.</param>
/// <param name="accumulatorsConcatenated">The destination span the backend reads and writes at the scattered indices, as canonical big-endian scalar encodings appended back to back. It must alias neither <paramref name="coefficientsConcatenated"/> nor <paramref name="dataConcatenated"/>; overlap between <paramref name="accumulatorsConcatenated"/> and <paramref name="dataConcatenated"/> is not supported — across successive consecutive runs the implementation writes the reduced sum of a run before reading input slots for later runs, so any gathered input slot that coincides with an output slot written by a preceding run receives a corrupted value.</param>
/// <param name="count">The number of terms.</param>
/// <param name="curve">Identifies the field whose order the results are reduced modulo.</param>
/// <remarks>
/// <para>
/// The access pattern of the circuit-evaluation and per-round weight-precompute loops, which read
/// wire values at arbitrary stored indices and accumulate into output slots at other stored
/// indices. Indices are caller-supplied <see cref="int"/> spans because the per-term operands do
/// not arrive contiguously; the products accumulate with the binary-field deferred-reduction
/// discipline (<see cref="ScalarBatchMultiplyAccumulateDelegate"/>): reduction is deferred per
/// consecutive run of terms sharing an output slot — the carry-less products for all terms in one
/// such run are XOR-accumulated in the three-lane accumulator and the 0x87 fold is applied once
/// when the slot changes. Non-consecutive occurrences of the same output slot start independent
/// accumulators and are each reduced separately; the reduced sums are then XOR-accumulated into
/// the slot, which is byte-identical to a single reduction by GF(2)-linearity.
/// </para>
/// <para>
/// The coefficient buffer has length <c>count * Scalar.SizeBytes</c> and the index spans have
/// length <paramref name="count"/>; a correct backend validates this and throws on mismatch, and
/// rejects an <paramref name="accumulatorsConcatenated"/> span that overlaps either input span. The
/// backend does not bounds-check each gathered/scattered index against the data and accumulator
/// lengths on the hot path — the caller guarantees in-range indices, matching the reference's
/// unconditional indexing. Byte offsets are computed as <c>index * Scalar.SizeBytes</c> in 32-bit
/// arithmetic, so indices must stay below <c>int.MaxValue / Scalar.SizeBytes</c> elements
/// (≈ 67 million at 32 bytes per scalar) — far above any circuit table in use. A backend that does not benefit is free to implement this as a loop over
/// the single-element <see cref="ScalarMultiplyDelegate"/> and <see cref="ScalarAddDelegate"/>; the
/// observed contract is canonical-bytes-in, canonical-bytes-out.
/// </para>
/// </remarks>
public delegate void ScalarGatherMultiplyAccumulateDelegate(
    ReadOnlySpan<byte> coefficientsConcatenated,
    ReadOnlySpan<byte> dataConcatenated,
    ReadOnlySpan<int> inputIndices,
    ReadOnlySpan<int> outputIndices,
    Span<byte> accumulatorsConcatenated,
    int count,
    CurveParameterSet curve);
