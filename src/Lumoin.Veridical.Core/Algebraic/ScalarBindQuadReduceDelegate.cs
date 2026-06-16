using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The fused per-term reduction of the Longfellow <c>bind_quad</c> dot product
/// (<c>Quad::bind_gh_all</c>, longfellow-zk <c>lib/zk/zk_common.h</c>) over the curve identified by
/// <paramref name="curve"/>. For each term <c>k</c> in <c>[0, count)</c> the primitive forms the
/// four-way CHAINED product
/// <c>(isZeroFlags[k] != 0 ? beta : coefficientTable[coefficientIndices[k]]) · eqgConcatenated[gateIndices[k]]
/// · eqh0Concatenated[leftIndices[k]] · eqh1Concatenated[rightIndices[k]]</c> and XOR-accumulates it
/// into <paramref name="accumulator"/>.
/// </summary>
/// <param name="coefficientTable">The distinct term coefficients, canonical 32-byte slots, deduped by the caller; <paramref name="coefficientIndices"/> selects per term.</param>
/// <param name="coefficientIndices">Length <paramref name="count"/>; each entry indexes <paramref name="coefficientTable"/> for that term's coefficient <c>v</c>.</param>
/// <param name="beta">One canonical 32-byte slot, the assert-zero coefficient used when a term's zero flag is set.</param>
/// <param name="eqgConcatenated">The <c>eqg</c> table, <c>nv</c> canonical 32-byte slots; <paramref name="gateIndices"/> selects per term.</param>
/// <param name="eqh0Concatenated">The <c>eqh0</c> table, <c>nw</c> canonical 32-byte slots; <paramref name="leftIndices"/> selects per term.</param>
/// <param name="eqh1Concatenated">The <c>eqh1</c> table, <c>nw</c> canonical 32-byte slots; <paramref name="rightIndices"/> selects per term.</param>
/// <param name="gateIndices">Length <paramref name="count"/>; each entry indexes <paramref name="eqgConcatenated"/>.</param>
/// <param name="leftIndices">Length <paramref name="count"/>; each entry indexes <paramref name="eqh0Concatenated"/>.</param>
/// <param name="rightIndices">Length <paramref name="count"/>; each entry indexes <paramref name="eqh1Concatenated"/>.</param>
/// <param name="isZeroFlags">Length <paramref name="count"/>, one byte per term; a non-zero byte selects <paramref name="beta"/> in place of the term's coefficient (and the term's <paramref name="coefficientIndices"/> entry is ignored, though it must still be in range).</param>
/// <param name="count">The number of terms.</param>
/// <param name="accumulator">One canonical 32-byte slot, XOR-accumulated; the caller clears it (or seeds it) and the primitive read-modify-writes it.</param>
/// <param name="curve">Identifies the field whose order the products reduce modulo.</param>
/// <remarks>
/// <para>
/// The per-term product is the four-way CHAINED product. Each multiply MUST reduce to a canonical
/// 128-bit element BEFORE the next carry-less multiply consumes it — not because the fold is non-linear
/// (over GF(2) reduction IS linear, so reducing the chain at the end would give the same field element in
/// exact arithmetic), but because the unreduced product is a ~255-bit value that does not fit the packed
/// 128-bit <c>(high, low)</c> limb pair the next multiply takes as input. So the reduction happens ONCE
/// PER MULTIPLY — THREE reductions per term — and is NEVER deferred across the chain. The reference's
/// deferred-reduction accumulator trick therefore applies only WITHIN a single product (one
/// multiply-accumulate plus one accumulate-reduce per multiply), never across the chain. Deferring the
/// fold across the chain would feed a truncated operand into the next multiply and diverge, breaking
/// byte-identicalness.
/// </para>
/// <para>
/// The cross-term accumulation is XOR (GF addition — associative and commutative), so the term sum may
/// be partitioned and the partials combined in any fixed order, byte-identical to the sequential sum.
/// The contract is canonical-bytes-in, canonical-bytes-out: every table slot and the accumulator are
/// canonical 32-byte big-endian encodings. A backend that does not benefit from fusion is free to
/// implement this as a scalar loop over the per-curve multiply and add; the contract is the observed
/// result, not the strategy.
/// </para>
/// <para>
/// The byte offset of a selected slot is <c>index * 32</c>; the caller keeps every index small enough
/// that <c>index * 32 &lt; int.MaxValue</c> so the slice arithmetic stays within a signed 32-bit range.
/// </para>
/// </remarks>
public delegate void ScalarBindQuadReduceDelegate(
    ReadOnlySpan<byte> coefficientTable,
    ReadOnlySpan<int> coefficientIndices,
    ReadOnlySpan<byte> beta,
    ReadOnlySpan<byte> eqgConcatenated,
    ReadOnlySpan<byte> eqh0Concatenated,
    ReadOnlySpan<byte> eqh1Concatenated,
    ReadOnlySpan<int> gateIndices,
    ReadOnlySpan<int> leftIndices,
    ReadOnlySpan<int> rightIndices,
    ReadOnlySpan<byte> isZeroFlags,
    int count,
    Span<byte> accumulator,
    CurveParameterSet curve);
