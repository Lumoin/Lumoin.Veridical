using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Applies one LCH14 additive-FFT forward butterfly across a whole butterfly group that shares the
/// single <paramref name="twiddle"/>, over the curve identified by <paramref name="curve"/>: for
/// each offset <c>off</c> in <c>0..stride</c>, <c>low[off] += twiddle·high[off]</c> then
/// <c>high[off] += low[off]</c>. The two operand spans are the low and high halves of the group,
/// each <paramref name="stride"/> elements long.
/// </summary>
/// <param name="twiddle">The shared twiddle factor as one canonical big-endian scalar encoding.</param>
/// <param name="lowConcatenated">The low half of the group: <paramref name="stride"/> canonical big-endian scalar encodings appended back to back; read and written in place.</param>
/// <param name="highConcatenated">The high half of the group, in the same layout; read and written in place.</param>
/// <param name="stride">The number of element pairs in the group.</param>
/// <param name="curve">Identifies the field whose order the results are reduced modulo.</param>
/// <remarks>
/// <para>
/// The FFT butterfly is the largest carry-less-multiply consumer in the prove because the Ligero
/// row encode is built entirely from it; expressing one butterfly group as a batch op — a shared
/// broadcast twiddle over a strided span — covers both the FFT and, transitively, the entire row
/// encode at a single seam. The twiddle is loaded and broadcast into the SIMD lanes once per group.
/// </para>
/// <para>
/// Both halves have length <c>stride * Scalar.SizeBytes</c> and the twiddle has length
/// <c>Scalar.SizeBytes</c>; a correct backend validates this and throws on mismatch. The two
/// in-place updates are ordered (the <c>high</c> update reads the just-written <c>low</c>), so the
/// backend writes <c>low[off]</c> before reading it for <c>high[off]</c>. A backend that does not
/// benefit is free to implement this as a loop over the single-element multiply/add delegates; the
/// observed contract is canonical-bytes-in, canonical-bytes-out, byte-identical to the per-element
/// butterfly.
/// </para>
/// </remarks>
public delegate void Gf2kButterflyBatchDelegate(
    ReadOnlySpan<byte> twiddle,
    Span<byte> lowConcatenated,
    Span<byte> highConcatenated,
    int stride,
    CurveParameterSet curve);
