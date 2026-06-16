using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// Extends a tableau row in place: the <c>N</c> input evaluations in the prefix of
/// <paramref name="evaluations"/> become all <c>M</c> systematic Reed–Solomon evaluations, the first
/// <c>N</c> unchanged. The wire-format Ligero flow threads one of these per <c>(N, M)</c> shape, closed
/// over the field's encoder (the binary <see cref="Algebraic.Lch14ReedSolomon"/> or the prime
/// <see cref="Algebraic.Fp256ReedSolomon"/>).
/// </summary>
/// <param name="evaluations"><c>M</c> canonical scalars; the first <c>N</c> are the inputs.</param>
internal delegate void RowInterpolateDelegate(Span<byte> evaluations);
