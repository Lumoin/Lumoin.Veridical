using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form sum of scalar multiples
/// <c>sum_i scalars[i] * points[i]</c> over the curve identified by
/// <paramref name="curve"/>, writing the result into <paramref name="result"/>.
/// </summary>
/// <param name="pointsConcatenated">The G1 points laid out as one contiguous span: <c>count</c> compressed point encodings appended back to back.</param>
/// <param name="scalarsConcatenated">The scalars laid out as one contiguous span: <c>count</c> canonical big-endian scalar encodings appended back to back.</param>
/// <param name="count">The number of (point, scalar) pairs.</param>
/// <param name="result">The destination span the backend writes the canonical-form sum into.</param>
/// <param name="curve">Identifies the curve the points and scalars live over.</param>
/// <remarks>
/// <para>
/// Spans of spans do not exist in C#, so the parallel arrays of points and
/// scalars cross the delegate boundary as flattened buffers plus a count. The
/// backend knows its own <c>SizeBytes</c> values and slices accordingly. For
/// BLS12-381 each point is <c>WellKnownCurves.Bls12Curve381G1CompressedSizeBytes</c> (48) bytes
/// and each scalar is <c>Scalar.SizeBytes</c> (32) bytes; a
/// correct backend validates the buffer lengths against the supplied
/// <paramref name="count"/> and throws on mismatch.
/// </para>
/// <para>
/// Multi-scalar multiplication is the dominant cost in most pairing-based
/// proof systems. Backends implement it via Pippenger's algorithm or one of
/// its variants for asymptotic speed-up over <c>count</c> independent
/// scalar multiplications. The contract observed at this delegate is the
/// same canonical-bytes-in, canonical-bytes-out shape used by the
/// single-operand delegates.
/// </para>
/// </remarks>
public delegate void G1MultiScalarMultiplyDelegate(
    ReadOnlySpan<byte> pointsConcatenated,
    ReadOnlySpan<byte> scalarsConcatenated,
    int count,
    Span<byte> result,
    CurveParameterSet curve);