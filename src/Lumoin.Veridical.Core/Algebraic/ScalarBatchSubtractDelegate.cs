using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form difference of <paramref name="count"/>
/// pairs of scalars over the curve identified by <paramref name="curve"/>,
/// writing the results into <paramref name="resultsConcatenated"/>.
/// </summary>
/// <param name="minuendsConcatenated">The minuends laid out as one contiguous span: <paramref name="count"/> canonical big-endian scalar encodings appended back to back.</param>
/// <param name="subtrahendsConcatenated">The subtrahends, in the same layout.</param>
/// <param name="resultsConcatenated">The destination span the backend writes the canonical-form differences into, in the same layout.</param>
/// <param name="count">The number of scalar pairs.</param>
/// <param name="curve">Identifies the field whose order the results are reduced modulo.</param>
/// <remarks>
/// Same shape as <see cref="ScalarBatchAddDelegate"/>. See its remarks for
/// the rationale behind batched delegates in addition to the
/// single-element <see cref="ScalarSubtractDelegate"/>.
/// </remarks>
public delegate void ScalarBatchSubtractDelegate(
    ReadOnlySpan<byte> minuendsConcatenated,
    ReadOnlySpan<byte> subtrahendsConcatenated,
    Span<byte> resultsConcatenated,
    int count,
    CurveParameterSet curve);