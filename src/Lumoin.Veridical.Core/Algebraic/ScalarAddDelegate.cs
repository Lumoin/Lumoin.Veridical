using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form sum of two scalars over the curve identified
/// by <paramref name="curve"/>, writing the result into
/// <paramref name="result"/>.
/// </summary>
/// <param name="a">The left operand in canonical big-endian byte layout.</param>
/// <param name="b">The right operand in canonical big-endian byte layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form sum into.</param>
/// <param name="curve">Identifies the field whose order the result is reduced modulo.</param>
/// <remarks>
/// <para>
/// The destination span must have the canonical byte length for the supplied
/// curve's scalar field — for BLS12-381, 32 bytes. A correct backend reduces
/// the result modulo the field order before writing.
/// </para>
/// <para>
/// This is an inner-loop arithmetic delegate. It does not stamp provenance
/// onto a tag, does not return a <c>CryptoEvent</c>, and does not allocate.
/// All those concerns belong to boundary operations (entropy sampling, hash
/// to field, deserialisation), not to per-operation arithmetic that runs
/// thousands of times inside a single multi-scalar multiplication or
/// polynomial evaluation.
/// </para>
/// </remarks>
public delegate void ScalarAddDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);