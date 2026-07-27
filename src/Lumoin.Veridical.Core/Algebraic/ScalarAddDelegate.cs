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
/// The destination span must have the canonical byte length of the field the
/// specific delegate instance carries. For a scalar-field backend that is the
/// curve's scalar field — for BLS12-381, 32 bytes — but the same delegate type
/// also carries base-field and extension-field arithmetic for the constant-time
/// ladders (48-byte BLS12-381 base-field elements, 96-byte Fp2 elements), so
/// the element length follows from the factory that produced the instance, not
/// from the curve alone. A correct backend reduces the result modulo its
/// field's order before writing.
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