using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Reduces an arbitrary-length input byte sequence modulo the supplied curve's
/// scalar field order, writing the canonical-form result into
/// <paramref name="result"/>.
/// </summary>
/// <param name="input">Source bytes interpreted as a big-endian unsigned integer. May be any non-zero length.</param>
/// <param name="result">The destination span the backend writes the canonical-form reduced scalar into.</param>
/// <param name="curve">Identifies the field whose order the result is reduced modulo.</param>
/// <remarks>
/// <para>
/// A 32-byte input for BLS12-381 produces a valid scalar but with a small bias
/// toward small values, because the input range is only slightly wider than
/// the field order. Hash-to-field constructions per RFC 9380 use wider input
/// (typically 48 bytes for BLS12-381 at 128-bit security) so that the
/// modular reduction does not bias the result distribution. Callers requiring
/// uniformly-distributed scalars must supply input wide enough to absorb the
/// reduction bias; callers requiring only validity may use input the same
/// width as the field.
/// </para>
/// <para>
/// This is a transformation delegate — it does not stamp provenance and does
/// not allocate. Provenance for hash-to-field constructions belongs to a
/// dedicated hash-to-field delegate that this one composes with, not to the
/// reduction step alone.
/// </para>
/// </remarks>
public delegate void ScalarReduceDelegate(
    ReadOnlySpan<byte> input,
    Span<byte> result,
    CurveParameterSet curve);