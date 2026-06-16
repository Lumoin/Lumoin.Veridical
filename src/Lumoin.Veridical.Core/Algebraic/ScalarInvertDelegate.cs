using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form multiplicative inverse of a non-zero scalar
/// over the curve identified by <paramref name="curve"/>, writing the result
/// into <paramref name="result"/>.
/// </summary>
/// <param name="a">The operand in canonical big-endian byte layout. Must be non-zero in the supplied curve's scalar field; behaviour for zero input is backend-defined.</param>
/// <param name="result">The destination span the backend writes the canonical-form multiplicative inverse into.</param>
/// <param name="curve">Identifies the field whose order the result is reduced modulo.</param>
/// <remarks>
/// <para>
/// Backends typically implement inversion via Fermat's little theorem
/// (<c>a^(r-2) mod r</c>) for constant-time behaviour, or via the binary
/// extended GCD when timing predictability is unnecessary. The choice is
/// internal to the backend; the contract observed here is bytes in, bytes
/// out.
/// </para>
/// <para>
/// Application code that may call this on potentially-zero inputs should
/// guard with a zero check before dispatching, since the backend's reaction
/// to a zero input — throw, return zero, return one, undefined — is not
/// uniform across implementations.
/// </para>
/// </remarks>
public delegate void ScalarInvertDelegate(
    ReadOnlySpan<byte> a,
    Span<byte> result,
    CurveParameterSet curve);