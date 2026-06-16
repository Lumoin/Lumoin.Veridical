using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form product of two scalars over the curve
/// identified by <paramref name="curve"/>, writing the result into
/// <paramref name="result"/>.
/// </summary>
/// <param name="a">The left factor in canonical big-endian byte layout.</param>
/// <param name="b">The right factor in canonical big-endian byte layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form product into.</param>
/// <param name="curve">Identifies the field whose order the result is reduced modulo.</param>
/// <remarks>
/// <para>
/// Backends commonly perform multiplication in Montgomery form and convert
/// back to canonical form on output. The conversion is internal to the
/// backend; the wire-level contract observed at this delegate is canonical
/// big-endian bytes in, canonical big-endian bytes out.
/// </para>
/// </remarks>
public delegate void ScalarMultiplyDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);