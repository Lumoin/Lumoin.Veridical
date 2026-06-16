using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes the canonical-form sum of two Fp2 extension-field elements
/// over the curve identified by <paramref name="curve"/>, writing the
/// result into <paramref name="result"/>.
/// </summary>
/// <param name="a">The left operand in canonical <c>[c0 : 48 bytes][c1 : 48 bytes]</c> layout.</param>
/// <param name="b">The right operand in the same layout.</param>
/// <param name="result">The destination span the backend writes the canonical-form sum into.</param>
/// <param name="curve">Identifies the field whose order the components are reduced modulo.</param>
/// <remarks>
/// Addition in Fp2 is componentwise: <c>(a0 + a1·u) + (b0 + b1·u) = (a0 + b0) + (a1 + b1)·u</c>.
/// A correct backend reduces each component modulo the BLS12-381 base
/// field prime before writing.
/// </remarks>
public delegate void Fp2AddDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    CurveParameterSet curve);