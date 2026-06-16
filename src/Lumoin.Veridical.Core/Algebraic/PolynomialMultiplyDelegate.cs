using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Multiplies two univariate polynomials in coefficient form, writing
/// the canonical-form product into <paramref name="result"/>.
/// </summary>
/// <param name="a">The left polynomial's coefficients in canonical big-endian byte order, low-degree first; carries <c>aDegree + 1</c> elements.</param>
/// <param name="aDegree">The storage degree of the left polynomial.</param>
/// <param name="b">The right polynomial's coefficients, same byte layout; carries <c>bDegree + 1</c> elements.</param>
/// <param name="bDegree">The storage degree of the right polynomial.</param>
/// <param name="result">The destination span the backend writes the canonical-form product into; carries <c>aDegree + bDegree + 1</c> elements.</param>
/// <param name="curve">Identifies the field whose order the arithmetic is reduced modulo.</param>
/// <remarks>
/// <para>
/// Result coefficient <c>k</c> is
/// <c>sum over i in [max(0, k - bDegree), min(aDegree, k)] of (a[i] · b[k - i]) mod r</c>,
/// for every <c>k ∈ [0, aDegree + bDegree]</c>. This is the schoolbook
/// <c>O((aDegree + 1)·(bDegree + 1))</c> convolution.
/// </para>
/// <para>
/// NTT- and FFT-based variants are future optimisations behind the same
/// delegate; the reference backend implements the schoolbook formula for
/// clarity and to keep the test surface independent of the optimisation
/// path. A correct backend reduces every output coefficient modulo the
/// field order.
/// </para>
/// </remarks>
public delegate void PolynomialMultiplyDelegate(
    ReadOnlySpan<byte> a,
    int aDegree,
    ReadOnlySpan<byte> b,
    int bDegree,
    Span<byte> result,
    CurveParameterSet curve);