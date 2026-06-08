using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Evaluates a univariate polynomial in coefficient form at a single
/// scalar point.
/// </summary>
/// <param name="coefficients">The <c>degree + 1</c> coefficients in canonical big-endian byte order, low-degree first: <c>c_0, c_1, ..., c_degree</c>.</param>
/// <param name="point">The evaluation point in canonical big-endian byte order; length equals one field element.</param>
/// <param name="result">The destination span the backend writes the canonical-form scalar result into.</param>
/// <param name="degree">The storage degree of the polynomial; <c>coefficients</c> carries <c>degree + 1</c> elements.</param>
/// <param name="curve">Identifies the field whose order the arithmetic is reduced modulo.</param>
/// <remarks>
/// <para>
/// The intended implementation is Horner's scheme:
/// <c>((c_degree · x + c_{degree-1}) · x + ... + c_1) · x + c_0</c>,
/// which evaluates with <c>degree</c> multiplications and <c>degree</c>
/// additions on the field. A backend may instead unroll a Pippenger-like
/// dot-product against precomputed powers of <c>x</c>, but it must
/// produce the same reduced scalar.
/// </para>
/// <para>
/// Storage degree is distinct from algebraic degree: a polynomial with
/// <paramref name="degree"/> <c>= 5</c> but <c>c_5 = 0</c> is algebraically
/// degree 4 or less. The evaluate delegate does not need to special-case
/// leading-zero coefficients — Horner's scheme handles them implicitly.
/// </para>
/// </remarks>
public delegate void PolynomialEvaluateDelegate(
    ReadOnlySpan<byte> coefficients,
    ReadOnlySpan<byte> point,
    Span<byte> result,
    int degree,
    CurveParameterSet curve);