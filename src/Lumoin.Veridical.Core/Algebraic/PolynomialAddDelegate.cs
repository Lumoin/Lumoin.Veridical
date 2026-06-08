using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Adds two univariate polynomials of the same storage degree
/// coefficient-wise, writing the canonical-form sum into
/// <paramref name="result"/>.
/// </summary>
/// <param name="a">The left polynomial's coefficients in canonical big-endian byte order, low-degree first; carries <c>degree + 1</c> elements.</param>
/// <param name="b">The right polynomial's coefficients, same layout and length as <paramref name="a"/>.</param>
/// <param name="result">The destination span the backend writes the canonical-form sum into; carries <c>degree + 1</c> elements.</param>
/// <param name="degree">The shared storage degree; both inputs and the output carry <c>degree + 1</c> coefficients.</param>
/// <param name="curve">Identifies the field whose order the arithmetic is reduced modulo.</param>
/// <remarks>
/// <para>
/// Output coefficient <c>i</c> is <c>(a[i] + b[i]) mod r</c> for every
/// <c>i ∈ [0, degree]</c>. This is structurally the batched version of
/// <see cref="ScalarAddDelegate"/> at <c>degree + 1</c> independent
/// scalar additions.
/// </para>
/// <para>
/// The two inputs must share storage degree; if a caller wants to add
/// polynomials of different storage degrees, the caller pads the shorter
/// one with zero coefficients before calling. The delegate does not
/// perform the padding internally — that would require allocating, and
/// allocation belongs at the caller boundary where the
/// <see cref="Memory.SensitiveMemoryPool{T}"/> is in scope.
/// </para>
/// </remarks>
public delegate void PolynomialAddDelegate(
    ReadOnlySpan<byte> a,
    ReadOnlySpan<byte> b,
    Span<byte> result,
    int degree,
    CurveParameterSet curve);