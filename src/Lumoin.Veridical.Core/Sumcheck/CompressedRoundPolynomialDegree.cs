namespace Lumoin.Veridical.Core.Sumcheck;

/// <summary>
/// Carries the algebraic degree of a
/// <see cref="CompressedRoundPolynomial"/>. A degree-<c>d</c> compressed
/// round polynomial stores <c>d</c> field elements (the constant term
/// followed by the quadratic and higher terms; the linear term is
/// elided).
/// </summary>
/// <param name="Value">The algebraic degree of the original (uncompressed) polynomial; must be at least 2.</param>
/// <remarks>
/// <para>
/// Surfaced as a value in the compressed polynomial's <see cref="Tag"/>
/// so consumers can read the degree without unwrapping the leaf type.
/// </para>
/// <para>
/// Distinct from <see cref="Algebraic.PolynomialDegree"/> because the
/// two reflect different layouts: a regular polynomial of degree
/// <c>d</c> stores <c>d + 1</c> coefficients in their natural order;
/// a compressed round polynomial of degree <c>d</c> stores <c>d</c>
/// coefficients in the order <c>(c_0, c_2, c_3, ..., c_d)</c>.
/// </para>
/// </remarks>
public readonly record struct CompressedRoundPolynomialDegree(int Value);