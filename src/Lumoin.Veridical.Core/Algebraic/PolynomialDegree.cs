namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Carries the storage degree of a univariate <see cref="Polynomial"/> —
/// the index of the highest-degree coefficient slot, with
/// <c>Value + 1</c> coefficients stored in total.
/// </summary>
/// <param name="Value">The storage degree; <c>Value + 1</c> coefficient slots are present.</param>
/// <remarks>
/// <para>
/// Surfaced as a value in the polynomial's <see cref="Tag"/> so consumers
/// can read the degree without unwrapping the leaf type.
/// </para>
/// <para>
/// Storage degree is distinct from algebraic degree: a polynomial with
/// storage degree <c>d</c> may have its leading coefficient be zero, in
/// which case its algebraic degree is strictly less than <c>d</c>. The
/// distinction matters for arithmetic — the multiply delegate's result
/// always has storage degree <c>dA + dB</c> even when the algebraic-degree
/// product is smaller — and is the reason polynomial inspection surfaces
/// reports both the storage degree and the predicates
/// <c>IsConstant</c> / <c>IsLinear</c> that look at the actual coefficient
/// pattern.
/// </para>
/// </remarks>
public readonly record struct PolynomialDegree(int Value);