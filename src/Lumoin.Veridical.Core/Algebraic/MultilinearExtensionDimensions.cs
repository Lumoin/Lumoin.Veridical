namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Carries the two integers that describe the shape of a dense
/// <see cref="MultilinearExtension"/>: the number of boolean-hypercube
/// variables <c>n</c> and the resulting <c>2^n</c> evaluations.
/// </summary>
/// <param name="VariableCount">The number of variables <c>n</c>.</param>
/// <param name="EvaluationCount">The number of evaluations <c>2^n</c>.</param>
/// <remarks>
/// <para>
/// Surfaced as a value in the MLE's <see cref="Tag"/> so consumers can
/// read the dimensions without unwrapping the leaf type. Tooling that
/// formats reports, dispatches by shape, or validates protocol arity
/// against the MLE's underlying buffer pulls this entry rather than
/// re-deriving <c>2^n</c> from a freshly observed VariableCount each time.
/// </para>
/// <para>
/// The two fields are redundant on purpose: <c>EvaluationCount</c> is
/// always <c>1 &lt;&lt; VariableCount</c>, but holding both makes the value
/// self-explanatory at every consumer site.
/// </para>
/// </remarks>
public readonly record struct MultilinearExtensionDimensions(
    int VariableCount,
    int EvaluationCount);