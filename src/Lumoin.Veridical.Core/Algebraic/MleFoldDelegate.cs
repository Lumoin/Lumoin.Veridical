using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Folds one variable of a dense multilinear extension against a scalar
/// challenge, producing the MLE in one fewer variable.
/// </summary>
/// <param name="originalEvaluations">The <c>2^variableCount</c> evaluations of the source MLE, laid out as one field element per slot in canonical big-endian byte order.</param>
/// <param name="challenge">The scalar challenge <c>c</c> in canonical big-endian byte order; length equals one field element.</param>
/// <param name="foldedEvaluations">The destination span the backend writes the <c>2^(variableCount-1)</c> folded evaluations into.</param>
/// <param name="variableCount">The number of variables of the source MLE. The output MLE has <c>variableCount - 1</c> variables.</param>
/// <param name="curve">Identifies the field whose order the arithmetic is reduced modulo.</param>
/// <remarks>
/// <para>
/// The folding identity for an MLE <c>f</c> in <c>n</c> variables at
/// challenge <c>c</c> is, for every <c>(x_2, ..., x_n) ∈ {0,1}^(n-1)</c>:
/// </para>
/// <code>
/// f_folded(x_2, ..., x_n) = (1 - c) · f(0, x_2, ..., x_n)
///                         + c · f(1, x_2, ..., x_n)
/// </code>
/// <para>
/// Dense form pairs evaluations by their first-variable index: the
/// element at offset <c>2i</c> is <c>f(0, ...)</c> and the element at
/// offset <c>2i + 1</c> is <c>f(1, ...)</c>. The fold computes
/// <c>2^(n-1)</c> linear interpolations, one per pair.
/// </para>
/// <para>
/// This is the inner loop of every sumcheck-based proof system; the
/// reviewer's intent is that backends vectorise it (lane-interleaved
/// pairs, two field-multiplications and one add per output slot). A
/// correct backend reduces every output element modulo the field order
/// before writing.
/// </para>
/// </remarks>
public delegate void MleFoldDelegate(
    ReadOnlySpan<byte> originalEvaluations,
    ReadOnlySpan<byte> challenge,
    Span<byte> foldedEvaluations,
    int variableCount,
    CurveParameterSet curve);