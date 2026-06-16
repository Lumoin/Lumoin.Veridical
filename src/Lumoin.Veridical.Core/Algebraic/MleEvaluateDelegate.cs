using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Evaluates a dense multilinear extension at an <c>n</c>-element point,
/// writing the resulting scalar into <paramref name="result"/>.
/// </summary>
/// <param name="evaluations">The <c>2^variableCount</c> evaluations of the MLE, laid out as one field element per slot in canonical big-endian byte order.</param>
/// <param name="point">The evaluation point: <c>variableCount</c> field elements concatenated in canonical big-endian order, one per variable.</param>
/// <param name="result">The destination span the backend writes the canonical-form scalar result into; length equals one field element.</param>
/// <param name="variableCount">The number of variables of the MLE. The point must carry exactly this many elements.</param>
/// <param name="curve">Identifies the field whose order the arithmetic is reduced modulo.</param>
/// <remarks>
/// <para>
/// The canonical algorithm is <c>variableCount</c> rounds of folding,
/// one per variable, until zero variables remain. A backend that
/// implements <see cref="MleEvaluateDelegate"/> via repeated calls to a
/// <see cref="MleFoldDelegate"/> against a single scratch buffer is
/// correct by construction; backends that fuse the folds for cache or
/// SIMD locality must produce the same final scalar.
/// </para>
/// <para>
/// On the boolean hypercube — every <c>point[i]</c> is <c>0</c> or
/// <c>1</c> — the result equals the evaluation at the corresponding
/// hypercube index, the multilinear-extension definition. Outside the
/// hypercube the result is the unique multilinear interpolation.
/// </para>
/// <para>
/// This is the boundary-of-prover entry point through which the
/// transcript-derived challenges are consumed in sumcheck-based proof
/// systems. A correct backend reduces the result modulo the field order
/// before writing.
/// </para>
/// </remarks>
public delegate void MleEvaluateDelegate(
    ReadOnlySpan<byte> evaluations,
    ReadOnlySpan<byte> point,
    Span<byte> result,
    int variableCount,
    CurveParameterSet curve);