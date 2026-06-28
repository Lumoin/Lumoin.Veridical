using Lumoin.Veridical.Core.ConstraintSystems;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// A view onto an <see cref="R1csMatrix"/> that supplies its
/// multilinear-extension evaluation surface. The matrix MLE
/// <c>A~ : F^(ℓ_y + ℓ_x) → F</c> interprets the sparse-COO matrix as
/// a function over the boolean hypercube
/// <c>{0,1}^(ℓ_y + ℓ_x)</c> with
/// <c>A~(bits(i), bits(j)) = A[i,j]</c>, and is uniquely extended to
/// the full field domain by multilinear interpolation.
/// </summary>
/// <remarks>
/// <para>
/// This type does not own the matrix's buffer; the caller manages the
/// <see cref="R1csMatrix"/>'s lifetime. The view exists to give the
/// MLE-evaluation operation surface its own discoverable home and to
/// hold any future per-view caches (precomputed row-equality vectors,
/// for instance) without polluting the constraint-system layer.
/// </para>
/// <para>
/// The matrix must have <see cref="R1csMatrix.RowCount"/> and
/// <see cref="R1csMatrix.ColumnCount"/> both powers of two. Spartan
/// pads the underlying R1CS instance to power-of-two dimensions before
/// constructing this view; the constructor enforces the precondition.
/// </para>
/// <para>
/// <b>Composability note.</b> Both
/// <see cref="MatrixMleEvaluationExtensions.Evaluate"/> and
/// <see cref="MatrixMleEvaluationExtensions.EvaluateRowSlice"/>
/// internally compose scalar add / subtract / multiply delegates per
/// non-zero triple — a fine-grained pattern that suits a CPU backend
/// where each scalar op is microseconds. A future batched/GPU backend
/// would want to push this entire loop onto the substrate (one kernel
/// per <c>EvaluateRowSlice</c> call), not interleave per-op delegate
/// dispatch with kernel launches. When that batching seam lands, it
/// belongs at this layer — a dedicated
/// <c>MatrixMleEvaluateDelegate</c> or similar — not inside the
/// scalar-op delegates.
/// </para>
/// </remarks>
public sealed class MatrixMleEvaluation
{
    /// <summary>The underlying sparse matrix. Lifetime is owned by the caller.</summary>
    public R1csMatrix Matrix { get; }

    /// <summary>The number of variables addressing rows: <c>ℓ_y = log_2(Matrix.RowCount)</c>.</summary>
    public int RowVariableCount { get; }

    /// <summary>The number of variables addressing columns: <c>ℓ_x = log_2(Matrix.ColumnCount)</c>.</summary>
    public int ColumnVariableCount { get; }

    /// <summary>The runtime tag identifying this view.</summary>
    public Tag Tag { get; }


    /// <summary>
    /// Wraps <paramref name="matrix"/> in a matrix-MLE evaluation view.
    /// The matrix dimensions must both be powers of two.
    /// </summary>
    /// <param name="matrix">The sparse matrix to view as an MLE. The caller retains ownership.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="matrix"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the matrix has a row or column count that is not a power of two.</exception>
    public MatrixMleEvaluation(R1csMatrix matrix)
    {
        ArgumentNullException.ThrowIfNull(matrix);

        if(!BitOperations.IsPow2(matrix.RowCount))
        {
            throw new ArgumentException(
                $"MatrixMleEvaluation requires a power-of-two row count; received {matrix.RowCount}. Pad the underlying R1CS instance to a power-of-two row count before constructing this view.",
                nameof(matrix));
        }

        if(!BitOperations.IsPow2(matrix.ColumnCount))
        {
            throw new ArgumentException(
                $"MatrixMleEvaluation requires a power-of-two column count; received {matrix.ColumnCount}.",
                nameof(matrix));
        }

        Matrix = matrix;
        RowVariableCount = BitOperations.Log2((uint)matrix.RowCount);
        ColumnVariableCount = BitOperations.Log2((uint)matrix.ColumnCount);

        Tag = Tag.Create(AlgebraicRole.MultilinearExtension)
            .With(matrix.Curve);
    }
}