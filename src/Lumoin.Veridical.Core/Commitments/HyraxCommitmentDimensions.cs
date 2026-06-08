namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Describes the shape of a Hyrax commitment: how the underlying
/// multilinear extension's <c>2^n</c> evaluations are decomposed into
/// a <c>RowCount × ColumnCount</c> matrix.
/// </summary>
/// <param name="VariableCount">The number of variables <c>n</c> of the MLE this commitment was constructed for.</param>
/// <param name="RowCount">The number of rows in the decomposition; <c>2^⌈n/2⌉</c>.</param>
/// <param name="ColumnCount">The number of columns; <c>2^⌊n/2⌋</c>.</param>
/// <remarks>
/// <para>
/// The decomposition convention is row-major and contiguous in the
/// underlying MLE buffer: matrix entry <c>M[i][j]</c> is the MLE
/// evaluation at storage index <c>i · ColumnCount + j</c>. Because the
/// MLE's storage-index convention has the first variable <c>b_1</c> in
/// the least-significant bit, the column index <c>j</c> is determined
/// by the lower <c>⌊n/2⌋</c> bits of the storage index — i.e., by MLE
/// variables <c>b_1 .. b_⌊n/2⌋</c> — and the row index <c>i</c> by the
/// upper <c>⌈n/2⌉</c> bits.
/// </para>
/// <para>
/// Carried in the Tag so consumers can read the matrix shape without
/// unwrapping the leaf type.
/// </para>
/// </remarks>
public readonly record struct HyraxCommitmentDimensions(
    int VariableCount,
    int RowCount,
    int ColumnCount)
{
    /// <summary>
    /// Computes the Hyrax matrix dimensions for an MLE with the
    /// supplied variable count, following the row-major convention
    /// (<c>RowCount = 2^⌈n/2⌉</c>, <c>ColumnCount = 2^⌊n/2⌋</c>).
    /// </summary>
    public static HyraxCommitmentDimensions ForVariableCount(int variableCount)
    {
        int upperHalf = (variableCount + 1) / 2;
        int lowerHalf = variableCount / 2;
        return new HyraxCommitmentDimensions(
            VariableCount: variableCount,
            RowCount: 1 << upperHalf,
            ColumnCount: 1 << lowerHalf);
    }
}