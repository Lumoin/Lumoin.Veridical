using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The matrix and code dimensions of a Ligero polynomial-commitment evaluation
/// argument, derived solely from the polynomial's variable count, the inverse
/// code rate and the requested query count. Prover and verifier each derive an
/// identical instance (the verifier from <c>evaluationPoint.Length</c>), so no
/// dimension data travels on the wire.
/// </summary>
/// <param name="VariableCount">The polynomial's variable count <c>d</c> (<c>2^d</c> evaluations).</param>
/// <param name="RowVariableCount">The number of variables addressing rows, <c>⌈d/2⌉</c>.</param>
/// <param name="ColumnVariableCount">The number of variables addressing columns, <c>⌊d/2⌋</c>.</param>
/// <param name="RowCount">The number of matrix rows, <c>2^RowVariableCount</c>.</param>
/// <param name="ColumnCount">The number of matrix columns (the RS message length), <c>2^ColumnVariableCount</c>.</param>
/// <param name="CodewordLength">The RS codeword length per row, <c>InverseRate · ColumnCount</c>.</param>
/// <param name="ExtensionWidth">The number of committed (extension) columns, <c>CodewordLength − ColumnCount</c>.</param>
/// <param name="PaddedLeafCount">The Merkle leaf count, <see cref="ExtensionWidth"/> rounded up to a power of two.</param>
/// <param name="PathDepth">The Merkle authentication-path depth, <c>log2(PaddedLeafCount)</c>.</param>
/// <param name="OpenedColumnCount">The number of opened columns actually used, <c>min(queryCount, ExtensionWidth)</c>.</param>
/// <remarks>
/// The row/column split is row-major and matches the Hyrax convention
/// (<c>RowCount = 2^⌈d/2⌉</c>, <c>ColumnCount = 2^⌊d/2⌋</c>, matrix entry
/// <c>M[i][j]</c> at storage index <c>i·ColumnCount + j</c>); the column index
/// is the lower <c>⌊d/2⌋</c> bits of the storage index. Only the extension
/// columns are committed and opened, so every barycentric evaluation point is at
/// node <c>ColumnCount + idx ≥ ColumnCount</c> and never coincides with a
/// message node.
/// </remarks>
public readonly record struct LigeroEvaluationDimensions(
    int VariableCount,
    int RowVariableCount,
    int ColumnVariableCount,
    int RowCount,
    int ColumnCount,
    int CodewordLength,
    int ExtensionWidth,
    int PaddedLeafCount,
    int PathDepth,
    int OpenedColumnCount)
{
    /// <summary>
    /// Derives the dimensions for a <paramref name="variableCount"/>-variable
    /// polynomial under the given inverse rate and requested query count.
    /// </summary>
    /// <param name="variableCount">The polynomial's variable count <c>d ≥ 0</c>.</param>
    /// <param name="inverseRate">The inverse code rate <c>≥ 2</c> (so at least one extension column exists).</param>
    /// <param name="queryCount">The requested opened-column count <c>≥ 1</c>; clamped down to the extension width.</param>
    /// <exception cref="ArgumentOutOfRangeException">When a parameter is out of range.</exception>
    public static LigeroEvaluationDimensions ForVariableCount(int variableCount, int inverseRate, int queryCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(variableCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(inverseRate, 2);
        ArgumentOutOfRangeException.ThrowIfLessThan(queryCount, 1);

        int rowVariableCount = (variableCount + 1) / 2;
        int columnVariableCount = variableCount / 2;
        int rowCount = 1 << rowVariableCount;
        int columnCount = 1 << columnVariableCount;
        int codewordLength = inverseRate * columnCount;
        int extensionWidth = codewordLength - columnCount;
        int paddedLeafCount = (int)BitOperations.RoundUpToPowerOf2((uint)extensionWidth);
        int pathDepth = BitOperations.Log2((uint)paddedLeafCount);
        int openedColumnCount = Math.Min(queryCount, extensionWidth);

        return new LigeroEvaluationDimensions(
            variableCount,
            rowVariableCount,
            columnVariableCount,
            rowCount,
            columnCount,
            codewordLength,
            extensionWidth,
            paddedLeafCount,
            pathDepth,
            openedColumnCount);
    }
}
