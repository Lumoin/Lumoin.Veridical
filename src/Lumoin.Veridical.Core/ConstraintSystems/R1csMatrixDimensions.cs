namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Describes the shape of a single R1CS matrix in sparse-COO form.
/// </summary>
/// <param name="RowCount">The number of rows; should equal the constraint count of the parent instance.</param>
/// <param name="ColumnCount">The number of columns; should equal the variable count of the parent instance.</param>
/// <param name="NonzeroCount">The number of non-zero entries actually stored.</param>
/// <remarks>
/// Carried in the matrix's Tag so cross-matrix dimension validation
/// (every matrix in an R1CS instance must have the same row and column
/// count) can read the shape without inspecting the buffer.
/// </remarks>
public readonly record struct R1csMatrixDimensions(
    int RowCount,
    int ColumnCount,
    int NonzeroCount);