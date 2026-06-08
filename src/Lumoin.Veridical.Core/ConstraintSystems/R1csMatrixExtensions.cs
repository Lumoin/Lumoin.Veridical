using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Matrix-vector product over sparse R1CS matrices.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class R1csMatrixExtensions
{
    extension(R1csMatrix matrix)
    {
        /// <summary>
        /// Computes <c>result = matrix · z</c> via one
        /// multiply-accumulate per non-zero triple. <paramref name="destination"/>
        /// is cleared on entry.
        /// </summary>
        /// <param name="zBytes">The input vector as <c>matrix.ColumnCount</c> canonical scalars concatenated.</param>
        /// <param name="destination">The output vector buffer; must be <c>matrix.RowCount · scalarSize</c> bytes.</param>
        /// <param name="scalarAdd">The scalar-add backend.</param>
        /// <param name="scalarMul">The scalar-multiply backend.</param>
        /// <param name="pool">The pool to rent scratch from.</param>
        public void MatrixVectorProduct(
            ReadOnlySpan<byte> zBytes,
            Span<byte> destination,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMul,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(matrix);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarMul);
            ArgumentNullException.ThrowIfNull(pool);

            int scalarSize = R1csMatrix.GetValueByteSize(matrix.Curve);
            if(zBytes.Length != matrix.ColumnCount * scalarSize)
            {
                throw new ArgumentException(
                    $"z must be {matrix.ColumnCount * scalarSize} bytes ({matrix.ColumnCount} × {scalarSize}); received {zBytes.Length}.",
                    nameof(zBytes));
            }

            if(destination.Length != matrix.RowCount * scalarSize)
            {
                throw new ArgumentException(
                    $"destination must be {matrix.RowCount * scalarSize} bytes ({matrix.RowCount} × {scalarSize}); received {destination.Length}.",
                    nameof(destination));
            }

            destination.Clear();
            CryptographicOperationCounters.Increment(CryptographicOperationKind.R1csMatrixVectorProduct, matrix.Curve);

            ReadOnlySpan<byte> rowIndicesBytes = matrix.GetRowIndicesBytes();
            ReadOnlySpan<byte> colIndicesBytes = matrix.GetColumnIndicesBytes();
            ReadOnlySpan<byte> valuesBytes = matrix.GetValuesBytes();

            using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
            Span<byte> term = termOwner.Memory.Span[..scalarSize];

            for(int i = 0; i < matrix.NonzeroCount; i++)
            {
                int row = BinaryPrimitives.ReadInt32BigEndian(rowIndicesBytes.Slice(i * sizeof(int), sizeof(int)));
                int col = BinaryPrimitives.ReadInt32BigEndian(colIndicesBytes.Slice(i * sizeof(int), sizeof(int)));
                ReadOnlySpan<byte> value = valuesBytes.Slice(i * scalarSize, scalarSize);
                ReadOnlySpan<byte> zCol = zBytes.Slice(col * scalarSize, scalarSize);

                scalarMul(value, zCol, term, matrix.Curve);
                Span<byte> resultRow = destination.Slice(row * scalarSize, scalarSize);
                scalarAdd(resultRow, term, resultRow, matrix.Curve);
            }
        }
    }
}