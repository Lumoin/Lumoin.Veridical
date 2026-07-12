using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// An R1CS coefficient matrix in sparse coordinate (COO) form.
/// Stores <see cref="NonzeroCount"/> non-zero entries as three
/// parallel arrays: row indices, column indices, and field-element
/// values. Triples are sorted lexicographically by <c>(row, column)</c>
/// so satisfaction checking can iterate them in row-major order
/// without resorting.
/// </summary>
/// <remarks>
/// <para>
/// Buffer layout, in order:
/// </para>
/// <list type="number">
///   <item><description>Row indices: <c>NonzeroCount</c> 4-byte big-endian <see cref="int"/>s.</description></item>
///   <item><description>Column indices: <c>NonzeroCount</c> 4-byte big-endian <see cref="int"/>s.</description></item>
///   <item><description>Values: <c>NonzeroCount</c> canonical big-endian scalars (32 bytes each for BLS12-381).</description></item>
/// </list>
/// <para>
/// Big-endian index storage means the same matrix bytes are reproducible
/// across platforms; the transcript-absorb path consumes the bytes as
/// stored, so prover and verifier on different ISAs see identical hash
/// inputs.
/// </para>
/// <para>
/// The type is broad: one <see cref="R1csMatrix"/> can hold a matrix
/// over any curve, with the curve carried in the Tag. BLS12-381 and
/// BN254 are wired; further curves add their own scalar size to
/// <see cref="GetValueByteSize"/>.
/// </para>
/// </remarks>
public sealed class R1csMatrix: SensitiveMemory
{
    private const int IndexByteSize = sizeof(int);


    /// <summary>The number of rows in the matrix (matches the constraint count of the parent R1CS instance).</summary>
    public int RowCount { get; }

    /// <summary>The number of columns (matches the variable count <c>n</c> of the parent instance).</summary>
    public int ColumnCount { get; }

    /// <summary>The number of stored non-zero entries.</summary>
    public int NonzeroCount { get; }

    /// <summary>The curve identifying the scalar field the values live in.</summary>
    public CurveParameterSet Curve { get; }


    internal R1csMatrix(
        IMemoryOwner<byte> owner,
        int rowCount,
        int columnCount,
        int nonzeroCount,
        CurveParameterSet curve,
        Tag tag)
        : base(owner, tag)
    {
        RowCount = rowCount;
        ColumnCount = columnCount;
        NonzeroCount = nonzeroCount;
        Curve = curve;
    }


    /// <summary>
    /// Constructs a sparse matrix from caller-supplied parallel arrays
    /// of row indices, column indices, and canonical scalar values.
    /// </summary>
    /// <param name="rowIndices">The row of each non-zero, length <c>nnz</c>.</param>
    /// <param name="columnIndices">The column of each non-zero, length <c>nnz</c>.</param>
    /// <param name="values">Canonical big-endian bytes of the values, length <c>nnz · scalarSizeBytes</c>.</param>
    /// <param name="rowCount">The number of rows.</param>
    /// <param name="columnCount">The number of columns.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">Optional caller-supplied Tag merged with the algebraic-identity entries.</param>
    /// <exception cref="ArgumentException">When the triples are out of order, indices are out of range, the array lengths disagree, or the curve is unsupported.</exception>
    public static R1csMatrix FromSortedTriples(
        ReadOnlySpan<int> rowIndices,
        ReadOnlySpan<int> columnIndices,
        ReadOnlySpan<byte> values,
        int rowCount,
        int columnCount,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rowCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(columnCount);

        int scalarSize = GetValueByteSize(curve);
        int nnz = rowIndices.Length;

        if(nnz <= 0)
        {
            throw new ArgumentException(
                "R1csMatrix requires at least one non-zero entry; an all-zero matrix has no useful encoding in COO form.",
                nameof(rowIndices));
        }

        if(columnIndices.Length != nnz)
        {
            throw new ArgumentException(
                $"columnIndices has length {columnIndices.Length}; must match rowIndices length {nnz}.",
                nameof(columnIndices));
        }

        if(values.Length != nnz * scalarSize)
        {
            throw new ArgumentException(
                $"values has length {values.Length}; expected {nnz * scalarSize} ({nnz} × {scalarSize}).",
                nameof(values));
        }

        ValidateTriplesSortedAndInRange(rowIndices, columnIndices, rowCount, columnCount);

        //Reject non-canonical field elements at the construction boundary: every
        //interop reader (Circom .r1cs, ZkInterface) funnels through here, and a
        //value at or above the order would diverge between its transcript-absorb
        //bytes and its reduced arithmetic value.
        for(int i = 0; i < nnz; i++)
        {
            if(!WellKnownCurves.IsCanonicalScalar(values.Slice(i * scalarSize, scalarSize), curve))
            {
                throw new ArgumentException(
                    $"Matrix value at triple {i} (row {rowIndices[i]}, column {columnIndices[i]}) encodes an integer at or above the scalar field order of {curve}.",
                    nameof(values));
            }
        }

        int bufferSize = ComputeBufferSize(nnz, curve);
        IMemoryOwner<byte> owner = pool.Rent(bufferSize);
        Span<byte> buffer = owner.Memory.Span[..bufferSize];

        WriteIntsBigEndian(rowIndices, buffer[..(nnz * IndexByteSize)]);
        WriteIntsBigEndian(columnIndices, buffer.Slice(nnz * IndexByteSize, nnz * IndexByteSize));
        values.CopyTo(buffer.Slice(2 * nnz * IndexByteSize, nnz * scalarSize));

        var dimensions = new R1csMatrixDimensions(rowCount, columnCount, nnz);
        Tag effectiveTag = tag is null
            ? ComposeAlgebraicTag(dimensions, curve)
            : MergeWithAlgebraicTag(tag, dimensions, curve);

        CryptographicOperationCounters.Increment(CryptographicOperationKind.R1csConstructMatrix, curve);
        return new R1csMatrix(owner, rowCount, columnCount, nnz, curve, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the row-index array — <c>NonzeroCount × 4</c> bytes big-endian.</summary>
    public ReadOnlySpan<byte> GetRowIndicesBytes()
    {
        return AsReadOnlySpan()[..(NonzeroCount * IndexByteSize)];
    }


    /// <summary>Returns the canonical bytes of the column-index array.</summary>
    public ReadOnlySpan<byte> GetColumnIndicesBytes()
    {
        return AsReadOnlySpan().Slice(NonzeroCount * IndexByteSize, NonzeroCount * IndexByteSize);
    }


    /// <summary>Returns the canonical bytes of the value array — <c>NonzeroCount × scalarSize</c> bytes.</summary>
    public ReadOnlySpan<byte> GetValuesBytes()
    {
        int scalarSize = GetValueByteSize(Curve);
        return AsReadOnlySpan().Slice(2 * NonzeroCount * IndexByteSize, NonzeroCount * scalarSize);
    }


    /// <summary>Reads the <paramref name="index"/>'th row-column pair from the matrix's stored arrays.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is outside <c>[0, NonzeroCount)</c>.</exception>
    public (int Row, int Column) GetTriplePosition(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, NonzeroCount);

        int row = BinaryPrimitives.ReadInt32BigEndian(GetRowIndicesBytes().Slice(index * IndexByteSize, IndexByteSize));
        int column = BinaryPrimitives.ReadInt32BigEndian(GetColumnIndicesBytes().Slice(index * IndexByteSize, IndexByteSize));
        return (row, column);
    }


    /// <summary>Returns a span over the <paramref name="index"/>'th stored value (32 bytes for BLS12-381).</summary>
    public ReadOnlySpan<byte> GetValueBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, NonzeroCount);

        int scalarSize = GetValueByteSize(Curve);
        return GetValuesBytes().Slice(index * scalarSize, scalarSize);
    }


    /// <summary>Returns the total buffer size in bytes for the supplied non-zero count and curve.</summary>
    public static int ComputeBufferSize(int nonzeroCount, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(nonzeroCount);
        int scalarSize = GetValueByteSize(curve);
        return (2 * IndexByteSize + scalarSize) * nonzeroCount;
    }


    /// <summary>Returns the canonical scalar-field byte size for the supplied curve. Throws for unsupported curves.</summary>
    internal static int GetValueByteSize(CurveParameterSet curve)
    {
        if(curve.Code == CurveParameterSet.Bls12Curve381.Code)
        {
            return WellKnownCurves.Bls12Curve381ScalarSizeBytes;
        }

        if(curve.Code == CurveParameterSet.Bn254.Code)
        {
            return WellKnownCurves.Bn254ScalarSizeBytes;
        }

        throw new ArgumentException(
            $"R1csMatrix supports Bls12Curve381 or Bn254; received {curve}.",
            nameof(curve));
    }


    private static void ValidateTriplesSortedAndInRange(
        ReadOnlySpan<int> rowIndices,
        ReadOnlySpan<int> columnIndices,
        int rowCount,
        int columnCount)
    {
        for(int i = 0; i < rowIndices.Length; i++)
        {
            int row = rowIndices[i];
            int column = columnIndices[i];

            if((uint)row >= (uint)rowCount)
            {
                throw new ArgumentException(
                    $"Triple at index {i.ToString(CultureInfo.InvariantCulture)} has row {row}; must be in [0, {rowCount}).",
                    nameof(rowIndices));
            }

            if((uint)column >= (uint)columnCount)
            {
                throw new ArgumentException(
                    $"Triple at index {i.ToString(CultureInfo.InvariantCulture)} has column {column}; must be in [0, {columnCount}).",
                    nameof(columnIndices));
            }

            if(i > 0)
            {
                int previousRow = rowIndices[i - 1];
                int previousColumn = columnIndices[i - 1];
                bool strictlyIncreasing = row > previousRow || (row == previousRow && column > previousColumn);
                if(!strictlyIncreasing)
                {
                    throw new ArgumentException(
                        $"Triples must be strictly ascending by (row, column); at index {i.ToString(CultureInfo.InvariantCulture)} ({row}, {column}) does not follow ({previousRow}, {previousColumn}).",
                        nameof(rowIndices));
                }
            }
        }
    }


    private static void WriteIntsBigEndian(ReadOnlySpan<int> source, Span<byte> destination)
    {
        for(int i = 0; i < source.Length; i++)
        {
            BinaryPrimitives.WriteInt32BigEndian(destination.Slice(i * IndexByteSize, IndexByteSize), source[i]);
        }
    }


    private static Tag ComposeAlgebraicTag(R1csMatrixDimensions dimensions, CurveParameterSet curve)
    {
        return Tag.Create(AlgebraicRole.R1csMatrix)
            .With(curve)
            .With(dimensions);
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, R1csMatrixDimensions dimensions, CurveParameterSet curve)
    {
        return tag.With(AlgebraicRole.R1csMatrix)
            .With(curve)
            .With(dimensions);
    }
}