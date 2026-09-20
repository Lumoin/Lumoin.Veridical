using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for <see cref="R1csMatrix"/>: construction and its argument validation,
/// ordering validation, tag composition, operation counting, accessor bounds,
/// buffer sizing and matrix-vector product correctness.
/// </summary>
[TestClass]
internal sealed class R1csMatrixTests
{
    /// <summary>The width of one stored BLS12-381 value.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The stored entry count of a matrix built from one triple.</summary>
    private const int SingleEntryCount = 1;

    /// <summary>The stored entry count of the two-triple inputs.</summary>
    private const int TwoEntryCount = 2;

    /// <summary>The value bytes one triple needs: a single scalar.</summary>
    private const int SingleEntryValueBytes = SingleEntryCount * ScalarSize;

    /// <summary>The value bytes two triples need: two scalars.</summary>
    private const int TwoEntryValueBytes = TwoEntryCount * ScalarSize;

    /// <summary>The first row, and the first column.</summary>
    private const int FirstIndex = 0;

    /// <summary>The second row.</summary>
    private const int SecondIndex = 1;

    /// <summary>A row or column count of one, the smallest a matrix can have.</summary>
    private const int SingleDimension = 1;

    /// <summary>A row count of two, which holds the rows <see cref="FirstIndex"/> and <see cref="SecondIndex"/>.</summary>
    private const int TwoDimension = 2;

    /// <summary>A row or column count of zero, which leaves no index in range.</summary>
    private const int ZeroDimension = 0;

    /// <summary>
    /// A row or column count of minus one. The index range checks compare as unsigned values, where minus
    /// one is the largest count, so they accept the index <see cref="FirstIndex"/> against it.
    /// </summary>
    private const int NegativeDimension = -1;

    /// <summary>The row count of the boundary inputs; as a row index it names the row one past the last.</summary>
    private const int BoundaryRowCount = 2;

    /// <summary>
    /// The column count of the boundary inputs; as a column index it names the column one past the last.
    /// It differs from <see cref="BoundaryRowCount"/>, so each range message shows which bound it checked.
    /// </summary>
    private const int BoundaryColumnCount = 3;

    /// <summary>The column both triples of the repeated-position input occupy.</summary>
    private const int RepeatedColumn = 1;

    /// <summary>The column count of the repeated-position input, which keeps <see cref="RepeatedColumn"/> in range.</summary>
    private const int RepeatedPositionColumnCount = 2;

    /// <summary>A non-zero count of zero, for which no COO buffer exists.</summary>
    private const int ZeroNonzeroCount = 0;

    /// <summary>A negative non-zero count, whose COO buffer size would be negative.</summary>
    private const int NegativeNonzeroCount = -1;

    /// <summary>
    /// The most negative index. Its four-byte index offset and its 32-byte value offset both wrap to zero
    /// in unchecked 32-bit arithmetic, so a read that skipped the non-negative guard would land on the
    /// first stored entry instead of failing.
    /// </summary>
    private const int MostNegativeIndex = int.MinValue;

    /// <summary>
    /// An index far past the stored entries whose four-byte index offset, 2^30 times 4, is 2^32 and wraps
    /// to zero in unchecked 32-bit arithmetic, so a position read that skipped the upper-bound guard would
    /// return the first stored position instead of failing.
    /// </summary>
    private const int IndexOffsetWrappingIndex = 1 << 30;

    /// <summary>
    /// An index far past the stored entries whose 32-byte value offset, 2^27 times 32, is 2^32 and wraps
    /// to zero in unchecked 32-bit arithmetic, so a value read that skipped the upper-bound guard would
    /// return the first stored value instead of failing.
    /// </summary>
    private const int ValueOffsetWrappingIndex = 1 << 27;

    /// <summary>The row, column and non-zero counts a caller's tag claims, none of which match the matrix built under it.</summary>
    private const int CallerClaimedDimension = 4;

    /// <summary>The operation count one matrix construction records.</summary>
    private const long SingleConstructionCount = 1;

    /// <summary>The name of the provider library a caller's tag carries.</summary>
    private const string CallerLibraryName = "caller.library";

    /// <summary>The version of the provider library a caller's tag carries.</summary>
    private const string CallerLibraryVersion = "1.0.0";

    /// <summary>The parameter name the null guard on the pool reports.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The parameter name the positivity guard on the row count reports.</summary>
    private const string RowCountParameterName = "rowCount";

    /// <summary>The parameter name the positivity guard on the column count reports.</summary>
    private const string ColumnCountParameterName = "columnCount";

    /// <summary>The parameter name the empty-set, row-range and ordering guards report.</summary>
    private const string RowIndicesParameterName = "rowIndices";

    /// <summary>The parameter name the column-length and column-range guards report.</summary>
    private const string ColumnIndicesParameterName = "columnIndices";

    /// <summary>The parameter name the value-length guard reports.</summary>
    private const string ValuesParameterName = "values";

    /// <summary>The parameter name the positivity guard of the buffer-size computation reports.</summary>
    private const string NonzeroCountParameterName = "nonzeroCount";

    /// <summary>The parameter name the scalar-size lookup reports for a curve it holds no size for.</summary>
    private const string CurveParameterName = "curve";

    /// <summary>The parameter name both index guards of the position and value accessors report.</summary>
    private const string IndexParameterName = "index";

    /// <summary>The statement the empty-set guard makes about a matrix without triples.</summary>
    private const string EmptyTripleSetMessage = "R1csMatrix requires at least one non-zero entry";

    /// <summary>The statement the ordering guard makes about the order triples must follow.</summary>
    private const string OrderingMessage = "Triples must be strictly ascending by (row, column)";

    /// <summary>The statement the scalar-size lookup makes about the curves it holds a size for.</summary>
    private const string UnwiredCurveMessage = "R1csMatrix supports Bls12Curve381 or Bn254";


    /// <summary>The BLS12-381 scalar addition delegate.</summary>
    private static ScalarAddDelegate ScalarAdd { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();

    /// <summary>The BLS12-381 scalar multiplication delegate.</summary>
    private static ScalarMultiplyDelegate ScalarMul { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();


    /// <summary>The pooled rentals and matrices opened during a test, released together in cleanup.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Disposes every rental and matrix the test opened, most recent first.</summary>
    [TestCleanup]
    public void DisposeRentals()
    {
        for(int i = Disposables.Count - 1; i >= 0; i--)
        {
            Disposables[i].Dispose();
        }

        Disposables.Clear();
    }


    /// <summary>Verifies that a matrix built from sorted triples reports the given dimensions and reproduces every row/column position in order.</summary>
    [TestMethod]
    public void ConstructionFromSortedTriplesIsRoundTrip()
    {
        ReadOnlySpan<int> rows = stackalloc int[] { 0, 0, 1, 2 };
        ReadOnlySpan<int> cols = stackalloc int[] { 1, 2, 0, 2 };

        using IMemoryOwner<byte> valuesOwner = BaseMemoryPool.Shared.Rent(4 * Scalar.SizeBytes);
        Span<byte> values = valuesOwner.Memory.Span[..(4 * Scalar.SizeBytes)];
        values.Clear();
        WriteCanonical(new BigInteger(3), values.Slice(0 * Scalar.SizeBytes, Scalar.SizeBytes));
        WriteCanonical(new BigInteger(5), values.Slice(1 * Scalar.SizeBytes, Scalar.SizeBytes));
        WriteCanonical(new BigInteger(7), values.Slice(2 * Scalar.SizeBytes, Scalar.SizeBytes));
        WriteCanonical(new BigInteger(11), values.Slice(3 * Scalar.SizeBytes, Scalar.SizeBytes));

        using R1csMatrix matrix = R1csMatrix.FromSortedTriples(rows, cols, values, 3, 3, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.AreEqual(3, matrix.RowCount);
        Assert.AreEqual(3, matrix.ColumnCount);
        Assert.AreEqual(4, matrix.NonzeroCount);

        //Round-trip the row/column reading.
        for(int i = 0; i < 4; i++)
        {
            (int row, int column) = matrix.GetTriplePosition(i);
            Assert.AreEqual(rows[i], row);
            Assert.AreEqual(cols[i], column);
        }
    }


    /// <summary>Verifies that triples whose row indices are not ascending are rejected.</summary>
    [TestMethod]
    public void OutOfOrderRowsAreRejected()
    {
        //Heap-allocated arrays so they can be captured by the lambda.
        int[] rows = [0, 2, 1];
        int[] cols = [0, 0, 0];
        byte[] values = AllocateZeroValuesArray(3);

        Assert.ThrowsExactly<ArgumentException>(() =>
            _ = R1csMatrix.FromSortedTriples(rows, cols, values, 3, 1, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared));
    }


    /// <summary>Verifies that triples whose column indices are not ascending within the same row are rejected.</summary>
    [TestMethod]
    public void OutOfOrderColumnsWithinSameRowAreRejected()
    {
        int[] rows = [0, 0];
        int[] cols = [2, 1];
        byte[] values = AllocateZeroValuesArray(2);

        Assert.ThrowsExactly<ArgumentException>(() =>
            _ = R1csMatrix.FromSortedTriples(rows, cols, values, 1, 3, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared));
    }


    /// <summary>Verifies that a triple whose row index is at or past the declared row count is rejected.</summary>
    [TestMethod]
    public void OutOfRangeIndicesAreRejected()
    {
        int[] rows = [0, 5];
        int[] cols = [0, 0];
        byte[] values = AllocateZeroValuesArray(2);

        //Row 5 with rowCount=3 should reject.
        Assert.ThrowsExactly<ArgumentException>(() =>
            _ = R1csMatrix.FromSortedTriples(rows, cols, values, 3, 1, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared));
    }


    /// <summary>Verifies that a non-zero count whose COO buffer size would exceed a single addressable array is rejected with a descriptive <see cref="ArgumentException"/>, computed in <c>Int64</c> so the product itself cannot overflow.</summary>
    [TestMethod]
    public void ComputeBufferSizeRejectsNonzeroCountExceedingAddressableBuffer()
    {
        //ComputeBufferSize multiplies the non-zero count by (2 * 4-byte index + 32-byte scalar) = 40.
        //An interop reader can accumulate enough triples to overflow that Int32 product before the
        //builders' own Array.MaxLength intake caps trip, so the product is taken in Int64 and a
        //buffer larger than a single addressable array is rejected here with a documented
        //ArgumentException — not a negative pool.Rent (ArgumentOutOfRangeException) at Build. The
        //guard is a pure computation, so it is checked directly without renting the ~2 GB buffer.
        const int nonzeroCountOverflowingBuffer = 60_000_000;   //40 * 60,000,000 = 2.4e9 > Array.MaxLength.

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = R1csMatrix.ComputeBufferSize(nonzeroCountOverflowingBuffer, CurveParameterSet.Bls12Curve381));

        Assert.Contains("exceeds the maximum addressable size", exception.Message, "the Int64 buffer-size guard must reject the count");
    }


    /// <summary>Verifies that a representable non-zero count returns the exact COO buffer size: two Int32 index arrays plus the scalar array.</summary>
    [TestMethod]
    public void ComputeBufferSizeReturnsExactByteCountForARepresentableCount()
    {
        //A representable count returns the exact COO byte size: two Int32 index arrays plus the
        //scalar array. Locks the boundary so the Int64 widening cannot drift the normal-path result.
        const int indexByteSize = 4;
        const int nonzeroCount = 4;
        int expected = ((2 * indexByteSize) + Scalar.SizeBytes) * nonzeroCount;

        int bufferSize = R1csMatrix.ComputeBufferSize(nonzeroCount, CurveParameterSet.Bls12Curve381);

        Assert.AreEqual(expected, bufferSize, "COO buffer size = (2*IndexByteSize + scalarSize) * nnz");
    }


    /// <summary>
    /// Test helper. <see cref="System.Span{T}"/> is a ref struct and
    /// cannot be carried across the lambda boundary that
    /// <c>Assert.ThrowsExactly</c> requires; the rejection tests use
    /// heap-allocated arrays instead. The bytes are immediately handed
    /// to <c>R1csMatrix.FromSortedTriples</c> which copies them into a
    /// pool-rented buffer; the array itself is short-lived.
    /// </summary>
    private static byte[] AllocateZeroValuesArray(int triples)
    {
        var array = GC.AllocateUninitializedArray<byte>(triples * Scalar.SizeBytes);
        Array.Clear(array);
        return array;
    }


    /// <summary>Verifies that the sparse matrix-vector product matches direct computation for a small matrix and vector.</summary>
    [TestMethod]
    public void MatrixVectorProductMatchesDirectComputation()
    {
        //Matrix:
        //  [ 3  5 ]
        //  [ 0  7 ]
        // z = [ 2, 4 ]
        // Az = [ 3*2 + 5*4, 7*4 ] = [ 26, 28 ]
        ReadOnlySpan<int> rows = stackalloc int[] { 0, 0, 1 };
        ReadOnlySpan<int> cols = stackalloc int[] { 0, 1, 1 };

        int scalarSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> valuesOwner = BaseMemoryPool.Shared.Rent(3 * scalarSize);
        Span<byte> values = valuesOwner.Memory.Span[..(3 * scalarSize)];
        values.Clear();
        WriteCanonical(new BigInteger(3), values.Slice(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), values.Slice(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(7), values.Slice(2 * scalarSize, scalarSize));

        using R1csMatrix matrix = R1csMatrix.FromSortedTriples(rows, cols, values, 2, 2, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> zOwner = BaseMemoryPool.Shared.Rent(2 * scalarSize);
        Span<byte> z = zOwner.Memory.Span[..(2 * scalarSize)];
        WriteCanonical(new BigInteger(2), z.Slice(0, scalarSize));
        WriteCanonical(new BigInteger(4), z.Slice(scalarSize, scalarSize));

        using IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(2 * scalarSize);
        Span<byte> result = resultOwner.Memory.Span[..(2 * scalarSize)];

        matrix.MatrixVectorProduct(z, result, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);

        BigInteger row0 = new(result[..scalarSize], isUnsigned: true, isBigEndian: true);
        BigInteger row1 = new(result.Slice(scalarSize, scalarSize), isUnsigned: true, isBigEndian: true);

        Assert.AreEqual(new BigInteger(26), row0);
        Assert.AreEqual(new BigInteger(28), row1);
    }


    /// <summary>Verifies that multiplying by the zero vector produces an all-zero result regardless of the matrix's own entries.</summary>
    [TestMethod]
    public void MatrixVectorProductWithZeroVectorIsZero()
    {
        ReadOnlySpan<int> rows = stackalloc int[] { 0, 1 };
        ReadOnlySpan<int> cols = stackalloc int[] { 0, 0 };

        int scalarSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> valuesOwner = BaseMemoryPool.Shared.Rent(2 * scalarSize);
        Span<byte> values = valuesOwner.Memory.Span[..(2 * scalarSize)];
        values.Clear();
        WriteCanonical(new BigInteger(3), values[..scalarSize]);
        WriteCanonical(new BigInteger(5), values.Slice(scalarSize, scalarSize));

        using R1csMatrix matrix = R1csMatrix.FromSortedTriples(rows, cols, values, 2, 1, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> zOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> z = zOwner.Memory.Span[..scalarSize];
        z.Clear();

        using IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(2 * scalarSize);
        Span<byte> result = resultOwner.Memory.Span[..(2 * scalarSize)];

        matrix.MatrixVectorProduct(z, result, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);

        for(int i = 0; i < 2 * scalarSize; i++)
        {
            Assert.AreEqual(0, result[i]);
        }
    }


    /// <summary>
    /// FromSortedTriples refuses a missing pool, naming <c>pool</c>. The single triple is in range and its
    /// zero value is canonical, so every other guard accepts the input, and without the null guard the pool
    /// would first be reached where the matrix buffer is rented, as a null dereference rather than a caller
    /// fault.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsANullPool()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        int[] rows = [FirstIndex];
        int[] columns = [FirstIndex];

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, SingleDimension, SingleDimension, CurveParameterSet.Bls12Curve381, null!).Dispose());

        Assert.AreEqual(PoolParameterName, thrown.ParamName);
    }


    /// <summary>
    /// FromSortedTriples refuses a row count of zero with an <see cref="ArgumentOutOfRangeException"/> naming
    /// <c>rowCount</c> and carrying the refused value. The row-range check would refuse the triple against
    /// zero rows as well, but it answers with a plain <see cref="ArgumentException"/> naming
    /// <c>rowIndices</c>, so the exact type and name show the positivity guard answered first.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsAZeroRowCount()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        int[] rows = [FirstIndex];
        int[] columns = [FirstIndex];

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, ZeroDimension, SingleDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(RowCountParameterName, thrown.ParamName);
        Assert.AreEqual(ZeroDimension, thrown.ActualValue);
    }


    /// <summary>
    /// FromSortedTriples refuses a row count of minus one, naming <c>rowCount</c> and carrying the refused
    /// value. The row-range check compares as unsigned values, where minus one is the largest count, so it
    /// accepts the triple; without the positivity guard the call would return a matrix that reports minus one
    /// rows.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsANegativeRowCount()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        int[] rows = [FirstIndex];
        int[] columns = [FirstIndex];

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, NegativeDimension, SingleDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(RowCountParameterName, thrown.ParamName);
        Assert.AreEqual(NegativeDimension, thrown.ActualValue);
    }


    /// <summary>
    /// FromSortedTriples refuses a column count of zero with an <see cref="ArgumentOutOfRangeException"/>
    /// naming <c>columnCount</c> and carrying the refused value. The row count is positive, and the
    /// column-range check would refuse the triple against zero columns as well, but it answers with a plain
    /// <see cref="ArgumentException"/> naming <c>columnIndices</c>, so the exact type and name show the
    /// positivity guard answered first.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsAZeroColumnCount()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        int[] rows = [FirstIndex];
        int[] columns = [FirstIndex];

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, SingleDimension, ZeroDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(ColumnCountParameterName, thrown.ParamName);
        Assert.AreEqual(ZeroDimension, thrown.ActualValue);
    }


    /// <summary>
    /// FromSortedTriples refuses a column count of minus one, naming <c>columnCount</c> and carrying the
    /// refused value. The row count is positive, and the column-range check compares as unsigned values,
    /// where minus one is the largest count, so it accepts the triple; without the positivity guard the call
    /// would return a matrix that reports minus one columns.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsANegativeColumnCount()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        int[] rows = [FirstIndex];
        int[] columns = [FirstIndex];

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, SingleDimension, NegativeDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(ColumnCountParameterName, thrown.ParamName);
        Assert.AreEqual(NegativeDimension, thrown.ActualValue);
    }


    /// <summary>
    /// FromSortedTriples refuses an empty triple set with a plain <see cref="ArgumentException"/> naming
    /// <c>rowIndices</c> and stating that a matrix needs at least one entry. The empty spans agree in length,
    /// so the length guards accept them, and the refusal comes before the buffer is sized: without it the
    /// buffer-size computation would refuse the zero count instead, with an
    /// <see cref="ArgumentOutOfRangeException"/> naming <c>nonzeroCount</c>.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsAnEmptyTripleSet()
    {
        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => R1csMatrix.FromSortedTriples(ReadOnlySpan<int>.Empty, ReadOnlySpan<int>.Empty, ReadOnlySpan<byte>.Empty, SingleDimension, SingleDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(RowIndicesParameterName, thrown.ParamName);
        Assert.Contains(EmptyTripleSetMessage, thrown.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// FromSortedTriples refuses column indices shorter than the row indices, naming <c>columnIndices</c> and
    /// stating both lengths. The value span is sized for the two row indices, so the value-length guard would
    /// accept it, and without the refusal the range check would read a column index past the end of the
    /// shorter span.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsColumnIndicesShorterThanTheRowIndices()
    {
        Memory<byte> values = RentCleared(TwoEntryValueBytes);
        int[] rows = [FirstIndex, SecondIndex];
        int[] columns = [FirstIndex];

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, TwoDimension, SingleDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(ColumnIndicesParameterName, thrown.ParamName);
        Assert.Contains(
            $"columnIndices has length {columns.Length}; must match rowIndices length {rows.Length}.",
            thrown.Message,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// FromSortedTriples refuses a value span one scalar short of the two triples, naming <c>values</c> and
    /// stating the byte length it received and the byte length it expected. The index spans agree in length
    /// and the triples are sorted and in range, so no other guard answers, and without the refusal the
    /// canonical-value check would slice the second value past the end of the span.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsValuesShorterThanTheTriples()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        int[] rows = [FirstIndex, SecondIndex];
        int[] columns = [FirstIndex, FirstIndex];

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, TwoDimension, SingleDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(ValuesParameterName, thrown.ParamName);
        Assert.Contains(
            $"values has length {SingleEntryValueBytes}; expected {TwoEntryValueBytes}",
            thrown.Message,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// FromSortedTriples refuses a triple whose row equals the row count, naming <c>rowIndices</c> and stating
    /// the refused row and the range it must fall in. That row is the first index outside the range, the
    /// column is in range, and a single triple has no predecessor to be ordered against, so only the row-range
    /// guard answers.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsARowEqualToTheRowCount()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        int[] rows = [BoundaryRowCount];
        int[] columns = [FirstIndex];

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, BoundaryRowCount, BoundaryColumnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(RowIndicesParameterName, thrown.ParamName);
        Assert.Contains(
            $"has row {BoundaryRowCount}; must be in [0, {BoundaryRowCount})",
            thrown.Message,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// FromSortedTriples refuses a triple whose column equals the column count, naming <c>columnIndices</c> and
    /// stating the refused column and the range it must fall in. That column is the first index outside the
    /// range, the row is in range, and a single triple has no predecessor to be ordered against, so only the
    /// column-range guard answers.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsAColumnEqualToTheColumnCount()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        int[] rows = [FirstIndex];
        int[] columns = [BoundaryColumnCount];

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, BoundaryRowCount, BoundaryColumnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(ColumnIndicesParameterName, thrown.ParamName);
        Assert.Contains(
            $"has column {BoundaryColumnCount}; must be in [0, {BoundaryColumnCount})",
            thrown.Message,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// FromSortedTriples refuses two triples at the same position, naming <c>rowIndices</c> and stating that
    /// triples must be strictly ascending. Both triples are in range and their order is non-decreasing, so only
    /// the strictness of the ordering guard refuses them; accepting them would store one coefficient position
    /// twice.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesRejectsARepeatedPosition()
    {
        Memory<byte> values = RentCleared(TwoEntryValueBytes);
        int[] rows = [FirstIndex, FirstIndex];
        int[] columns = [RepeatedColumn, RepeatedColumn];

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => R1csMatrix.FromSortedTriples(rows, columns, values.Span, SingleDimension, RepeatedPositionColumnCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(RowIndicesParameterName, thrown.ParamName);
        Assert.Contains(OrderingMessage, thrown.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// FromSortedTriples merges a caller's tag with the matrix identity. The caller's provider-library entry
    /// survives, while the role, curve and dimensions the caller's tag claims are replaced by the matrix's own,
    /// so a caller's tag cannot relabel the matrix. A matrix built without a caller's tag carries no provider
    /// library, so the surviving entry shows the caller's tag was merged rather than discarded.
    /// </summary>
    [TestMethod]
    public void FromSortedTriplesMergesTheCallerTagUnderTheMatrixIdentity()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        ReadOnlySpan<int> rows = [FirstIndex];
        ReadOnlySpan<int> columns = [FirstIndex];
        ProviderLibrary callerLibrary = new(CallerLibraryName, CallerLibraryVersion);
        Tag callerTag = Tag.Create(AlgebraicRole.Scalar)
            .With(CurveParameterSet.Bn254)
            .With(new R1csMatrixDimensions(CallerClaimedDimension, CallerClaimedDimension, CallerClaimedDimension))
            .With(callerLibrary);
        R1csMatrixDimensions matrixDimensions = new(SingleDimension, SingleDimension, SingleEntryCount);

        using R1csMatrix matrix = R1csMatrix.FromSortedTriples(rows, columns, values.Span, SingleDimension, SingleDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, callerTag);

        Assert.IsTrue(matrix.Tag.TryGet(out ProviderLibrary carriedLibrary), "The caller's provider library survives the merge.");
        Assert.AreEqual(callerLibrary, carriedLibrary);
        Assert.AreEqual(AlgebraicRole.R1csMatrix, matrix.Tag.Get<AlgebraicRole>(), "The matrix role replaces the role the caller's tag claims.");
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, matrix.Tag.Get<CurveParameterSet>(), "The matrix curve replaces the curve the caller's tag claims.");
        Assert.AreEqual(matrixDimensions, matrix.Tag.Get<R1csMatrixDimensions>(), "The matrix dimensions replace the dimensions the caller's tag claims.");
    }


    /// <summary>
    /// With counting enabled, one matrix construction records exactly one
    /// <see cref="CryptographicOperationKind.R1csConstructMatrix"/> operation. Counter aggregation is
    /// process-wide, so the test runs outside the parallel batch, turns observing off and clears the counts
    /// before it constructs, and clears the counts and restores both gates afterwards.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public void FromSortedTriplesCountsOneMatrixConstruction()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        ReadOnlySpan<int> rows = [FirstIndex];
        ReadOnlySpan<int> columns = [FirstIndex];
        bool wasCountingEnabled = CryptographicOperationCounters.IsCountingEnabled;
        bool wasObservingEnabled = CryptographicOperationCounters.IsObservingEnabled;
        try
        {
            CryptographicOperationCounters.IsObservingEnabled = false;
            CryptographicOperationCounters.IsCountingEnabled = true;
            CryptographicOperationCounters.Reset();

            using R1csMatrix matrix = R1csMatrix.FromSortedTriples(rows, columns, values.Span, SingleDimension, SingleDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

            Assert.AreEqual(SingleConstructionCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.R1csConstructMatrix),
                "One construction must record one R1csConstructMatrix operation.");
        }
        finally
        {
            CryptographicOperationCounters.Reset();
            CryptographicOperationCounters.IsCountingEnabled = wasCountingEnabled;
            CryptographicOperationCounters.IsObservingEnabled = wasObservingEnabled;
        }
    }


    /// <summary>
    /// GetTriplePosition refuses the most negative index, naming <c>index</c> and carrying the refused value.
    /// The index is below the entry count, so the upper-bound guard stays silent, and its four-byte offset
    /// wraps to zero, so without the non-negative guard the read would return the first stored position
    /// instead of failing.
    /// </summary>
    [TestMethod]
    public void GetTriplePositionRejectsANegativeIndexWhoseOffsetWraps()
    {
        R1csMatrix matrix = BuildRegisteredSingleEntryMatrix();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = matrix.GetTriplePosition(MostNegativeIndex));

        Assert.AreEqual(IndexParameterName, thrown.ParamName);
        Assert.AreEqual(MostNegativeIndex, thrown.ActualValue);
    }


    /// <summary>
    /// GetTriplePosition refuses an index far past the single stored entry, naming <c>index</c> and carrying
    /// the refused value. The index is non-negative, so only the upper-bound guard answers, and its four-byte
    /// offset wraps to zero, so without that guard the read would return the first stored position instead of
    /// failing.
    /// </summary>
    [TestMethod]
    public void GetTriplePositionRejectsAnIndexPastTheEntriesWhoseOffsetWraps()
    {
        R1csMatrix matrix = BuildRegisteredSingleEntryMatrix();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = matrix.GetTriplePosition(IndexOffsetWrappingIndex));

        Assert.AreEqual(IndexParameterName, thrown.ParamName);
        Assert.AreEqual(IndexOffsetWrappingIndex, thrown.ActualValue);
    }


    /// <summary>
    /// GetValueBytes refuses the most negative index, naming <c>index</c> and carrying the refused value. The
    /// index is below the entry count, so the upper-bound guard stays silent, and its 32-byte offset wraps to
    /// zero, so without the non-negative guard the read would return the first stored value instead of
    /// failing.
    /// </summary>
    [TestMethod]
    public void GetValueBytesRejectsANegativeIndexWhoseOffsetWraps()
    {
        R1csMatrix matrix = BuildRegisteredSingleEntryMatrix();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = matrix.GetValueBytes(MostNegativeIndex));

        Assert.AreEqual(IndexParameterName, thrown.ParamName);
        Assert.AreEqual(MostNegativeIndex, thrown.ActualValue);
    }


    /// <summary>
    /// GetValueBytes refuses an index far past the single stored entry, naming <c>index</c> and carrying the
    /// refused value. The index is non-negative, so only the upper-bound guard answers, and its 32-byte offset
    /// wraps to zero, so without that guard the read would return the first stored value instead of failing.
    /// </summary>
    [TestMethod]
    public void GetValueBytesRejectsAnIndexPastTheEntriesWhoseOffsetWraps()
    {
        R1csMatrix matrix = BuildRegisteredSingleEntryMatrix();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = matrix.GetValueBytes(ValueOffsetWrappingIndex));

        Assert.AreEqual(IndexParameterName, thrown.ParamName);
        Assert.AreEqual(ValueOffsetWrappingIndex, thrown.ActualValue);
    }


    /// <summary>
    /// ComputeBufferSize refuses a non-zero count of zero with an <see cref="ArgumentOutOfRangeException"/>
    /// naming <c>nonzeroCount</c> and carrying the refused value. The curve is wired, so the scalar-size lookup
    /// accepts it, and without the refusal a buffer size of zero bytes would be returned for a matrix that
    /// cannot exist.
    /// </summary>
    [TestMethod]
    public void ComputeBufferSizeRejectsAZeroNonzeroCount()
    {
        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = R1csMatrix.ComputeBufferSize(ZeroNonzeroCount, CurveParameterSet.Bls12Curve381));

        Assert.AreEqual(NonzeroCountParameterName, thrown.ParamName);
        Assert.AreEqual(ZeroNonzeroCount, thrown.ActualValue);
    }


    /// <summary>
    /// ComputeBufferSize refuses a negative non-zero count, naming <c>nonzeroCount</c> and carrying the refused
    /// value. The curve is wired, and a negative product never exceeds the addressable maximum, so without the
    /// refusal a negative byte count would be returned to the caller.
    /// </summary>
    [TestMethod]
    public void ComputeBufferSizeRejectsANegativeNonzeroCount()
    {
        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = R1csMatrix.ComputeBufferSize(NegativeNonzeroCount, CurveParameterSet.Bls12Curve381));

        Assert.AreEqual(NonzeroCountParameterName, thrown.ParamName);
        Assert.AreEqual(NegativeNonzeroCount, thrown.ActualValue);
    }


    /// <summary>
    /// ComputeBufferSize refuses a curve the COO layout holds no scalar size for, naming <c>curve</c> and
    /// listing the curves it supports. Pallas is not one of them, and the count of one is positive, so the
    /// count guard accepts it and only the scalar-size lookup answers; without that refusal a size would be
    /// computed from an unknown scalar width.
    /// </summary>
    [TestMethod]
    public void ComputeBufferSizeRejectsACurveWithoutAScalarSize()
    {
        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => _ = R1csMatrix.ComputeBufferSize(SingleEntryCount, CurveParameterSet.Pallas));

        Assert.AreEqual(CurveParameterName, thrown.ParamName);
        Assert.Contains(UnwiredCurveMessage, thrown.Message, StringComparison.Ordinal);
    }


    /// <summary>Reduces <paramref name="value"/> mod the BLS12-381 scalar-field order and writes it as canonical big-endian bytes.</summary>
    /// <param name="value">The integer to reduce and encode.</param>
    /// <param name="destination">Receives the canonical big-endian bytes.</param>
    /// <exception cref="InvalidOperationException">When the reduced value does not fit <paramref name="destination"/>.</exception>
    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % r) + r) % r;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    /// <summary>
    /// Rents a pooled buffer, clears it so every value it holds is the canonical zero scalar, and registers
    /// the rental for release in <see cref="DisposeRentals"/>.
    /// </summary>
    /// <param name="length">The buffer length in bytes.</param>
    /// <returns>The cleared buffer, exactly <paramref name="length"/> bytes long.</returns>
    private Memory<byte> RentCleared(int length)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Disposables.Add(owner);

        Memory<byte> buffer = owner.Memory[..length];
        buffer.Span.Clear();

        return buffer;
    }


    /// <summary>
    /// Builds a one-by-one matrix whose only stored entry is a zero value at the first row and column,
    /// registering the value rental and the matrix for release in <see cref="DisposeRentals"/>.
    /// </summary>
    /// <returns>A matrix with a <see cref="R1csMatrix.NonzeroCount"/> of one.</returns>
    private R1csMatrix BuildRegisteredSingleEntryMatrix()
    {
        Memory<byte> values = RentCleared(SingleEntryValueBytes);
        ReadOnlySpan<int> rows = [FirstIndex];
        ReadOnlySpan<int> columns = [FirstIndex];
        R1csMatrix matrix = R1csMatrix.FromSortedTriples(rows, columns, values.Span, SingleDimension, SingleDimension, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        Disposables.Add(matrix);

        return matrix;
    }
}