using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for <see cref="R1csMatrix"/>: construction, ordering validation,
/// matrix-vector product correctness.
/// </summary>
[TestClass]
internal sealed class R1csMatrixTests
{
    private static readonly ScalarAddDelegate ScalarAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static readonly ScalarMultiplyDelegate ScalarMul = Bls12Curve381BigIntegerScalarReference.GetMultiply();


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


    [TestMethod]
    public void OutOfOrderColumnsWithinSameRowAreRejected()
    {
        int[] rows = [0, 0];
        int[] cols = [2, 1];
        byte[] values = AllocateZeroValuesArray(2);

        Assert.ThrowsExactly<ArgumentException>(() =>
            _ = R1csMatrix.FromSortedTriples(rows, cols, values, 1, 3, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared));
    }


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
}