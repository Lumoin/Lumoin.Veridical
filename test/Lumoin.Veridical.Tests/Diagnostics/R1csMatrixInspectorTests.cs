using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Diagnostics;

[TestClass]
internal sealed class R1csMatrixInspectorTests
{
    [TestMethod]
    public void InspectReturnsTripleSummary()
    {
        ReadOnlySpan<int> rows = stackalloc int[] { 0, 1 };
        ReadOnlySpan<int> cols = stackalloc int[] { 0, 1 };
        int scalarSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> valuesOwner = SensitiveMemoryPool<byte>.Shared.Rent(2 * scalarSize);
        Span<byte> values = valuesOwner.Memory.Span[..(2 * scalarSize)];
        WriteCanonical(new BigInteger(3), values[..scalarSize]);
        WriteCanonical(new BigInteger(5), values.Slice(scalarSize, scalarSize));

        using R1csMatrix matrix = R1csMatrix.FromSortedTriples(rows, cols, values, 2, 2, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        R1csMatrixReport report = R1csMatrixInspector.Inspect(matrix);

        Assert.AreEqual(2, report.RowCount);
        Assert.AreEqual(2, report.ColumnCount);
        Assert.AreEqual(2, report.NonzeroCount);
        Assert.AreEqual(2, report.FirstTriplesRendered);
        Assert.Contains("(0, 0,", report.FirstTriplesSummary);
        Assert.Contains("(1, 1,", report.FirstTriplesSummary);
    }


    [TestMethod]
    public void InspectThrowsOnNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => R1csMatrixInspector.Inspect(null!));
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